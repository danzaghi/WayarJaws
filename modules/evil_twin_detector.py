import os
from datetime import datetime
from scapy.all import PcapReader, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt


def extract_ap_info(pkt):
    # Only process 802.11 Beacon frames and Probe Response frames
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return None

    dot11 = pkt.getlayer(Dot11)
    # The BSSID is the hardware MAC address of the Access Point radio
    bssid = dot11.addr3.lower() if dot11 and dot11.addr3 else None
    if not bssid:
        return None

    # Check the capability flags in the beacon header to see if Privacy/encryption is required
    cap_info = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}") if pkt.haslayer(Dot11Beacon) else pkt.sprintf("{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
    privacy_bit = "privacy" in cap_info

    ssid = None
    channel = None
    crypto_suites = set()

    # Loop through the Information Elements (tagged parameters) attached to the frame
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        # Tag 0: Service Set Identifier (SSID / Network Name)
        if elt.ID == 0:
            try:
                ssid = elt.info.decode("utf-8", errors="ignore")
            except Exception:
                ssid = str(elt.info)
        # Tag 3: Direct-Sequence (DS) Parameter Set contains the primary operating channel
        elif elt.ID == 3:
            try:
                if isinstance(elt.info, bytes) and len(elt.info) > 0:
                    channel = int(elt.info[0])
                elif isinstance(elt.info, int):
                    channel = elt.info
            except Exception:
                pass
        # Tag 48: Robust Security Network (RSN) indicates modern WPA2 or WPA3
        elif elt.ID == 48:
            crypto_suites.add("WPA2")
        # Tag 221: Vendor-specific element with Microsoft OUI (00:50:f2) indicates legacy WPA (WPA1)
        elif elt.ID == 221 and isinstance(elt.info, bytes) and elt.info.startswith(b"\x00P\xf2\x01"):
            crypto_suites.add("WPA")

        # Move to the next tagged parameter in the frame
        elt = elt.payload.getlayer(Dot11Elt)

    # Classify the primary security profile for this Access Point
    if "WPA2" in crypto_suites:
        primary_security = "WPA2"
    elif "WPA" in crypto_suites:
        primary_security = "WPA"
    elif privacy_bit:
        primary_security = "WEP"
    else:
        primary_security = "Open"

    return {
        "bssid": bssid,
        "ssid": ssid if (ssid and ssid != "\x00") else "<Hidden SSID>",
        "channel": channel if channel else "Unknown",
        "security": primary_security,
        "crypto_suites": list(crypto_suites),
        "timestamp": float(pkt.time),
    }


def detect_evil_twin(pcap_or_packets, known_ap_table=None, return_summary=False):
    # This detector identifies Evil Twin and Rogue Access Points in wireless traffic.
    # It catches security downgrade attacks (e.g. cloning a WPA2 network as Open)
    # while intelligently avoiding false positives on multi-AP mesh / enterprise setups.

    # Accept either an offline PCAP file path or a pre-loaded list of Scapy packets
    total_packets = 0
    total_management_frames = 0
    ap_inventory = {}

    if isinstance(pcap_or_packets, str):
        if not os.path.exists(pcap_or_packets):
            raise FileNotFoundError(f"PCAP file not found: {pcap_or_packets}")
        packet_source = PcapReader(pcap_or_packets)
    else:
        packet_source = pcap_or_packets

    # Parse packets one by one to catalog every Access Point in range
    for pkt in packet_source:
        total_packets += 1
        info = extract_ap_info(pkt)
        if not info:
            continue

        total_management_frames += 1
        bssid = info["bssid"]

        if bssid not in ap_inventory:
            ap_inventory[bssid] = {
                "bssid": bssid,
                "ssid": info["ssid"],
                "security": info["security"],
                "channels": set([info["channel"]]) if info["channel"] != "Unknown" else set(),
                "first_seen": info["timestamp"],
                "last_seen": info["timestamp"],
                "frame_count": 0,
            }

        ap = ap_inventory[bssid]
        ap["frame_count"] += 1
        ap["last_seen"] = info["timestamp"]
        if info["ssid"] != "<Hidden SSID>" and ap["ssid"] == "<Hidden SSID>":
            ap["ssid"] = info["ssid"]
        if info["channel"] != "Unknown":
            ap["channels"].add(info["channel"])

    # Safely close reader if we opened a PCAP file stream
    if hasattr(packet_source, "close"):
        packet_source.close()

    # Group discovered Access Points by their advertised SSID
    ssid_clusters = {}
    for bssid, data in ap_inventory.items():
        net_name = data["ssid"]
        if net_name not in ssid_clusters:
            ssid_clusters[net_name] = []
        ssid_clusters[net_name].append(data)

    alerts = []

    # Check each SSID cluster for rogue or duplicate behavior
    for ssid, bssid_list in ssid_clusters.items():
        # Skip unrevealed / hidden networks because they don't have a readable public name to clone
        if ssid == "<Hidden SSID>":
            continue

        # Check 1: Security Downgrade / Mismatch (The definitive Evil Twin attack signature)
        # An attacker clones an encrypted network (e.g. Campus Wi-Fi) as an Open unencrypted
        # hotspot to capture user traffic and credentials.
        encrypted_aps = [ap for ap in bssid_list if ap["security"] in ("WPA2", "WPA", "WEP")]
        open_aps = [ap for ap in bssid_list if ap["security"] == "Open"]

        if encrypted_aps and open_aps:
            # We found both encrypted and open APs advertising the EXACT same network name!
            for rogue_ap in open_aps:
                legit_ap = encrypted_aps[0]
                formatted_time = datetime.fromtimestamp(rogue_ap["first_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                rogue_channels = list(rogue_ap["channels"]) if rogue_ap["channels"] else ["Unknown"]
                legit_channels = list(legit_ap["channels"]) if legit_ap["channels"] else ["Unknown"]

                alerts.append({
                    "attack_type": "Evil Twin - Security Downgrade",
                    "severity": "CRITICAL",
                    "timestamp": formatted_time,
                    "source_mac": rogue_ap["bssid"],
                    "target_mac": legit_ap["bssid"],
                    "bssid": rogue_ap["bssid"],
                    "packet_count": rogue_ap["frame_count"],
                    "ssid": ssid,
                    "channel": rogue_channels[0] if len(rogue_channels) == 1 else rogue_channels,
                    "rogue_security": rogue_ap["security"],
                    "legitimate_bssid": legit_ap["bssid"],
                    "legitimate_security": legit_ap["security"],
                    "evidence": (
                        f"Rogue AP {rogue_ap['bssid']} is advertising SSID '{ssid}' with NO ENCRYPTION (Open), "
                        f"conflicting with legitimate encrypted AP {legit_ap['bssid']} ({legit_ap['security']} on Ch {legit_channels}). "
                        f"Classic Evil Twin honeypot designed to harvest client credentials."
                    ),
                })
            # Once we flag the security downgrade for this SSID, skip further checks on this cluster
            continue

        # Check 2: Authorized Baseline / Whitelist Verification (Optional)
        # If the network admin supplied a table of known authorized AP MAC addresses:
        if known_ap_table and ssid in known_ap_table:
            expected_ap = known_ap_table[ssid]
            allowed_bssid = expected_ap.get("bssid", "").lower()
            for ap in bssid_list:
                if allowed_bssid and ap["bssid"] != allowed_bssid:
                    formatted_time = datetime.fromtimestamp(ap["first_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                    alerts.append({
                        "attack_type": "Rogue AP - Unauthorized BSSID",
                        "severity": "HIGH",
                        "timestamp": formatted_time,
                        "source_mac": ap["bssid"],
                        "target_mac": "Broadcast",
                        "bssid": ap["bssid"],
                        "packet_count": ap["frame_count"],
                        "ssid": ssid,
                        "channel": list(ap["channels"]) if ap["channels"] else "Unknown",
                        "evidence": (
                            f"Discovered unauthorized AP {ap['bssid']} broadcasting protected SSID '{ssid}'. "
                            f"Expected legitimate BSSID: {allowed_bssid}."
                        ),
                    })
            continue

        # Check 3: Multi-AP Enterprise / Mesh Network Handling
        # If multiple APs advertise the same SSID and all have MATCHING security profiles
        # (e.g. all WPA2 as in university eduroam networks), this is 100% normal roaming!
        # We intentionally DO NOT raise an alarm to prevent false positives.

    # Format summary metrics for reporting
    if return_summary:
        summary = {
            "total_packets": total_packets,
            "total_management_frames": total_management_frames,
            "discovered_aps_count": len(ap_inventory),
            "unique_ssids": list(ssid_clusters.keys()),
            "discovered_aps": [
                {
                    "bssid": data["bssid"],
                    "ssid": data["ssid"],
                    "security": data["security"],
                    "channels": list(data["channels"]),
                    "frame_count": data["frame_count"],
                }
                for data in ap_inventory.values()
            ],
            "alerts_triggered": len(alerts),
        }
        return alerts, summary

    return alerts
