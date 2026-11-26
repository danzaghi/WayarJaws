import os
from datetime import datetime
from scapy.all import PcapReader, Dot11, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, Dot11Elt, ARP, IP, IPv6, TCP, Ether
from modules.deauth_detector import get_reason_description
from modules.evil_twin_detector import extract_ap_info
from modules.port_scan_detector import get_scan_type_name


def run_detection_engine(pcap_path, enabled_modules=None, progress_callback=None):
    # This unified engine reads the PCAP file in a single, memory-safe streaming pass.
    # By analyzing all active attack types in one loop, it delivers maximum performance
    # without lagging or freezing the Tkinter graphical interface.

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"Target PCAP file does not exist: {pcap_path}")

    # Default to enabling all 4 detection modules if none specified
    if enabled_modules is None:
        enabled_modules = {
            "deauth": True,
            "evil_twin": True,
            "arp": True,
            "port_scan": True,
        }

    do_deauth = enabled_modules.get("deauth", True)
    do_evil_twin = enabled_modules.get("evil_twin", True)
    do_arp = enabled_modules.get("arp", True)
    do_port_scan = enabled_modules.get("port_scan", True)

    # In-memory accumulators for the enabled modules
    deauth_frames = []
    ap_inventory = {}
    ip_mac_table = {}
    arp_alerts_dict = {}
    scan_streams = {}

    total_packets = 0
    timeline_points = []

    if progress_callback:
        progress_callback(5, "Opening capture file and initializing detection engines...")

    # Open PCAP file using Scapy's streaming PcapReader
    reader = PcapReader(pcap_path)

    try:
        for pkt in reader:
            total_packets += 1
            pkt_time = float(pkt.time)
            is_suspicious_pkt = False

            # Update progress callback every 5000 packets to keep the UI snappy
            if progress_callback and total_packets % 5000 == 0:
                progress_callback(None, f"Analyzed {total_packets:,} packets...")

            # ------------------------------------------------------------------
            # 1. 802.11 DEAUTHENTICATION FRAME INSPECTION
            # ------------------------------------------------------------------
            if do_deauth and pkt.haslayer(Dot11Deauth):
                is_suspicious_pkt = True
                dot11 = pkt.getlayer(Dot11)
                deauth = pkt.getlayer(Dot11Deauth)
                src = dot11.addr2.lower() if dot11 and dot11.addr2 else "unknown"
                dst = dot11.addr1.lower() if dot11 and dot11.addr1 else "unknown"
                bssid = dot11.addr3.lower() if dot11 and dot11.addr3 else "unknown"
                reason_code = getattr(deauth, "reason", None)

                deauth_frames.append({
                    "timestamp": float(pkt.time),
                    "source_mac": src,
                    "target_mac": dst,
                    "bssid": bssid,
                    "reason_code": reason_code,
                })

            # ------------------------------------------------------------------
            # 2. EVIL TWIN / BEACON MANAGEMENT FRAME INSPECTION
            # ------------------------------------------------------------------
            if do_evil_twin and (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                info = extract_ap_info(pkt)
                if info:
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

            # ------------------------------------------------------------------
            # 3. ARP SPOOFING / CACHE POISONING INSPECTION
            # ------------------------------------------------------------------
            if do_arp and pkt.haslayer(ARP):
                arp = pkt.getlayer(ARP)
                s_ip = arp.psrc
                s_mac = arp.hwsrc.lower() if arp.hwsrc else None
                t = float(pkt.time)

                if s_ip and s_ip != "0.0.0.0" and s_mac and s_mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    bssid_val = "N/A"
                    if pkt.haslayer(Dot11):
                        d11 = pkt.getlayer(Dot11)
                        bssid_val = d11.addr3.lower() if d11.addr3 else "N/A"

                    if s_ip not in ip_mac_table:
                        ip_mac_table[s_ip] = {"mac": s_mac, "first_seen": t, "last_seen": t, "count": 1}
                    else:
                        orig_mac = ip_mac_table[s_ip]["mac"]
                        if orig_mac == s_mac:
                            ip_mac_table[s_ip]["last_seen"] = t
                            ip_mac_table[s_ip]["count"] += 1
                        else:
                            # Conflict! A second MAC is claiming an existing IP mapping
                            is_suspicious_pkt = True
                            conflict_key = (s_ip, s_mac)
                            if conflict_key in arp_alerts_dict:
                                arp_alerts_dict[conflict_key]["packet_count"] += 1
                                arp_alerts_dict[conflict_key]["_last_seen"] = t
                            else:
                                r_time = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
                                arp_alerts_dict[conflict_key] = {
                                    "attack_type": "ARP Spoofing / Poisoning",
                                    "severity": "CRITICAL",
                                    "timestamp": r_time,
                                    "source_mac": s_mac,
                                    "target_mac": orig_mac,
                                    "bssid": bssid_val,
                                    "packet_count": 1,
                                    "ip_address": s_ip,
                                    "original_mac": orig_mac,
                                    "spoofed_mac": s_mac,
                                    "evidence": "",
                                    "_first_seen": t,
                                    "_last_seen": t,
                                }

            # ------------------------------------------------------------------
            # 4. TCP PORT SCANNING RECONNAISSANCE INSPECTION
            # ------------------------------------------------------------------
            if do_port_scan and pkt.haslayer(TCP) and (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                tcp = pkt.getlayer(TCP)
                is_syn = (tcp.flags == "S" or tcp.flags == 0x02)
                is_null = (tcp.flags == "" or tcp.flags == 0)
                is_fin = (tcp.flags == "F" or tcp.flags == 0x01)
                is_xmas = (tcp.flags == "FPU" or tcp.flags == 0x29)

                if is_syn or is_null or is_fin or is_xmas:
                    is_suspicious_pkt = True
                    if pkt.haslayer(IP):
                        sip = pkt[IP].src
                        dip = pkt[IP].dst
                    else:
                        sip = pkt[IPv6].src
                        dip = pkt[IPv6].dst

                    smac = "Unknown"
                    dmac = "Unknown"
                    scan_bssid = "N/A"
                    if pkt.haslayer(Ether):
                        smac = pkt[Ether].src.lower()
                        dmac = pkt[Ether].dst.lower()
                    elif pkt.haslayer(Dot11):
                        d11 = pkt[Dot11]
                        smac = d11.addr2.lower() if d11.addr2 else "Unknown"
                        dmac = d11.addr1.lower() if d11.addr1 else "Unknown"
                        scan_bssid = d11.addr3.lower() if d11.addr3 else "N/A"

                    pair_key = (sip, dip)
                    if pair_key not in scan_streams:
                        scan_streams[pair_key] = []
                    scan_streams[pair_key].append({
                        "timestamp": float(pkt.time),
                        "dport": tcp.dport,
                        "flags": tcp.flags,
                        "src_mac": smac,
                        "dst_mac": dmac,
                        "bssid": scan_bssid,
                    })

            # Record timeline sample for the SOC dashboard activity chart
            timeline_points.append((pkt_time, is_suspicious_pkt))

    finally:
        reader.close()

    if progress_callback:
        progress_callback(85, "Correlating attack patterns and calculating metrics...")

    compiled_alerts = []

    # --------------------------------------------------------------------------
    # EVALUATE DEAUTH ATTACKS (5.0s window, threshold 10)
    # --------------------------------------------------------------------------
    if do_deauth and deauth_frames:
        time_window = 5.0
        threshold = 10
        conversations = {}
        for f in deauth_frames:
            key = (f["source_mac"], f["target_mac"], f["bssid"])
            if key not in conversations:
                conversations[key] = []
            conversations[key].append(f)

        for (src, dst, bssid), frames in conversations.items():
            frames.sort(key=lambda item: item["timestamp"])
            window = []
            active_alert = None

            for frame in frames:
                t = frame["timestamp"]
                if active_alert:
                    if t - active_alert["_last_seen"] <= time_window:
                        active_alert["packet_count"] += 1
                        active_alert["_last_seen"] = t
                        continue
                    else:
                        dur = active_alert["_last_seen"] - active_alert["_start_time"]
                        r_desc = get_reason_description(active_alert["reason_code"])
                        active_alert["evidence"] = (
                            f"Detected {active_alert['packet_count']} deauth frames from {src} to {dst} "
                            f"(BSSID: {bssid}) over {dur:.2f}s (Threshold: >={threshold} frames in {time_window}s). "
                            f"Reason: {active_alert['reason_code']} - {r_desc}."
                        )
                        active_alert.pop("_start_time", None)
                        active_alert.pop("_last_seen", None)
                        compiled_alerts.append(active_alert)
                        active_alert = None
                        window = []

                window.append(frame)
                while window and (t - window[0]["timestamp"] > time_window):
                    window.pop(0)

                if len(window) >= threshold:
                    first_time = window[0]["timestamp"]
                    r_time = datetime.fromtimestamp(first_time).strftime("%Y-%m-%d %H:%M:%S")
                    active_alert = {
                        "attack_type": "Deauthentication Flood",
                        "severity": "CRITICAL" if len(window) >= 50 else "HIGH",
                        "timestamp": r_time,
                        "source_mac": src,
                        "target_mac": dst,
                        "bssid": bssid,
                        "packet_count": len(window),
                        "reason_code": frame["reason_code"],
                        "evidence": "",
                        "_start_time": first_time,
                        "_last_seen": t,
                    }
                    window = []

            if active_alert:
                dur = active_alert["_last_seen"] - active_alert["_start_time"]
                r_desc = get_reason_description(active_alert["reason_code"])
                active_alert["severity"] = "CRITICAL" if active_alert["packet_count"] >= 50 else "HIGH"
                active_alert["evidence"] = (
                    f"Detected {active_alert['packet_count']} deauth frames from {src} to {dst} "
                    f"(BSSID: {bssid}) over {dur:.2f}s (Threshold: >={threshold} frames in {time_window}s). "
                    f"Reason: {active_alert['reason_code']} - {r_desc}."
                )
                active_alert.pop("_start_time", None)
                active_alert.pop("_last_seen", None)
                compiled_alerts.append(active_alert)

    # --------------------------------------------------------------------------
    # EVALUATE EVIL TWIN / ROGUE AP CLUSTERS
    # --------------------------------------------------------------------------
    if do_evil_twin and ap_inventory:
        ssid_clusters = {}
        for bssid, data in ap_inventory.items():
            net_name = data["ssid"]
            if net_name not in ssid_clusters:
                ssid_clusters[net_name] = []
            ssid_clusters[net_name].append(data)

        for ssid, bssid_list in ssid_clusters.items():
            if ssid == "<Hidden SSID>":
                continue

            encrypted = [ap for ap in bssid_list if ap["security"] in ("WPA2", "WPA", "WEP")]
            open_aps = [ap for ap in bssid_list if ap["security"] == "Open"]

            if encrypted and open_aps:
                for rogue in open_aps:
                    legit = encrypted[0]
                    r_time = datetime.fromtimestamp(rogue["first_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                    rogue_ch = list(rogue["channels"]) if rogue["channels"] else ["Unknown"]
                    legit_ch = list(legit["channels"]) if legit["channels"] else ["Unknown"]

                    compiled_alerts.append({
                        "attack_type": "Evil Twin - Security Downgrade",
                        "severity": "CRITICAL",
                        "timestamp": r_time,
                        "source_mac": rogue["bssid"],
                        "target_mac": legit["bssid"],
                        "bssid": rogue["bssid"],
                        "packet_count": rogue["frame_count"],
                        "ssid": ssid,
                        "channel": rogue_ch[0] if len(rogue_ch) == 1 else rogue_ch,
                        "evidence": (
                            f"Rogue AP {rogue['bssid']} is broadcasting SSID '{ssid}' without encryption (Open), "
                            f"conflicting with legitimate encrypted AP {legit['bssid']} ({legit['security']} on Ch {legit_ch}). "
                            f"Classic Evil Twin honeypot designed to harvest credentials."
                        ),
                    })

    # --------------------------------------------------------------------------
    # EVALUATE ARP SPOOFING ALERTS
    # --------------------------------------------------------------------------
    if do_arp and arp_alerts_dict:
        for (ip, s_mac), alert_entry in arp_alerts_dict.items():
            orig_mac = alert_entry["original_mac"]
            count = alert_entry["packet_count"]
            dur = alert_entry["_last_seen"] - alert_entry["_first_seen"]
            alert_entry["evidence"] = (
                f"ARP cache poisoning detected for IP {ip}. Originally registered to {orig_mac}, "
                f"but rogue MAC {s_mac} claimed ownership via {count} spoofed ARP packet(s) over {dur:.2f}s. "
                f"Strong indicator of a Man-in-the-Middle (MITM) attack intercepting network traffic."
            )
            alert_entry.pop("_first_seen", None)
            alert_entry.pop("_last_seen", None)
            compiled_alerts.append(alert_entry)

    # --------------------------------------------------------------------------
    # EVALUATE TCP PORT SCANS (10.0s window, threshold 15 unique ports)
    # --------------------------------------------------------------------------
    if do_port_scan and scan_streams:
        scan_time_window = 10.0
        scan_threshold = 15

        for (sip, dip), probes in scan_streams.items():
            probes.sort(key=lambda p: p["timestamp"])
            window = []
            active_alert = None

            for probe in probes:
                t = probe["timestamp"]
                if active_alert:
                    if t - active_alert["_last_seen"] <= scan_time_window:
                        active_alert["packet_count"] += 1
                        active_alert["_probed_ports"].add(probe["dport"])
                        active_alert["_last_seen"] = t
                        continue
                    else:
                        dur = active_alert["_last_seen"] - active_alert["_first_seen"]
                        ports_list = sorted(list(active_alert["_probed_ports"]))
                        active_alert["ports_probed_count"] = len(ports_list)
                        active_alert["sample_ports"] = ports_list[:10]
                        active_alert["evidence"] = (
                            f"Host {sip} ({active_alert['source_mac']}) scanned {len(ports_list)} unique TCP ports "
                            f"on target {dip} ({active_alert['target_mac']}) within {dur:.2f}s "
                            f"(Threshold: >={scan_threshold} ports in {scan_time_window}s). "
                            f"Sample ports probed: {ports_list[:10]}."
                        )
                        active_alert.pop("_probed_ports", None)
                        active_alert.pop("_first_seen", None)
                        active_alert.pop("_last_seen", None)
                        compiled_alerts.append(active_alert)
                        active_alert = None
                        window = []

                window.append(probe)
                while window and (t - window[0]["timestamp"] > scan_time_window):
                    window.pop(0)

                unique_ports = {p["dport"] for p in window}
                if len(unique_ports) >= scan_threshold:
                    f_time = window[0]["timestamp"]
                    r_time = datetime.fromtimestamp(f_time).strftime("%Y-%m-%d %H:%M:%S")
                    active_alert = {
                        "attack_type": get_scan_type_name(probe["flags"]),
                        "severity": "CRITICAL" if len(unique_ports) >= 50 else "HIGH",
                        "timestamp": r_time,
                        "source_mac": probe["src_mac"],
                        "target_mac": probe["dst_mac"],
                        "bssid": probe["bssid"],
                        "packet_count": len(window),
                        "source_ip": sip,
                        "target_ip": dip,
                        "ports_probed_count": len(unique_ports),
                        "sample_ports": [],
                        "evidence": "",
                        "_probed_ports": set(unique_ports),
                        "_first_seen": f_time,
                        "_last_seen": t,
                    }
                    window = []

            if active_alert:
                dur = active_alert["_last_seen"] - active_alert["_first_seen"]
                ports_list = sorted(list(active_alert["_probed_ports"]))
                active_alert["ports_probed_count"] = len(ports_list)
                active_alert["sample_ports"] = ports_list[:10]
                active_alert["evidence"] = (
                    f"Host {sip} ({active_alert['source_mac']}) scanned {len(ports_list)} unique TCP ports "
                    f"on target {dip} ({active_alert['target_mac']}) within {dur:.2f}s "
                    f"(Threshold: >={scan_threshold} ports in {scan_time_window}s). "
                    f"Sample ports probed: {ports_list[:10]}."
                )
                active_alert.pop("_probed_ports", None)
                active_alert.pop("_first_seen", None)
                active_alert.pop("_last_seen", None)
                compiled_alerts.append(active_alert)

    # Assign clean sequential numeric IDs to alerts (1, 2, 3...)
    for idx, alert in enumerate(compiled_alerts, start=1):
        alert["id"] = idx

    # Calculate executive metrics for the dashboard KPI cards
    crit_count = sum(1 for a in compiled_alerts if a["severity"] == "CRITICAL")
    high_count = sum(1 for a in compiled_alerts if a["severity"] == "HIGH")
    med_count = sum(1 for a in compiled_alerts if a["severity"] == "MEDIUM")

    cat_counts = {}
    for a in compiled_alerts:
        cat_counts[a["attack_type"]] = cat_counts.get(a["attack_type"], 0) + 1

    # Calculate timeline buckets for the native SOC Canvas charts
    num_bins = 24
    if timeline_points:
        t_start = timeline_points[0][0]
        t_end = timeline_points[-1][0]
        total_duration = max(t_end - t_start, 0.001)
        bin_width = total_duration / num_bins

        bins_total = [0] * num_bins
        bins_attack = [0] * num_bins

        for pt_time, is_atk in timeline_points:
            idx = min(int((pt_time - t_start) / bin_width), num_bins - 1)
            bins_total[idx] += 1
            if is_atk:
                bins_attack[idx] += 1

        timeline_data = {
            "duration": total_duration,
            "total_bins": bins_total,
            "attack_bins": bins_attack,
            "start_time": t_start,
            "end_time": t_end,
        }
    else:
        timeline_data = {
            "duration": 0.0,
            "total_bins": [0] * num_bins,
            "attack_bins": [0] * num_bins,
            "start_time": 0.0,
            "end_time": 0.0,
        }

    summary_metrics = {
        "total_packets": total_packets,
        "total_alerts": len(compiled_alerts),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "category_counts": cat_counts,
        "timeline_data": timeline_data,
    }

    if progress_callback:
        progress_callback(100, f"Analysis Complete! Found {len(compiled_alerts)} threat(s) across {total_packets:,} packets.")

    return compiled_alerts, summary_metrics
