import os
from datetime import datetime
from scapy.all import PcapReader, ARP, Ether, Dot11


def detect_arp_spoofing(pcap_or_packets, return_summary=False):
    # This detector inspects ARP traffic to catch ARP Spoofing / Cache Poisoning attacks.
    # In a healthy network, an IP address maps to exactly one hardware MAC address.
    # If a second MAC suddenly claims an already-mapped IP, that is a classic Man-in-the-Middle (MITM) attack.

    # Accept either an offline PCAP file path or an in-memory list of Scapy packets
    total_packets = 0
    total_arp_packets = 0
    ip_mac_table = {}
    alerts = []
    active_alerts = {}

    if isinstance(pcap_or_packets, str):
        if not os.path.exists(pcap_or_packets):
            raise FileNotFoundError(f"PCAP file not found: {pcap_or_packets}")
        packet_source = PcapReader(pcap_or_packets)
    else:
        packet_source = pcap_or_packets

    for pkt in packet_source:
        total_packets += 1

        # Only inspect packets that carry the Address Resolution Protocol (ARP) layer
        if not pkt.haslayer(ARP):
            continue

        total_arp_packets += 1
        arp = pkt.getlayer(ARP)

        # Grab sender IP and MAC address from the ARP payload
        sender_ip = arp.psrc
        sender_mac = arp.hwsrc.lower() if arp.hwsrc else None
        target_ip = arp.pdst
        target_mac = arp.hwdst.lower() if arp.hwdst else None
        timestamp = float(pkt.time)

        # Ignore invalid, incomplete, or broadcast IP/MAC addresses
        # 0.0.0.0 is used during normal DHCP address acquisition (RFC 5227 probe)
        if not sender_ip or sender_ip == "0.0.0.0" or not sender_mac:
            continue
        if sender_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue

        # Extract BSSID if this was captured on an 802.11 wireless network
        bssid = "N/A"
        if pkt.haslayer(Dot11):
            dot11 = pkt.getlayer(Dot11)
            bssid = dot11.addr3.lower() if dot11.addr3 else "N/A"

        # Case 1: First time we see this IP address -> learn the legitimate mapping
        if sender_ip not in ip_mac_table:
            ip_mac_table[sender_ip] = {
                "mac": sender_mac,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "count": 1,
            }
        else:
            original_mac = ip_mac_table[sender_ip]["mac"]

            # Case 2: Same MAC reaffirms ownership -> normal healthy ARP traffic
            if original_mac == sender_mac:
                ip_mac_table[sender_ip]["last_seen"] = timestamp
                ip_mac_table[sender_ip]["count"] += 1
            else:
                # Case 3: A DIFFERENT MAC address claims the same IP address!
                # This indicates an active ARP poisoning / spoofing attempt.
                conflict_key = (sender_ip, sender_mac)

                if conflict_key in active_alerts:
                    # Consolidate ongoing attack frames into the existing alert burst
                    alert_entry = active_alerts[conflict_key]
                    alert_entry["packet_count"] += 1
                    alert_entry["_last_seen"] = timestamp
                else:
                    readable_time = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

                    alert_entry = {
                        "attack_type": "ARP Spoofing / Poisoning",
                        "severity": "CRITICAL",
                        "timestamp": readable_time,
                        "source_mac": sender_mac,        # The rogue/spoofing MAC
                        "target_mac": original_mac,      # The legitimate victim MAC
                        "bssid": bssid,
                        "packet_count": 1,
                        "ip_address": sender_ip,
                        "original_mac": original_mac,
                        "spoofed_mac": sender_mac,
                        "evidence": "",
                        "_first_seen": timestamp,
                        "_last_seen": timestamp,
                    }
                    active_alerts[conflict_key] = alert_entry

    # Safely close reader if we opened a PCAP file stream
    if hasattr(packet_source, "close"):
        packet_source.close()

    # Finalize alerts with clear, student-friendly plain English explanations
    for (ip, spoof_mac), alert_entry in active_alerts.items():
        orig_mac = alert_entry["original_mac"]
        count = alert_entry["packet_count"]
        duration = alert_entry["_last_seen"] - alert_entry["_first_seen"]

        alert_entry["evidence"] = (
            f"ARP cache poisoning detected for IP {ip}. Originally registered to {orig_mac}, "
            f"but rogue MAC {spoof_mac} claimed ownership via {count} spoofed ARP packet(s) over {duration:.2f}s. "
            f"Strong indicator of a Man-in-the-Middle (MITM) attack intercepting network traffic."
        )

        # Clean up internal calculation fields
        alert_entry.pop("_first_seen", None)
        alert_entry.pop("_last_seen", None)
        alerts.append(alert_entry)

    if return_summary:
        summary = {
            "total_packets": total_packets,
            "total_arp_packets": total_arp_packets,
            "unique_ips_tracked": len(ip_mac_table),
            "alerts_triggered": len(alerts),
            "ip_mac_mappings": {ip: data["mac"] for ip, data in ip_mac_table.items()},
        }
        return alerts, summary

    return alerts
