import os
from datetime import datetime
from scapy.all import PcapReader, IP, IPv6, TCP, Ether, Dot11


def get_scan_type_name(flags):
    # Classify the specific port scanning technique used by the attacker
    # Standard Nmap SYN stealth scan (SYN only)
    if flags == "S" or flags == 0x02:
        return "TCP Port Scan (SYN Stealth Scan)"
    # NULL scan: No flags set at all
    elif flags == "" or flags == 0:
        return "TCP Port Scan (NULL Stealth Scan)"
    # FIN scan: Only the FIN flag is set
    elif flags == "F" or flags == 0x01:
        return "TCP Port Scan (FIN Stealth Scan)"
    # Xmas scan: FIN, PSH, and URG flags all lit up like a Christmas tree
    elif flags == "FPU" or flags == 0x29:
        return "TCP Port Scan (Xmas Stealth Scan)"
    return "TCP Port Scan"


def detect_port_scan(pcap_or_packets, time_window=10.0, threshold=15, return_summary=False):
    # This detector identifies horizontal and vertical TCP port scans (e.g. Nmap SYN scans).
    # Normal network clients only talk to 1 or 2 ports (like 80/443 for web browsing).
    # If a host rapidly probes 15+ different ports on a target, that is an automated reconnaissance scan.

    total_packets = 0
    total_tcp_packets = 0
    total_probe_packets = 0

    if isinstance(pcap_or_packets, str):
        if not os.path.exists(pcap_or_packets):
            raise FileNotFoundError(f"PCAP file not found: {pcap_or_packets}")
        packet_source = PcapReader(pcap_or_packets)
    else:
        packet_source = pcap_or_packets

    # Group probe packets by communication pair: (source_ip, target_ip)
    scan_streams = {}

    for pkt in packet_source:
        total_packets += 1

        # Check for TCP layer and underlying IP (IPv4 or IPv6)
        if not (pkt.haslayer(TCP) and (pkt.haslayer(IP) or pkt.haslayer(IPv6))):
            continue

        total_tcp_packets += 1
        tcp = pkt.getlayer(TCP)

        # We look for SYN-only packets (without ACK) or stealth scan signatures (NULL, FIN, Xmas)
        is_syn = (tcp.flags == "S" or tcp.flags == 0x02)
        is_null = (tcp.flags == "" or tcp.flags == 0)
        is_fin = (tcp.flags == "F" or tcp.flags == 0x01)
        is_xmas = (tcp.flags == "FPU" or tcp.flags == 0x29)

        if not (is_syn or is_null or is_fin or is_xmas):
            continue

        total_probe_packets += 1

        # Extract IP addresses
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        else:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        # Extract MAC addresses and BSSID if present
        src_mac = "Unknown"
        dst_mac = "Unknown"
        bssid = "N/A"

        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src.lower()
            dst_mac = pkt[Ether].dst.lower()
        elif pkt.haslayer(Dot11):
            dot11 = pkt[Dot11]
            src_mac = dot11.addr2.lower() if dot11.addr2 else "Unknown"
            dst_mac = dot11.addr1.lower() if dot11.addr1 else "Unknown"
            bssid = dot11.addr3.lower() if dot11.addr3 else "N/A"

        stream_key = (src_ip, dst_ip)
        if stream_key not in scan_streams:
            scan_streams[stream_key] = []

        scan_streams[stream_key].append({
            "timestamp": float(pkt.time),
            "dport": tcp.dport,
            "flags": tcp.flags,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "bssid": bssid,
        })

    # Safely close reader if we opened a PCAP file stream
    if hasattr(packet_source, "close"):
        packet_source.close()

    alerts = []

    # Analyze each (source_ip, target_ip) pair using a sliding time window
    for (src_ip, dst_ip), probes in scan_streams.items():
        probes.sort(key=lambda p: p["timestamp"])

        window = []
        active_alert = None

        for probe in probes:
            current_time = probe["timestamp"]

            # If an alert is already active for this ongoing scan, extend the burst
            if active_alert:
                if current_time - active_alert["_last_seen"] <= time_window:
                    active_alert["packet_count"] += 1
                    active_alert["_probed_ports"].add(probe["dport"])
                    active_alert["_last_seen"] = current_time
                    continue
                else:
                    # Scan has finished cooling down; finalize and record the alert
                    duration = active_alert["_last_seen"] - active_alert["_first_seen"]
                    unique_ports = sorted(list(active_alert["_probed_ports"]))
                    ports_count = len(unique_ports)
                    sample_ports = unique_ports[:10]
                    severity = "CRITICAL" if ports_count >= 50 else "HIGH"

                    active_alert["severity"] = severity
                    active_alert["ports_probed_count"] = ports_count
                    active_alert["sample_ports"] = sample_ports
                    active_alert["evidence"] = (
                        f"Host {src_ip} ({active_alert['source_mac']}) scanned {ports_count} unique TCP ports "
                        f"on target {dst_ip} ({active_alert['target_mac']}) within {duration:.2f}s "
                        f"(Threshold: >={threshold} ports in {time_window}s). "
                        f"Sample ports probed: {sample_ports}. Classic Nmap reconnaissance scan signature."
                    )
                    active_alert.pop("_probed_ports", None)
                    active_alert.pop("_first_seen", None)
                    active_alert.pop("_last_seen", None)
                    alerts.append(active_alert)
                    active_alert = None
                    window = []

            # Add probe to sliding window
            window.append(probe)

            # Prune probes that are older than current_time - time_window
            while window and (current_time - window[0]["timestamp"] > time_window):
                window.pop(0)

            # Check if unique destination ports probed in this window exceeds our threshold
            unique_window_ports = {p["dport"] for p in window}
            if len(unique_window_ports) >= threshold:
                first_time = window[0]["timestamp"]
                readable_time = datetime.fromtimestamp(first_time).strftime("%Y-%m-%d %H:%M:%S")
                scan_type = get_scan_type_name(probe["flags"])

                active_alert = {
                    "attack_type": scan_type,
                    "severity": "HIGH",
                    "timestamp": readable_time,
                    "source_mac": probe["src_mac"],
                    "target_mac": probe["dst_mac"],
                    "bssid": probe["bssid"],
                    "packet_count": len(window),
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "ports_probed_count": len(unique_window_ports),
                    "sample_ports": [],
                    "evidence": "",
                    "_probed_ports": set(unique_window_ports),
                    "_first_seen": first_time,
                    "_last_seen": current_time,
                }
                window = []

        # Finalize any ongoing scan alert at the end of the packet list
        if active_alert:
            duration = active_alert["_last_seen"] - active_alert["_first_seen"]
            unique_ports = sorted(list(active_alert["_probed_ports"]))
            ports_count = len(unique_ports)
            sample_ports = unique_ports[:10]
            severity = "CRITICAL" if ports_count >= 50 else "HIGH"

            active_alert["severity"] = severity
            active_alert["ports_probed_count"] = ports_count
            active_alert["sample_ports"] = sample_ports
            active_alert["evidence"] = (
                f"Host {src_ip} ({active_alert['source_mac']}) scanned {ports_count} unique TCP ports "
                f"on target {dst_ip} ({active_alert['target_mac']}) within {duration:.2f}s "
                f"(Threshold: >={threshold} ports in {time_window}s). "
                f"Sample ports probed: {sample_ports}. Classic Nmap reconnaissance scan signature."
            )
            active_alert.pop("_probed_ports", None)
            active_alert.pop("_first_seen", None)
            active_alert.pop("_last_seen", None)
            alerts.append(active_alert)

    if return_summary:
        summary = {
            "total_packets": total_packets,
            "total_tcp_packets": total_tcp_packets,
            "total_probe_packets": total_probe_packets,
            "unique_ip_pairs": len(scan_streams),
            "alerts_triggered": len(alerts),
        }
        return alerts, summary

    return alerts
