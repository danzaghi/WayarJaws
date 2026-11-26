import os
from datetime import datetime
from scapy.all import PcapReader, rdpcap, Dot11, Dot11Deauth

# Dictionary of standard IEEE 802.11 Deauthentication Reason Codes
# This helps explain why a station was disconnected during viva demonstrations
IEEE_80211_REASON_CODES = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving (or has left) BSS",
    9: "STA requesting (re)association is not authenticated with responding STA",
    10: "Disassociated because the information in the Power Capability element is unacceptable",
    11: "Disassociated because the information in the Supported Channels element is unacceptable",
    12: "Disassociated due to BSS Transition Management",
    13: "Invalid element",
    14: "Message integrity code (MIC) failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "Element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of the security policy",
}


def get_reason_description(code):
    # Look up human-friendly explanation for an 802.11 reason code
    if code is None:
        return "Unknown / Not Specified"
    return IEEE_80211_REASON_CODES.get(code, f"Vendor specific or unassigned ({code})")


def detect_deauth(pcap_path, time_window=5.0, threshold=10, return_summary=False):
    # Make sure the file actually exists before we try to read it
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Read packets using a memory-friendly streaming reader (supports both file paths and lists)
    total_packets = 0
    deauth_frames = []

    if isinstance(pcap_path, str):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        packet_source = PcapReader(pcap_path)
    else:
        packet_source = pcap_path

    # Filter out only 802.11 Deauthentication management frames
    for pkt in packet_source:
        total_packets += 1
        # Check if the packet carries an 802.11 deauth layer
        if pkt.haslayer(Dot11Deauth):
            dot11_layer = pkt.getlayer(Dot11)
            deauth_layer = pkt.getlayer(Dot11Deauth)

            # Grab the sender, receiver, and BSSID MAC addresses from the wireless header
            source_mac = dot11_layer.addr2 if dot11_layer and dot11_layer.addr2 else "Unknown"
            target_mac = dot11_layer.addr1 if dot11_layer and dot11_layer.addr1 else "Unknown"
            bssid = dot11_layer.addr3 if dot11_layer and dot11_layer.addr3 else "Unknown"

            # Reason code indicates why the deauth frame was issued
            reason_code = getattr(deauth_layer, "reason", None)

            deauth_frames.append({
                "timestamp": float(pkt.time),
                "source_mac": source_mac.lower(),
                "target_mac": target_mac.lower(),
                "bssid": bssid.lower(),
                "reason_code": reason_code,
            })

    # Close reader safely if opened from file
    if hasattr(packet_source, "close"):
        packet_source.close()

    # Group deauth frames by communication stream: (source, target, bssid)
    conversations = {}
    for frame in deauth_frames:
        stream_key = (frame["source_mac"], frame["target_mac"], frame["bssid"])
        if stream_key not in conversations:
            conversations[stream_key] = []
        conversations[stream_key].append(frame)

    alerts = []

    # Analyze each stream to detect flood patterns exceeding our threshold within the time window
    for (src, dst, bssid), frames in conversations.items():
        # Sort frames chronologically by packet timestamp
        frames.sort(key=lambda item: item["timestamp"])

        window = []
        active_alert = None

        for frame in frames:
            current_time = frame["timestamp"]

            # If an alert is already active for this ongoing attack burst, check if this packet is part of it
            if active_alert:
                # If this frame arrived within the time window of the previous attack frame, extend the burst
                if current_time - active_alert["_last_seen"] <= time_window:
                    active_alert["packet_count"] += 1
                    active_alert["_last_seen"] = current_time
                    continue
                else:
                    # The attack paused or stopped; seal and save the previous alert
                    burst_duration = active_alert["_last_seen"] - active_alert["_start_time"]
                    reason_desc = get_reason_description(active_alert["reason_code"])
                    active_alert["evidence"] = (
                        f"Detected {active_alert['packet_count']} deauth frames from {src} to {dst} "
                        f"(BSSID: {bssid}) over {burst_duration:.2f}s (Threshold: >={threshold} frames in {time_window}s). "
                        f"Reason: {active_alert['reason_code']} - {reason_desc}."
                    )
                    # Clean up internal tracking fields before finalizing
                    active_alert.pop("_start_time", None)
                    active_alert.pop("_last_seen", None)
                    alerts.append(active_alert)
                    active_alert = None
                    window = []

            # Add current frame to our sliding window
            window.append(frame)

            # Slide the window forward: drop any frames older than (current_time - time_window)
            while window and (current_time - window[0]["timestamp"] > time_window):
                window.pop(0)

            # If the number of deauth frames in the sliding window hits the threshold, trigger an alert!
            if len(window) >= threshold:
                first_frame_time = window[0]["timestamp"]
                readable_time = datetime.fromtimestamp(first_frame_time).strftime("%Y-%m-%d %H:%M:%S")

                # Higher frame counts indicate an aggressive automated DoS flood
                severity = "CRITICAL" if len(window) >= 50 else "HIGH"

                active_alert = {
                    "attack_type": "Deauthentication Flood",
                    "severity": severity,
                    "timestamp": readable_time,
                    "source_mac": src,
                    "target_mac": dst,
                    "bssid": bssid,
                    "packet_count": len(window),
                    "reason_code": frame["reason_code"],
                    "evidence": "",  # Populated once burst finishes or at loop end
                    "_start_time": first_frame_time,
                    "_last_seen": current_time,
                }
                # Empty the window buffer so we don't duplicate count
                window = []

        # Finalize any ongoing active alert at the end of the packet list
        if active_alert:
            burst_duration = active_alert["_last_seen"] - active_alert["_start_time"]
            reason_desc = get_reason_description(active_alert["reason_code"])
            active_alert["severity"] = "CRITICAL" if active_alert["packet_count"] >= 50 else "HIGH"
            active_alert["evidence"] = (
                f"Detected {active_alert['packet_count']} deauth frames from {src} to {dst} "
                f"(BSSID: {bssid}) over {burst_duration:.2f}s (Threshold: >={threshold} frames in {time_window}s). "
                f"Reason: {active_alert['reason_code']} - {reason_desc}."
            )
            # Remove internal tracking variables
            active_alert.pop("_start_time", None)
            active_alert.pop("_last_seen", None)
            alerts.append(active_alert)

    # If caller requested dataset summary metrics, bundle them nicely
    if return_summary:
        summary = {
            "total_packets": total_packets,
            "total_deauth_frames": len(deauth_frames),
            "alerts_triggered": len(alerts),
            "unique_sources": list({f["source_mac"] for f in deauth_frames}),
            "unique_targets": list({f["target_mac"] for f in deauth_frames}),
            "unique_bssids": list({f["bssid"] for f in deauth_frames}),
            "reason_codes": list({f["reason_code"] for f in deauth_frames}),
        }
        return alerts, summary

    return alerts
