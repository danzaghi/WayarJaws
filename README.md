# WayarJaws 🦈
### Wireless & Network Intrusion Detection System (WIDS / NIDS)

**WayarJaws** is a lightweight, Python-powered Wireless and Network Intrusion Detection System featuring a modern, dark-themed Security Operations Center (SOC) dashboard. It provides both offline PCAP forensic analysis and live network monitoring to identify malicious wireless activity and reconnaissance attempts in real time.

---

## 🛡️ Detection Modules

WayarJaws analyzes packet captures and network traffic across several specialized detection engines:

1. **Deauthentication Flood Detection (`modules/deauth_detector.py`)**
   - Monitors IEEE 802.11 management frames for bursts of Deauthentication (Reason Code 7, etc.) and Disassociation frames.
   - Detects Denial-of-Service (DoS) attacks and WPA/WPA2 handshake capture attempts.

2. **Evil Twin / Rogue AP Detection (`modules/evil_twin_detector.py`)**
   - Detects rogue access points masquerading under legitimate SSIDs.
   - Tracks BSSID mismatches, sudden signal strength discrepancies, encryption downgrades, and beacon frame anomalies.

3. **ARP Spoofing / Poisoning Detection (`modules/arp_detector.py`)**
   - Identifies Man-in-the-Middle (MitM) attempts by analyzing ARP replies.
   - Flags gratuitous ARP floods and unauthorized IP-to-MAC mapping changes.

4. **Port Scan & Reconnaissance Detection (`modules/port_scan_detector.py`)**
   - Identifies network reconnaissance and scanning activity.
   - Detects TCP SYN stealth scans, FIN, NULL, XMAS scans, and horizontal/vertical port sweeps.

---

## ✨ Features

- **SOC Dashboard Interface**: Built with an Obsidian & Slate dark SIEM palette using Tkinter/ttk.
- **KPI Summary Cards**: Live counters for total alerts, high-severity threats, unique attackers, and victim devices.
- **Visual Analytics**: Interactive timeline activity chart and attack distribution donut chart rendered directly on canvas.
- **Forensic Alert Grid**: Filter alerts by attack category or severity, and search through logs in real time.
- **Incident Reporting**: Export forensic findings to structured `.csv` or formatted text summary reports.
- **Dataset Integration**: Includes sample PCAP captures in `datasets/` for testing and demonstration.

---

## 📁 Project Structure

```text
WayarJaws/
├── datasets/                 # Sample PCAP captures for demonstration & testing
│   ├── deauth.pcap
│   └── rap.pcap
├── modules/                  # Intrusion detection engines
│   ├── __init__.py
│   ├── arp_detector.py
│   ├── deauth_detector.py
│   ├── engine.py
│   ├── evil_twin_detector.py
│   └── port_scan_detector.py
├── .gitignore                # Git ignore configuration
├── main.py                   # Main GUI dashboard application
├── README.md                 # Project documentation
└── requirements.txt          # Python dependencies
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **Npcap** (Windows) or **libpcap** (Linux / macOS) for raw packet sniffing (Required if performing live network capture).
  - *Windows users:* Download and install [Npcap](https://npcap.com/) (enable *"Install Npcap in WinPcap API-compatible Mode"*).

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/danzaghi/WayarJaws.git
   cd WayarJaws
   ```

2. **(Optional) Create and activate a virtual environment:**
   ```bash
   # Windows PowerShell
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🖥️ Running the Application

Launch the SOC Dashboard:
```bash
python main.py
```

### Analyzing Captured Traffic:
1. Click **"Load PCAP File"** in the top control bar.
2. Select a packet capture file (e.g., from the `datasets/` folder: `datasets/deauth.pcap` or `datasets/rap.pcap`).
3. Click **"Run Analysis"** to process packets through the detection engine.
4. Review generated alerts, inspect detailed forensic evidence, and export the incident report as needed.

---

## 📜 License

This project was developed for educational and security research purposes.
