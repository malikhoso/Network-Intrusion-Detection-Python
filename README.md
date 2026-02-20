# Advanced Network Intrusion Detection System (NIDS) with ML Dashboard

A professional-grade, real-time Network Intrusion Detection System (NIDS) built with Python. This application monitors network traffic for malicious patterns, employs Machine Learning for anomaly detection, and provides a comprehensive Tkinter-based dashboard for security analysis.

## 🛡️ Security Capabilities

This system is designed to detect a wide array of network threats:
* **Protocol Attacks:** SYN Floods, ICMP Floods, UDP Floods, and DNS Flooding.
* **Reconnaissance:** High-accuracy Port Scan detection.
* **Anomalous Traffic:** Identifies "Christmas Tree" packets and Null scans.
* **C2 & Exfiltration:** Detects Command & Control (C2) beaconing and data exfiltration via ICMP/DNS.
* **MITM Attacks:** Real-time ARP Spoofing detection.
* **Web Threats:** Payload inspection for SQL Injection, XSS, and Path Traversal patterns.

## 🚀 Key Features

* **Interactive Dashboard:** Real-time alert timeline and protocol distribution charts (Matplotlib integration).
* **Machine Learning:** Uses **Scikit-Learn (Isolation Forest)** to baseline "normal" traffic and flag unknown anomalies.
* **Data Persistence:** Full SQLite3 backend to log alerts, network flows, and DNS queries for forensic analysis.
* **PCAP Integration:** Automatic capturing of suspicious packets into `.pcap` files for deep-packet inspection in Wireshark.
* **Custom Rule Engine:** Support for JSON-based custom rules to tailor detection to specific environments.
* **Professional Reporting:** Generates detailed text-based security analysis reports.

## 🛠️ Tech Stack

* **Network Sniffing:** [Scapy](https://scapy.net/)
* **Machine Learning:** Scikit-Learn (Isolation Forest)
* **Database:** SQLite3
* **GUI:** Tkinter & Matplotlib
* **Language:** Python 3.x



## 📂 Project Structure

```text
├── nids_dashboard.py      # Main application logic and GUI
├── custom_rules.json      # User-defined detection rules
├── pcaps/                 # Storage for suspicious packet captures
├── reports/               # Auto-generated security reports
└── nids_alerts.db         # SQLite database for forensic logs
