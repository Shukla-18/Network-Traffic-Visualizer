# 🕶️ Network Traffic Visualizer  
### 🔐 Real-Time Packet Analysis • Cyberpunk UI • Optimized for Kali Linux  

![banner](https://img.shields.io/badge/Built%20with-Streamlit%20%7C%20Plotly%20%7C%20Scapy-blueviolet?style=for-the-badge)  
![python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge)  
![license](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)  

---

## ⚡ Overview  

**Network Traffic Visualizer** is a modern, hacker-style network analysis tool built with **Streamlit**, **Plotly**, and **Scapy**.  
It allows you to capture, analyze, and visualize live or offline network packets — all from a smooth neon-themed cyber interface inspired by penetration testing dashboards.  

---

## 🧩 Features  

✅ **Live Packet Capture** using Scapy (requires root privileges)  
✅ **Load PCAP / PCAPNG Files** for offline analysis  
✅ **Interactive Visualizations** — Protocol distribution, top talkers, and traffic timeline  
✅ **Kali Linux Optimized UI** — Cyberpunk fonts, glowing effects, and dark grid background  
✅ **CSV & Summary Export** options  
✅ **Built-in BPF Filter Support** (`tcp port 80`, `icmp`, etc.)  
✅ **Root/User Status Detection**  
✅ **Completely Local — No external logging or telemetry**  

---

## 🛠️ Installation  

### 1️⃣ Clone the Repository  
```bash
git clone https://github.com/yourusername/network-traffic-visualizer.git
cd network-traffic-visualizer
```

### 2️⃣ Install Dependencies  
```bash
sudo apt update
sudo apt install python3-scapy python3-pip -y
pip install streamlit pandas plotly requests
```

Or simply use:  
```bash
pip install -r requirements.txt
```

---

## 🚀 Usage  

### Run with root privileges (for live capture):  
```bash
sudo streamlit run app.py --server.headless true
```

Then open your browser at:  
🔗 **http://localhost:8501**

---

## 🧠 Modes of Operation  

### 🔴 Capture (Live)
- Choose your **network interface** (`eth0`, `wlan0`, `lo`, etc.)  
- Specify **packet count** and **timeout**  
- Optionally, apply a **BPF filter** (`tcp port 80`, `icmp`)  
- Click **🚀 START CAPTURE / LOAD**  

### 🟢 Load PCAP File
- Upload any `.pcap`, `.pcapng`, or `.cap` file  
- Instantly view and analyze traffic  

---

## 📊 Visualizations  

| Visualization | Description |
|----------------|-------------|
| **Packets Table** | Displays timestamped packet details |
| **Protocol Distribution** | Interactive pie chart showing packet protocol ratios |
| **Top Talkers** | Bar chart showing top source IPs |
| **Traffic Over Time** | Line chart visualizing packet frequency over time |
| **Metrics Panel** | Quick stats: Total packets, sources, destinations, and data volume |

---

## 🧑‍💻 Interface Preview  

🖥️ **Dark Neon Theme (Cyber-Hacker UI)**  
- Glowing green & cyan elements  
- Grid-based background  
- Transparent panels with neon outlines  
- Smooth visual transitions  

*(You can replace this section with screenshots once you capture the UI.)*  

---

## 🧰 Directory Structure  

```
📦 network-traffic-visualizer/
 ┣ 📜 app.py                # Main Streamlit Application
 ┣ 📜 utils.py              # Scapy helper functions for sniffing and parsing
 ┣ 📜 requirements.txt      # Python dependencies
 ┣ 📜 README.md             # Project documentation
 ┗ 📂 assets/ (optional)    # Store screenshots or icons
```

---

## 🧪 Example Filters  

| Filter | Description |
|---------|-------------|
| `tcp port 80` | Capture only HTTP traffic |
| `icmp` | Capture ICMP (ping) packets |
| `udp port 53` | Capture DNS traffic |
| `port 443` | Capture HTTPS packets |
| `src host 192.168.1.10` | Capture packets from a specific source |

---

## ⚙️ Troubleshooting  

**❌ Error:** `Permission denied`  
> Run Streamlit as root using `sudo`.  

**❌ Error:** `sniff_packets() got an unexpected keyword argument 'filter'`  
> Update your `utils.py` to accept `filter` argument or use Scapy’s built-in `sniff()`.  

**⚠️ No packets captured?**  
> Ensure the selected interface is active and accessible (e.g., `wlan0mon` for Wi-Fi sniffing).  

---

## 🔒 Disclaimer  

This project is intended **for educational and authorized testing purposes only**.  
Do **not** use this tool on networks or systems you do not have explicit permission to analyze.  

---

## 🧑‍🎨 Author  

**Pratham**  
> 🧠 Computer Science Student | 🛡️ Cybersecurity Enthusiast | 🎮 Valorant Lover  

📧 Reach out: [Your email or GitHub profile link]  

---

## 📜 License  

MIT License © 2025 — Free to modify and distribute with attribution.  
