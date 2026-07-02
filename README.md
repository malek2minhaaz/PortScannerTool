#clone this repo in your kali linux terminal 
# PortScannerTool
PortScanner is a Python-based intelligent network security tool developed from scratch using socket programming. Unlike traditional port scanners, it combines TCP/UDP port scanning, banner grabbing, operating system fingerprinting, security risk analysis, exploitation awareness, and automated report generation into a single application.
=======
# ⚡ Port Scanner — Intelligent Port Scanner & Service Risk Analyzer
**Internship Project | Network Security | Built from Scratch with Python**

> Not Nmap. Built differently — using raw Python socket programming, multi-threaded scanning, intelligent risk scoring, banner grabbing, OS fingerprinting, and automated report generation.

---

## 🔍 What Makes Port Scanner Different from Nmap?

| Feature | Nmap | Port Scanner |
|---|---|---|
| Technology | C-based binary, packet crafting | Pure Python socket programming |
| Risk Scoring | None (just shows open ports) | CVSS-inspired scores 0–10 |
| CVE References | None | Built-in CVE database per service |
| Remediation Guidance | None | Detailed fix instructions per port |
| OS Detection Method | Packet fingerprinting | TTL + TCP Window + Port Profile |
| Report Formats | XML/grepable | HTML (dashboard) + JSON + TXT |
| Banner Analysis | Basic | Regex-based service identification |

---

## 📁 Project Structure

```
Port Scanner/
├── portscanner.py          # Main CLI entry point
├── setup.sh                 # Setup & syntax check script
├── requirements.txt         # Dependencies (stdlib only!)
├── README.md
├── core/
│   ├── scanner.py           # TCP + UDP port scanner
│   ├── banner_grab.py       # Service banner grabber
│   ├── risk_engine.py       # Risk scoring & CVE database
│   └── os_fingerprint.py    # OS detection (TTL/Window/Port)
├── utils/
│   ├── display.py           # Terminal output & colors
│   └── logger.py            # Scan session logger
├── reports/
│   └── report_gen.py        # HTML / TXT / JSON report generator
├── logs/                    # Auto-created: scan_history.log
└── reports/                 # Auto-created: output reports
```

---

## ⚙️ Setup

```bash
# 1. Clone / extract the project
cd Port Scanner

# 2. Run setup (checks Python, creates dirs, validates syntax)
chmod +x setup.sh
./setup.sh

# 3. Verify
python3 portscanner.py --help
```

**Requirements:** Python 3.8+ only. No pip installs needed. All stdlib.

---

## 🚀 Usage — All Commands

### Basic Scan (top 1024 ports)
```bash
python3 portscanner.py -t 192.168.1.1
```

### Scan Specific Ports
```bash
python3 portscanner.py -t 192.168.1.1 -p 22,80,443,3306,3389
```

### Scan Port Range
```bash
python3 portscanner.py -t 192.168.1.1 -p 1-500
```

### Full Port Scan (all 65535 ports)
```bash
python3 portscanner.py -t 192.168.1.1 -p 1-65535 --threads 200
```

### UDP Scan
```bash
python3 portscanner.py -t 192.168.1.1 --scan-type udp -p 53,67,68,161,162
```

### TCP + UDP Combined
```bash
python3 portscanner.py -t 192.168.1.1 --scan-type both
```

### With Banner Grabbing
```bash
python3 portscanner.py -t 192.168.1.1 --banner
```

### With Risk Analysis
```bash
python3 portscanner.py -t 192.168.1.1 --risk
```

### With OS Detection
```bash
python3 portscanner.py -t 192.168.1.1 --os-detect
```

### Full Scan (all features enabled)
```bash
python3 portscanner.py -t 192.168.1.1 --full-scan
```

### Generate HTML Report
```bash
python3 portscanner.py -t 192.168.1.1 --full-scan --report html
```

### Generate All Reports (HTML + TXT + JSON)
```bash
python3 portscanner.py -t 192.168.1.1 --full-scan --report all
```

### Verbose Mode (show closed ports too)
```bash
python3 portscanner.py -t 192.168.1.1 --verbose
```

### Custom Output Directory
```bash
python3 portscanner.py -t 192.168.1.1 --report html --output-dir /tmp/scans
```

### No Color Output (for piping/logging)
```bash
python3 portscanner.py -t 192.168.1.1 --no-color > scan_output.txt
```

### Custom Timeout & Threads
```bash
python3 portscanner.py -t 192.168.1.1 -p 1-1024 --threads 150 --timeout 2.0
```

### Scan with Hostname
```bash
python3 portscanner.py -t scanme.nmap.org -p 1-100 --banner --risk
```

---

## 🎯 Complete Demo Command (Best for Internship Demo)

```bash
python3 portscanner.py \
  -t 192.168.1.1 \
  -p 1-1024 \
  --full-scan \
  --threads 100 \
  --timeout 1.5 \
  --report all \
  --output-dir reports \
  --verbose
```

---

## 📊 Features Explained

### 1. TCP Port Scanner
- Multi-threaded using `concurrent.futures.ThreadPoolExecutor`
- Full TCP connect scan (3-way handshake via `socket.connect_ex`)
- States: OPEN / CLOSED / FILTERED
- Real-time progress bar

### 2. UDP Port Scanner
- Sends service-specific probe packets (DNS, SNMP probes)
- States: OPEN / CLOSED / OPEN|FILTERED
- Handles ICMP Port Unreachable responses

### 3. Banner Grabber
- Connects to open ports and sends protocol probes
- Service-specific probes: HTTP HEAD, SMTP EHLO, Redis PING, etc.
- Regex-based service identification: SSH, Apache, Nginx, MySQL, Redis, etc.

### 4. OS Fingerprinting
- **TTL Analysis**: System ping → parse TTL → map to OS (Windows=128, Linux=64, Cisco=255)
- **TCP Window**: Socket buffer size fingerprinting
- **Port Profile**: Probes Windows-specific (135, 445, 3389) and Linux-specific (22, 111) ports

### 5. Risk Engine
- CVSS-inspired scoring (0.0–10.0) per port
- Risk levels: CRITICAL / HIGH / MEDIUM / LOW / INFO
- CVE references per service
- Detailed remediation steps
- Overall security posture rating

### 6. Report Generator
- **HTML**: Full cybersecurity dashboard with dark theme
- **TXT**: Plain-text report for terminal/logging
- **JSON**: Structured data for integration/parsing

---

## 🔐 Risk Score Examples

| Port | Service | Score | Level |
|------|---------|-------|-------|
| 23   | Telnet  | 9.8   | CRITICAL |
| 3389 | RDP     | 9.8   | CRITICAL |
| 6379 | Redis   | 9.8   | CRITICAL |
| 445  | SMB     | 9.5   | CRITICAL |
| 3306 | MySQL   | 8.5   | HIGH |
| 21   | FTP     | 8.0   | HIGH |
| 22   | SSH     | 5.0   | MEDIUM |
| 80   | HTTP    | 5.0   | MEDIUM |
| 443  | HTTPS   | 2.0   | LOW |

---

## 🧪 Test on Localhost

```bash
# Safe test against your own machine
python3 portscanner.py -t 127.0.0.1 -p 1-1024 --full-scan --report html
```

---

## 📚 Technical Skills Demonstrated

- **Python Socket Programming**: `socket`, `AF_INET`, `SOCK_STREAM`, `SOCK_DGRAM`
- **Multithreading**: `ThreadPoolExecutor`, `threading.Lock`
- **TCP/UDP Protocols**: Port states, 3-way handshake, ICMP
- **Service Identification**: Banner regex, probe packets
- **OS Detection**: TTL analysis, window sizing
- **Security Concepts**: CVE, CVSS, risk scoring, remediation
- **Report Generation**: HTML, JSON, TXT from scratch

---

## ⚠️ Legal Notice

Port Scanner is for **authorized network security testing only**.  
Always obtain written permission before scanning any network or system you do not own.  
Unauthorized port scanning may violate computer crime laws.

---

*Built for Network Security Internship Project | Port Scanner v1.0*
>>>>>>> 001bc87 (Initial Commit)
