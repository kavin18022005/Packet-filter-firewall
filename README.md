# Data-Driven Packet Filtering Firewall & Heuristic SOC Dashboard

A production-grade, state-of-the-art **Data-Driven Packet Filtering Firewall** with heuristic anomaly detection, Scapy offline PCAP dissection, priority-ordered rule matching, synthetic traffic generation, and an interactive dark navy Security Operations Center (SOC) dashboard.

[![GitHub Repository](https://img.shields.io/badge/GitHub-Packet--filter--firewall-181717?style=for-the-badge&logo=github)](https://github.com/kavin18022005/Packet-filter-firewall)
[![CI Build](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions)](https://github.com/kavin18022005/Packet-filter-firewall/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://github.com/kavin18022005/Packet-filter-firewall/blob/main/LICENSE)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![Scapy](https://img.shields.io/badge/Packet_Inspection-Scapy-FF6F00?style=for-the-badge)](https://scapy.net)
[![React + Vite](https://img.shields.io/badge/Frontend-React_18_%2B_Vite-61DAFB?style=for-the-badge&logo=react)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css)](https://tailwindcss.com)
[![Pytest](https://img.shields.io/badge/Tests-25_Passed-10B981?style=for-the-badge&logo=pytest)](https://pytest.org)

---

## 🛡️ Architecture & Key Features

```
                                  ┌───────────────────────────────┐
                                  │      Incoming Traffic         │
                                  │ (Simulator / PCAP / Ingestion)│
                                  └──────────────┬────────────────┘
                                                 │
                                                 ▼
                                  ┌───────────────────────────────┐
                                  │   Scapy Packet Analyzer       │
                                  │ (L3/L4 Dissection & Flags)    │
                                  └──────────────┬────────────────┘
                                                 │
                                                 ▼
             ┌───────────────────────────────────┴───────────────────────────────────┐
             │                                                                       │
             ▼                                                                       ▼
┌───────────────────────────────┐                                   ┌───────────────────────────────┐
│     Firewall Rule Engine      │                                   │    Sliding-Window Detector    │
│  - CIDR Subnet Matching       │                                   │  - Port Scan Detection (>=5)  │
│  - Port Ranges & Protocols    │                                   │  - SYN Flood Burst Detection  │
│  - Strict Priority Ordering   │                                   │  - Sensitive Port Probes      │
│  - Fallback: DEFAULT-DENY     │                                   │  - Heuristic Anomaly Alerts   │
└────────────┬──────────────────┘                                   └───────────────┬───────────────┘
             │                                                                      │
             ▼                                                                      ▼
┌───────────────────────────────┐                                   ┌───────────────────────────────┐
│       Packet Evaluation       │                                   │      Security Alerts Log      │
│      (ALLOW vs BLOCK)         │                                   │   (1-Click Auto-Block IP)     │
└────────────┬──────────────────┘                                   └───────────────┬───────────────┘
             │                                                                      │
             └───────────────────────────────────┬──────────────────────────────────┘
                                                 │
                                                 ▼
                                  ┌───────────────────────────────┐
                                  │       SQLite ORM Engine       │
                                  │     (FastAPI REST Endpoints)  │
                                  └──────────────┬────────────────┘
                                                 │
                                                 ▼
                                  ┌───────────────────────────────┐
                                  │     CyberWall SOC Frontend    │
                                  │ (Recharts, Logs, Rule Editor) │
                                  └───────────────────────────────┘
```

### 1. Firewall Rule Engine
- **CIDR Subnet Matching**: Native `ipaddress` parsing supporting exact IPs (`192.168.1.1`), subnets (`192.168.1.0/24`, `10.0.0.0/8`), or wildcard (`ANY`).
- **Flexible Port Filtering**: Single ports (`80`), multi-port lists (`80,443,8080`), port ranges (`1024-65535`), or wildcard (`ANY`).
- **L4 Protocol Support**: TCP, UDP, ICMP, and ANY.
- **Priority Precedence**: Lower integer indicates higher precedence (Rule priority 10 runs before priority 100).
- **Rule Management**: Enable/disable toggle switches, priority adjustments, dynamic rule creation, and deletion.
- **Default-Deny Policy**: Any packet not matching an explicit active rule is automatically dropped (`DEFAULT-DENY`). Configurable via settings.

### 2. Heuristic Anomaly & Threat Detection
- **Port Scan Detection**: Sliding-window tracking monitoring distinct destination ports probed by a single source IP. Triggers `CRITICAL` alert when reaching threshold (default: 5 distinct ports in 30s).
- **SYN Flood Burst Detection**: Tracks high-frequency TCP SYN packets without ACK responses within a short time window. Triggers `HIGH` alert (default: 15 SYN packets in 10s).
- **Sensitive Port Reconnaissance**: Probing telnet (23), SMB (445), or RDP (3389) immediately raises an alert.
- **1-Click Auto-Block IP Mitigation**: Instant automated incident response. Clicking **Auto-Block IP** on any alert dynamically injects a priority 10 `BLOCK` rule for that offender.

### 3. Scapy Packet Dissection & Offline PCAP Ingestion
- Dissects Layer 3 IP headers and Layer 4 TCP/UDP/ICMP headers.
- Extracts TCP flags: `SYN`, `ACK`, `SYN-ACK`, `FIN`, `RST`, `PSH-ACK`.
- Supports dragging and dropping Wireshark / tcpdump `.pcap` capture files.
- Includes pre-bundled sample multi-vector attack PCAP for 1-click demonstration.

### 4. Synthetic Traffic Generator
- Configurable background generator with diverse realistic traffic patterns:
  - Valid web HTTPS / DNS traffic
  - Blocked external SSH attempts
  - Malicious port scans and Telnet probes
  - ICMP ping sweeps
- Interactive controls in top navbar: Play/Pause, Inject +5 packets, adjustable frequency slider.

### 5. CyberWall SOC Dashboard Frontend
- **Dark Navy Theme**: Built with Tailwind CSS, glowing neon accents, and responsive layout.
- **KPI Metrics**: Total Packets, Allowed Packets, Blocked Packets, Block Rate %, Threat Alerts, Active Rules.
- **Recharts Data Visualizations**:
  - L4 Protocol distribution donut chart
  - Real-time traffic volume timeline area chart
  - Allowed vs Blocked decision ratio bar chart
- **Granular Packet Logs**: Full-text search, action filter, protocol filter, traffic source filter, pagination, and inspection drawer with full metadata breakdown.
- **Rule Editor**: Interactive table with toggle switches, priority adjusters, and modal rule creation with schema validation.
- **Security Alerts**: Filterable threat list with mitigation buttons.
- **Settings**: Dynamic policy switching, threshold tuning, and factory reset.

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.12+
- Node.js 18+ and npm

### 1. Launch Everything in 1-Click
On Windows, double-click:
```bat
run_all.bat
```
This starts both the FastAPI backend and the Vite frontend, and opens `http://localhost:5173` in your browser.

---

### 2. Manual Startup

#### Backend
```bash
cd backend
py -3.12 -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
py -3.12 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`

#### Frontend
```bash
cd frontend
npm install
npm run dev
```
SOC Dashboard: `http://localhost:5173`

---

## 🧪 Automated Testing

A comprehensive automated test suite with **25 unit and integration tests** is included under `/tests`:

```bash
py -3.12 -m pytest -v tests/
```

### Test Coverage Summary:
- `tests/test_rule_matcher.py` (5 tests):
  - IP exact and CIDR subnet evaluation (`192.168.1.0/24`, `10.0.0.0/8`, `ANY`)
  - IP syntax error rejection (`999.999.999.999`, invalid CIDR masks)
  - Port parsing and range matching (`80`, `1024-65535`, `80,443`, `ANY`)
  - Port syntax error validation (out-of-bounds ports, reversed ranges)
  - L4 Protocol matching (TCP, UDP, ICMP, ANY)
- `tests/test_firewall_engine.py` (6 tests):
  - Default-Deny fallback action when no rule matches
  - Default-Allow permissive fallback action
  - Explicit rule ALLOW decision
  - Explicit rule BLOCK decision
  - Rule priority resolution (lowest integer rule evaluated first)
  - Disabled rules skipped during evaluation
- `tests/test_anomaly_detector.py` (3 tests):
  - Sensitive port probe detection (ports 23, 445, 3389)
  - Heuristic port scan threshold triggering with sliding window
  - Heuristic SYN flood burst detection with sliding window
- `tests/test_packet_analyzer.py` (5 tests):
  - Scapy TCP packet dissection and header extraction
  - Scapy UDP packet dissection
  - Scapy ICMP packet handling with graceful missing ports
  - Non-IP frame handling
  - TCP flag combinations parser (`SYN`, `ACK`, `SYN-ACK`, `FIN`, `RST`)
- `tests/test_api_endpoints.py` (6 tests):
  - Health check endpoint
  - Rules CRUD with Pydantic validation and error handling
  - Packet log ingestion, pagination, and search
  - Heuristic security alerts and 1-click Auto-Block IP mitigation
  - Dashboard statistics and distribution metrics
  - Traffic simulator controls and system settings updates

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check & engine status |
| `GET` | `/api/dashboard/stats` | Aggregated telemetry & protocol distributions |
| `GET` | `/api/dashboard/timeline` | Rolling traffic volume over time |
| `GET` | `/api/rules` | List all firewall rules ordered by priority |
| `POST` | `/api/rules` | Create a new firewall rule |
| `PUT` | `/api/rules/{id}` | Update existing rule |
| `PATCH` | `/api/rules/{id}/toggle` | Toggle rule enabled / disabled |
| `PATCH` | `/api/rules/{id}/priority` | Update rule priority precedence |
| `DELETE` | `/api/rules/{id}` | Delete firewall rule |
| `GET` | `/api/packets` | Paginated packet logs with search and filters |
| `GET` | `/api/packets/{id}` | Detailed packet metadata inspection |
| `POST` | `/api/packets/ingest` | Ingest single packet into firewall engine |
| `DELETE` | `/api/packets/clear` | Clear packet history |
| `GET` | `/api/alerts` | List heuristic anomaly security alerts |
| `PATCH` | `/api/alerts/{id}/status` | Update alert status (NEW, ACKNOWLEDGED, RESOLVED) |
| `POST` | `/api/alerts/{id}/block-ip` | Auto-mitigate: inject high-priority block rule |
| `DELETE` | `/api/alerts/clear` | Clear alerts |
| `GET` | `/api/simulator/status` | Synthetic generator status |
| `POST` | `/api/simulator/start` | Start synthetic traffic generator |
| `POST` | `/api/simulator/stop` | Stop synthetic traffic generator |
| `POST` | `/api/simulator/generate` | Generate synchronous packet batch |
| `POST` | `/api/simulator/config` | Update rate (ms) and batch size |
| `POST` | `/api/pcap/upload` | Dissect uploaded `.pcap` with Scapy |
| `POST` | `/api/pcap/sample` | Dissect bundled sample multi-vector `.pcap` |
| `GET` | `/api/settings` | Get all system settings and thresholds |
| `PUT` | `/api/settings/{key}` | Update system setting |
| `POST` | `/api/settings/reset-to-defaults` | Factory reset to baseline policies |

---

## 🔒 Security Best Practices Implemented
- **Default-Deny Model**: Explicit whitelisting ensures that zero-day and unclassified protocols cannot bypass defenses.
- **Fail-Safe Exception Handling**: Any malformed network frame is safely quarantined and logged without crashing the engine.
- **Automated Incident Response**: One-click rule generation stops active threat actors in real-time.
- **Sliding-Window Heuristics**: Time-decayed memory prevents memory leaks while catching stealth attacks across minutes.

---

## 🚀 Deployment Guide

### Option 1: Docker Compose (All-in-One Containerized)
Clone the repository and run:
```bash
git clone https://github.com/kavin18022005/Packet-filter-firewall.git
cd Packet-filter-firewall
docker compose up --build
```
- Frontend: `http://localhost:5173`
- Backend API Docs: `http://localhost:8000/docs`

### Option 2: Cloud Deployment (Vercel + Render)
1. **Frontend (Vercel)**:
   - Connect repository `kavin18022005/Packet-filter-firewall` to [Vercel](https://vercel.com).
   - Set Root Directory to `frontend`.
   - Build Command: `npm run build`
   - Output Directory: `dist`
   - Set Environment Variable: `VITE_API_URL=https://<your-backend-url>`

2. **Backend (Render / Railway)**:
   - Deploy as a Docker Web Service pointing to the root `Dockerfile`.
   - Port: `8000`

---

## 👤 Author & Maintainer

- **Developer**: Kavin S ([@kavin18022005](https://github.com/kavin18022005))
- **Repository**: [https://github.com/kavin18022005/Packet-filter-firewall](https://github.com/kavin18022005/Packet-filter-firewall)
- **License**: [MIT License](LICENSE)
