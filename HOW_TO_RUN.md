# How to Run CyberWall: Data-Driven Packet Filtering Firewall

This guide provides step-by-step instructions for running the application across Windows, Linux, macOS, and Docker environments.

---

## ⚡ Quick Start Options

### Option A: Windows 1-Click Launch (Recommended for Windows)
Double-click:
```bat
run_all.bat
```
This automatically starts:
1. **Backend Server** on `http://127.0.0.1:8000` (FastAPI + Scapy + SQLite)
2. **Frontend Dashboard** on `http://localhost:5173` (React + Vite + Tailwind CSS)
3. Opens the dashboard in your default browser.

---

### Option B: Linux / macOS 1-Click Launch
Give execute permissions and run:
```bash
chmod +x run_all.sh
./run_all.sh
```

---

### Option C: Docker Compose (All Platforms)
Ensure Docker is installed and running, then execute:
```bash
docker compose up --build
```
- **Web Dashboard**: `http://localhost:5173`
- **Backend API & Swagger Docs**: `http://localhost:8000/docs`

---

## 🛠️ Manual Step-by-Step Setup

### Prerequisites
- **Python 3.12+**
- **Node.js 18+ and npm**

---

### Step 1: Start the Backend (FastAPI + Scapy)

1. Open a terminal and navigate to the project root:
   ```bash
   cd "b:/Firewall Project"
   ```

2. (Optional) Create and activate a Python virtual environment:
   - **Windows:**
     ```powershell
     py -3.12 -m venv venv
     .\venv\Scripts\activate
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. Install backend dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

4. Start the FastAPI development server:
   ```bash
   py -3.12 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
   ```
   *(On Linux/macOS, use `uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload`)*

5. Verify backend is running:
   - **Health Endpoint**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)
   - **Swagger Interactive API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

### Step 2: Start the Frontend (React + Vite)

1. Open a second terminal window and navigate to the `frontend` folder:
   ```bash
   cd "b:/Firewall Project/frontend"
   ```

2. Install Node dependencies (first time only):
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```

4. Open your browser and navigate to:
   👉 **[http://localhost:5173](http://localhost:5173)**

---

## 🧪 Running Automated Tests

To run the complete Pytest suite (25 unit and integration tests):

```bash
# From the project root
py -3.12 -m pytest tests/ -v
```

All 25 tests test:
- CIDR IP Subnet & Protocol Matching
- Default-Deny & Priority Evaluation
- Sliding-Window Heuristic Anomaly Detection (SYN Floods & Port Scans)
- Scapy Deep Packet Dissection
- REST API Endpoints & IP Auto-Mitigation

---

## 🎮 How to Test & Use the Features

1. **Live Threat Simulator**:
   - In the top navigation bar, toggle the **"Simulator"** switch to `Active`.
   - The engine generates live synthetic network traffic (HTTP, DNS, SSH, Ping, and Port Scan bursts) in real time.
2. **Interactive Rule Management**:
   - Go to **Firewall Rules** to add rules (e.g. Block Port 23 Telnet, Block subnet `192.168.1.0/24`).
   - Toggle rules on/off or reorder priority.
3. **Deep Packet Inspector**:
   - Go to **Packet Logs** to filter by ALLOW/BLOCK, Protocol, or IP.
   - Click **"Inspect"** on any packet to view full Scapy L3/L4 headers, TCP flags, and rule match rationale.
4. **PCAP Capture Dissection**:
   - Go to **PCAP Analysis** and click **"Analyze Multi-Vector Sample PCAP"** (or upload your own `.pcap` file).
5. **Security Alert Auto-Mitigation**:
   - Go to **Security Alerts** to view detected SYN floods or port scans.
   - Click **"Auto-Block Attacker IP"** to immediately inject an automated high-priority block rule.
