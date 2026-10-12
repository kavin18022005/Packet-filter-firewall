@echo off
echo ========================================================
echo Starting Data-Driven Packet Filtering Firewall Backend
echo FastAPI + Scapy + SQLite Heuristic Anomaly Engine
echo ========================================================
cd /d "%~dp0"
py -3.12 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
pause
