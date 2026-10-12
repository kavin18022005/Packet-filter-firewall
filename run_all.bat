@echo off
echo ========================================================
echo Launching Data-Driven Packet Filtering Firewall & SOC Dashboard
echo ========================================================
cd /d "%~dp0"

start "CyberWall Backend (FastAPI)" cmd /c "py -3.12 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload"
timeout /t 2 /nobreak >nul

start "CyberWall Frontend (Vite)" cmd /c "cd frontend && npm run dev"
timeout /t 3 /nobreak >nul

start http://localhost:5173
echo Services launched! Backend: http://127.0.0.1:8000/docs | Frontend: http://localhost:5173
