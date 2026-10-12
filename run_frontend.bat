@echo off
echo ========================================================
echo Starting CyberWall SOC Frontend Dashboard
echo React + Vite + Tailwind CSS + Recharts
echo ========================================================
cd /d "%~dp0\frontend"
cmd.exe /c npm run dev
pause
