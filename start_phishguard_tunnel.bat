@echo off
title PhishGuard Local Backend & Cloudflare Tunnel Launcher

echo ==================================================
echo Starting PhishGuard FastAPI Local Backend (0.0.0.0:8000)...
echo ==================================================

start "PhishGuard Backend" /min "E:\CAPSTONE\PhishGuard-main\Backend\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000

timeout /t 3 /nobreak >nul

echo ==================================================
echo Starting Cloudflare HTTPS Tunnel...
echo ==================================================

"E:\CAPSTONE\PhishGuard-main\cloudflared.exe" tunnel --url http://127.0.0.1:8000

pause
