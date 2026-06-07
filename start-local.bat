@echo off
set ROOT=%~dp0

start "Threat Intel Backend" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%run-local.ps1"
start "Threat Intel Frontend" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%run-frontend-local.ps1"

echo Started backend and frontend windows.
echo Backend docs: http://127.0.0.1:8000/docs
echo Frontend: http://127.0.0.1:5173

