@echo off
REM Запуск NetworkDoctor с правами администратора (нужно для глубокого сброса).
REM Если прав нет — сам запросит их через UAC и перезапустится.

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
REM PyQt6 стоит в Python 3.14 — целимся явно (pythonw из PATH = 3.11 без зависимостей).
start "" pyw -3.14 "run.pyw"
