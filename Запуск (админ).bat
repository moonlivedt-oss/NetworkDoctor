@echo off
chcp 65001 >nul
setlocal
rem Запуск NetworkDoctor с правами администратора (нужно для глубокого сброса).
rem Если прав нет - сам запросит их через UAC и перезапустится.
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
call "%~dp0_python.cmd" || exit /b 1
if defined PYW (
    start "" "%PYW%" "%~dp0run.pyw"
) else (
    start "" %PY% "%~dp0run.pyw"
)
