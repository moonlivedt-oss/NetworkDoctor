@echo off
chcp 65001 >nul
setlocal
rem Обычный запуск NetworkDoctor (без прав администратора).
rem Диагностика и быстрая починка прокси работают; глубокий сброс - нет.
cd /d "%~dp0"
call "%~dp0_python.cmd" || exit /b 1
if defined PYW (
    start "" "%PYW%" "%~dp0run.pyw"
) else (
    start "" %PY% "%~dp0run.pyw"
)
