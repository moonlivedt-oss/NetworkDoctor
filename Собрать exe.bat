@echo off
REM Сборка NetworkDoctor в один .exe (без консоли), запускается без Python.
REM Требует: pip install pyinstaller
chcp 65001 >nul
cd /d "%~dp0"

echo === Проверяю PyInstaller ===
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller не установлен. Устанавливаю...
    python -m pip install pyinstaller
)

echo === Собираю NetworkDoctor.exe ===
python -m PyInstaller --noconfirm --clean ^
    --name NetworkDoctor ^
    --onefile ^
    --noconsole ^
    --hidden-import PyQt6.sip ^
    run.pyw

echo.
echo Готово. Файл: dist\NetworkDoctor.exe
pause
