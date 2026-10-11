@echo off
chcp 65001 >nul
setlocal
rem Сборка NetworkDoctor в один .exe (без консоли), запускается без Python.
rem Python и PyQt6 находит/ставит _python.cmd, PyInstaller ставится сам.
cd /d "%~dp0"
call "%~dp0_python.cmd" || exit /b 1

echo === Проверяю PyInstaller ===
%PY% -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller не установлен. Устанавливаю...
    %PY% -m pip install --disable-pip-version-check pyinstaller
)

echo === Собираю NetworkDoctor.exe ===
%PY% -m PyInstaller --noconfirm --clean ^
    --name NetworkDoctor ^
    --onefile ^
    --noconsole ^
    --hidden-import PyQt6.sip ^
    run.pyw
if errorlevel 1 (
    echo Сборка не удалась. Текст ошибки - выше.
    pause
    exit /b 1
)

echo.
echo Готово. Файл: dist\NetworkDoctor.exe
pause
