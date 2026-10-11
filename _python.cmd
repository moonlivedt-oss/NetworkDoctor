@echo off
rem Общий поиск Python для батников NetworkDoctor (вызывается через call).
rem Ищет Python 3.10+ (сначала через py-лаунчер, новые версии раньше, потом
rem python из PATH). Нет PyQt6 - ставит его сам, один раз. Результат:
rem переменные PY (с консолью) и PYW (настоящий pythonw.exe, без окна консоли).
set "PY="
set "PYW="
for %%V in (3.14 3.13 3.12 3.11 3.10) do if not defined PY (
    py -%%V -c "import PyQt6.QtWidgets" >nul 2>&1 && set "PY=py -%%V"
)
if not defined PY (
    python -c "import sys, PyQt6.QtWidgets; sys.exit(sys.version_info < (3, 10))" >nul 2>&1 && set "PY=python"
)
if defined PY goto :pyw

rem PyQt6 нигде нет - берём самый новый подходящий Python и ставим пакет.
for %%V in (3.14 3.13 3.12 3.11 3.10) do if not defined PY (
    py -%%V -c "import sys" >nul 2>&1 && set "PY=py -%%V"
)
if not defined PY (
    python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo.
    echo Не найден Python 3.10 или новее.
    echo Установите его с https://www.python.org/downloads/ или скачайте готовый
    echo NetworkDoctor.exe со страницы Releases - ему Python не нужен.
    echo.
    pause
    exit /b 1
)
echo Первый запуск: ставлю PyQt6 (один раз, нужен интернет)...
%PY% -m pip install --disable-pip-version-check -r "%~dp0requirements.txt"
%PY% -c "import PyQt6.QtWidgets" >nul 2>&1 || (
    echo Не удалось поставить PyQt6. Текст ошибки - выше.
    pause
    exit /b 1
)

:pyw
rem Настоящий pythonw.exe рядом с python.exe: заглушка pyw из Microsoft Store
rem мелькает и не стартует.
for /f "delims=" %%p in ('%PY% -c "import os, sys; print(os.path.join(os.path.dirname(sys.executable), 'pythonw.exe'))"') do set "PYW=%%p"
if not exist "%PYW%" set "PYW="
exit /b 0
