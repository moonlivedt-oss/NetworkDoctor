# -*- coding: utf-8 -*-
r"""Автозапуск NetworkDoctor вместе с Windows (свёрнутым в трей).

Пишем команду в HKCU\...\Run — это не требует прав администратора и работает
для текущего пользователя. Запускаем через pythonw (без окна консоли) наш
launcher run.pyw с флагом --tray, чтобы окно стартовало свёрнутым в трей.
"""

from __future__ import annotations

import sys
import winreg
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "NetworkDoctor"


def _launcher_path() -> Path:
    """Путь к run.pyw в корне проекта (папка над пакетом)."""
    return Path(__file__).resolve().parent.parent / "run.pyw"


def _pythonw() -> str:
    """pythonw.exe рядом с текущим python (запуск без окна консоли)."""
    exe = Path(sys.executable)
    cand = exe.with_name("pythonw.exe")
    return str(cand if cand.exists() else exe)


def autostart_command() -> str:
    """Команда, которая будет прописана в автозапуск.

    Если приложение собрано в .exe (PyInstaller) — запускаем сам .exe;
    иначе pythonw + наш launcher run.pyw. И то, и то с флагом --tray.
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --tray'
    return f'"{_pythonw()}" "{_launcher_path()}" --tray'


def is_autostart_enabled() -> bool:
    """Прописан ли автозапуск (и указывает ли на нас)."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            val = str(winreg.QueryValueEx(k, APP_NAME)[0]).lower()
        return "run.pyw" in val or ("networkdoctor" in val and "--tray" in val)
    except FileNotFoundError:
        return False
    except Exception:
        return False


def enable_autostart() -> tuple[bool, str]:
    """Включить автозапуск. Возвращает (успех, сообщение)."""
    # В режиме .exe launcher не нужен — стартуем сам исполняемый файл.
    if not getattr(sys, "frozen", False):
        launcher = _launcher_path()
        if not launcher.exists():
            return False, f"Не найден launcher: {launcher}"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ,
                              autostart_command())
        return True, "Автозапуск включён (старт свёрнутым в трей)."
    except Exception as e:
        return False, f"Не удалось включить автозапуск: {e}"


def disable_autostart() -> tuple[bool, str]:
    """Выключить автозапуск. Возвращает (успех, сообщение)."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, APP_NAME)
        return True, "Автозапуск выключен."
    except FileNotFoundError:
        return True, "Автозапуск и так был выключен."
    except Exception as e:
        return False, f"Не удалось выключить автозапуск: {e}"
