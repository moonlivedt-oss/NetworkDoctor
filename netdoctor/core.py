# -*- coding: utf-8 -*-
"""Базовые вещи: права администратора, запуск команд, общие константы."""

from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys

# Ветка реестра, где Windows (и все прокси-клиенты) хранит системный прокси.
INET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
ENV_KEY = r"Environment"  # пользовательские переменные окружения (HKCU)
PROXY_ENV_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
                   "http_proxy", "https_proxy", "all_proxy", "ftp_proxy")

# Ключевые слова в именах/описаниях виртуальных сетевых адаптеров.
VPN_ADAPTER_HINTS = ("wireguard", "wintun", "tap", "tun", "openvpn",
                     "nekoray", "clash", "v2ray", "xray", "shadowsocks",
                     "hiddify", "amnezia", "outline", "proton", "nord",
                     "surfshark", "warp", "cloudflare", "happ", "sing")

# Типичные локальные порты прокси-клиентов (SOCKS/HTTP).
PROXY_PORTS = {1080, 1081, 1082, 2080, 2081, 3128, 7890, 7891, 7892, 7897,
               8080, 8081, 8118, 8888, 9090, 9091, 10800, 10801, 10808,
               10809, 10810, 20170, 20171}

# Ключевые слова в именах процессов прокси-клиентов.
PROXY_PROC_HINTS = ("nekoray", "nekobox", "v2ray", "xray", "sing-box",
                    "singbox", "clash", "mihomo", "hiddify", "happ",
                    "shadowsocks", "ss-local", "sslocal", "tun2socks",
                    "qv2ray", "netch", "proxifier", "v2rayn", "warp",
                    "amnezia", "outline")

# Статусы для отображения.
OK, WARN, BAD, INFO = "ok", "warn", "bad", "info"

logger = logging.getLogger("NetworkDoctor")

# --- Абсолютные пути к системным утилитам ----------------------------------
# Запуск по «голому» имени («netsh», «powershell») небезопасен: Windows ищет
# исполняемый файл в т.ч. в текущей папке и папке приложения РАНЬШЕ System32.
# Если рядом подложить netsh.exe/powershell.exe — выполнится подделка, а мы
# нередко работаем с правами администратора (binary planting). Поэтому все
# системные утилиты резолвим в абсолютный путь внутри System32.
_SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
_SYSTEM_EXES = {
    "powershell": os.path.join(_SYS32, "WindowsPowerShell", "v1.0",
                               "powershell.exe"),
    "netsh": os.path.join(_SYS32, "netsh.exe"),
    "ipconfig": os.path.join(_SYS32, "ipconfig.exe"),
    "ping": os.path.join(_SYS32, "ping.exe"),
    "tasklist": os.path.join(_SYS32, "tasklist.exe"),
    "netstat": os.path.join(_SYS32, "netstat.exe"),
    "taskkill": os.path.join(_SYS32, "taskkill.exe"),
    "arp": os.path.join(_SYS32, "arp.exe"),
    "route": os.path.join(_SYS32, "route.exe"),
}


def _resolve_exe(name: str) -> str:
    """Абсолютный путь к системной утилите в System32, если он существует.

    Иначе возвращаем имя как есть (нестандартная система) — чтобы не сломать
    запуск там, где раскладка папок отличается.
    """
    path = _SYSTEM_EXES.get(name.lower())
    return path if path and os.path.exists(path) else name


def is_admin() -> bool:
    """True, если процесс запущен с правами администратора."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """Перезапустить эту же программу с запросом прав администратора (UAC)."""
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )


def relaunch_self() -> None:
    """Перезапустить программу без повышения прав (для применения темы/языка)."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "open", sys.executable,
        " ".join(f'"{a}"' for a in sys.argv), None, 1)


def ps_quote(s: str) -> str:
    """Безопасно обернуть строку в одинарные кавычки для PowerShell.

    Имена адаптеров могут содержать апостроф (например «O'Brien Wi-Fi») —
    без экранирования это ломает команду. В PS одинарная кавычка внутри строки
    удваивается: ' → ''.
    """
    return "'" + str(s).replace("'", "''") + "'"


def run_cmd(args: list[str], timeout: int = 30) -> tuple[int, str]:
    """Запустить команду без всплывающего окна консоли.

    Возвращает (код_возврата, текст_вывода). Декодируем «умно»: сначала пробуем
    UTF-8 (так пишут PowerShell в UTF-8-режиме и Unicode-символы вроде эмодзи) —
    кириллица в OEM-кодировке (cp866, вывод netsh/ipconfig) как UTF-8 невалидна
    и упадёт, поэтому такой вывод корректно уходит в 'oem'. Итог: не рассыпается
    ни UTF-8, ни консольная кириллица.
    """
    if args:
        args = [_resolve_exe(args[0]), *args[1:]]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
    except subprocess.TimeoutExpired:
        logger.warning("Команда не ответила за %s с: %s", timeout, " ".join(args))
        return -1, "(команда не ответила вовремя)"
    except FileNotFoundError:
        logger.warning("Команда не найдена: %s", args[0])
        return -1, f"(команда не найдена: {args[0]})"

    raw = (proc.stdout or b"") + (proc.stderr or b"")
    for enc in ("utf-8-sig", "oem", "cp866", "cp1251"):
        try:
            return proc.returncode, raw.decode(enc)
        except Exception:
            continue
    return proc.returncode, raw.decode("utf-8", errors="replace")
