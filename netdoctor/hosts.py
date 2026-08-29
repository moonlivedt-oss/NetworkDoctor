# -*- coding: utf-8 -*-
"""Работа с файлом hosts: путь, разбор записей и оценка подозрительности.

Вынесено из net_tools в отдельный модуль — логику hosts используют и
диагностика (показать записи), и починка (вычистить блокировки).
"""

from __future__ import annotations

import os


def _hosts_path() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "drivers", "etc", "hosts")


# Домены dev-инструментов, которые сами прописывают hosts — это не мусор.
_HOSTS_BENIGN_SUFFIXES = (".docker.internal", ".local", ".localhost")


def _hosts_entry_suspicious(ip: str, names: list[str]) -> bool:
    """True, если запись похожа на блокировку/подмену реального сайта.

    Подозрительно: реальный публичный домен уводится на loopback/0.0.0.0
    (классическая блокировка). Записи dev-инструментов (docker.internal и т.п.)
    и приватные адреса безвредны.
    """
    if ip in ("0.0.0.0",):
        return True
    for name in names:
        low = name.lower()
        if low in ("localhost", "localhost.localdomain"):
            continue
        if any(low.endswith(s) for s in _HOSTS_BENIGN_SUFFIXES):
            continue
        # публично выглядящий домен уводится на loopback → блокировка сайта
        if ip in ("127.0.0.1", "::1") and "." in low:
            return True
    return False


def read_hosts_entries() -> list[dict]:
    """Активные (незакомментированные) записи файла hosts, кроме стандартных
    localhost-строк. Возвращает [{line, suspicious}]."""
    path = _hosts_path()
    entries = []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for raw in f:
                line = raw.strip().lstrip("\ufeff").strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, names = parts[0], parts[1:]
                # стандартные безвредные localhost-строки
                if ip in ("127.0.0.1", "::1") and all(
                        h in ("localhost", "localhost.localdomain")
                        for h in names):
                    continue
                entries.append({"line": line,
                                "suspicious": _hosts_entry_suspicious(ip, names)})
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return entries
