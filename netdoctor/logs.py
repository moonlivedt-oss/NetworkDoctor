# -*- coding: utf-8 -*-
"""Файловые логи, история состояний сети (JSONL) и текстовые отчёты.

Всё, что делает утилита, и любые ошибки пишутся в файл — чтобы потом можно
было разобраться, ЧТО и КОГДА пошло не так (журнал в окне теряется при
закрытии). Плюс отдельная «история состояний»: по одному событию на строку —
удобно листать и искать, когда именно пропадал интернет или менялся выход.
"""

from __future__ import annotations

import datetime
import json
import logging
import platform
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import __version__
from .core import OK, WARN, BAD, INFO, is_admin, logger


def _base_dir() -> Path:
    """Корень проекта (папка над пакетом) — чтобы логи было легко найти."""
    try:
        return Path(__file__).resolve().parent.parent
    except Exception:
        return Path.cwd()


BASE_DIR = _base_dir()
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "netdoctor.log"
STATE_FILE = LOG_DIR / "network_state.jsonl"


def setup_logging() -> None:
    """Один раз настроить запись логов в файл с ротацией (5×1 МБ)."""
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-7s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(handler)
        logger.info("=" * 60)
        logger.info("NetworkDoctor запущен (админ=%s)", is_admin())
    except Exception:
        # Логи — не критично; если папку нельзя создать, работаем без файла.
        logger.addHandler(logging.NullHandler())


def record_state(kind: str, **data) -> None:
    """Дописать одно событие в историю состояний (JSONL, одна строка = событие).

    kind: 'diagnosis' | 'fix' | 'monitor' | 'tool'. Ошибки записи глушим —
    сохранение истории не должно мешать основной работе.
    """
    entry = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
             "kind": kind}
    entry.update(data)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with STATE_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning("Не удалось записать историю состояния: %s", e)


def read_state_history(limit: int = 80) -> list[dict]:
    """Прочитать последние `limit` событий истории (самые свежие — первыми)."""
    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []
    except Exception as e:
        logger.warning("Не удалось прочитать историю: %s", e)
        return []
    out = []
    for ln in lines[-limit:]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    out.reverse()
    return out


def install_excepthook() -> None:
    """Ловить необработанные исключения и писать их в лог (чтобы не терять)."""
    prev = sys.excepthook

    def hook(exc_type, exc, tb):
        logger.critical("Необработанное исключение",
                        exc_info=(exc_type, exc, tb))
        prev(exc_type, exc, tb)

    sys.excepthook = hook


def build_report(items: list[dict] | None, log_text: str) -> str:
    """Собрать текстовый отчёт: состояние сети + журнал сеанса — для пересылки.

    Работает офлайн (по последней диагностике), чтобы отчёт можно было выгрузить
    даже когда интернет не работает.
    """
    marks = {OK: "[ OK ]", WARN: "[ !! ]", BAD: "[ XX ]", INFO: "[ ii ]"}
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        win = f"{platform.system()} {platform.release()} (сборка {platform.version()})"
    except Exception:
        win = "?"
    lines = [
        "NetworkDoctor — отчёт о состоянии сети",
        "=" * 52,
        f"Версия NetworkDoctor: {__version__}",
        f"Дата:                 {now}",
        f"Система:              {win}",
        f"Права администратора: {'да' if is_admin() else 'нет'}",
        f"Python:               {sys.version.split()[0]}",
        "",
        "ДИАГНОСТИКА",
        "-" * 52,
    ]
    if not items:
        lines.append("Диагностика ещё не запускалась в этом сеансе.")
    else:
        for it in items:
            mark = marks.get(it.get("status"), "[ ?? ]")
            lines.append(f"{mark} {it.get('title', '')}")
            for dl in str(it.get("detail", "")).strip().splitlines():
                lines.append(f"        {dl}")
            lines.append("")
    lines += ["ЖУРНАЛ СЕАНСА", "-" * 52, log_text.strip() or "(пусто)", ""]
    return "\n".join(lines)
