# -*- coding: utf-8 -*-
"""Пользовательские настройки: тема, язык, состояния тумблеров, хост для пинга.

Хранится в logs/config.json. Загружается один раз при импорте; изменения
пишутся сразу. Ошибки чтения/записи не фатальны — используются значения по
умолчанию.
"""

from __future__ import annotations

import json
from pathlib import Path

from .logs import LOG_DIR

CONFIG_FILE: Path = LOG_DIR / "config.json"

DEFAULTS = {
    "theme": "dark",           # 'dark' | 'light'
    "language": "ru",          # 'ru' | 'en'
    "autofix": False,          # авто-починка при обрыве
    "ping_host": "1.1.1.1",    # хост по умолчанию для «Пинг хоста»
    "monitor_interval": 20,    # период проверки связи мониторингом, сек
    "github_repo": "",         # 'owner/name' для проверки обновлений
}

_data: dict = dict(DEFAULTS)


def load() -> dict:
    """Загрузить настройки с диска (с дополнением значений по умолчанию)."""
    global _data
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            merged = dict(DEFAULTS)
            merged.update({k: v for k, v in raw.items() if k in DEFAULTS})
            _data = merged
    except Exception:
        _data = dict(DEFAULTS)
    return _data


def save() -> bool:
    """Сохранить текущие настройки на диск. True при успехе."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            json.dumps(_data, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def get(key: str, default=None):
    return _data.get(key, DEFAULTS.get(key, default))


def set(key: str, value) -> None:
    """Установить значение и сразу сохранить."""
    _data[key] = value
    save()


# Загружаем при импорте, чтобы тема/язык были готовы до создания окна.
load()
