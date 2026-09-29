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
    "accent": "violet",        # 'violet' | 'blue' | 'teal' | 'rose'
    "language": "ru",          # 'ru' | 'en'
    "autofix": False,          # авто-починка при обрыве
    "ping_host": "1.1.1.1",    # хост по умолчанию для «Пинг хоста»
    "monitor_interval": 20,    # период проверки связи мониторингом, сек
    "github_repo": "moonlivedt-oss/MoonMinder",  # 'owner/name' для проверки обновлений
    "check_updates": True,     # тихо проверять обновления при запуске (раз в сутки)
    "last_update_check": "",   # дата последней авто-проверки (YYYY-MM-DD)
    "win_geometry": "",        # сохранённая геометрия окна (hex saveGeometry)
}

_data: dict = dict(DEFAULTS)


def _coerce(key: str, value):
    """Привести значение к типу значения по умолчанию.

    Битый или подменённый config.json не должен ронять программу (например
    monitor_interval='abc' → int('abc') упал бы при включении мониторинга) и не
    должен подсовывать неожиданный тип. Несовместимое значение заменяем на
    дефолт. bool проверяем до int — bool является подтипом int в Python.
    """
    default = DEFAULTS[key]
    if isinstance(default, bool):
        return value if isinstance(value, bool) else default
    if isinstance(default, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    if isinstance(default, str):
        return value if isinstance(value, str) else default
    return value


def load() -> dict:
    """Загрузить настройки с диска (с дополнением значений по умолчанию)."""
    global _data
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            merged = dict(DEFAULTS)
            merged.update({k: _coerce(k, v) for k, v in raw.items()
                           if k in DEFAULTS})
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
