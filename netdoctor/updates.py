# -*- coding: utf-8 -*-
"""Проверка обновлений через GitHub Releases.

Укажи свой репозиторий в GITHUB_REPO ('owner/name'). Если пусто — проверка
сообщает, что репозиторий не настроен. Сеть может быть недоступна — тогда
возвращаем понятную ошибку, не роняя приложение.
"""

from __future__ import annotations

import json
import re
import urllib.request

from . import __version__

# Репозиторий по умолчанию (fallback). Обычно задаётся не тут, а в настройках
# (config.json → "github_repo") — тогда не нужно править код. Формат: 'owner/name'.
GITHUB_REPO = "moonlivedt-oss/NetworkDoctor"

# Допустимый формат репозитория: 'владелец/название' из безопасных символов.
# Не пускаем сюда слэши/точки-переходы/пробелы, чтобы подменённый config.json не
# мог увести запрос на чужой адрес (../, лишние сегменты пути и т.п.).
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")

# Максимальный размер ответа GitHub, который читаем (защита от «бесконечного»
# тела). Реальный JSON релиза — десятки КБ.
_MAX_RESPONSE = 1_000_000


def due_for_auto_check(last_check: str, today: str) -> bool:
    """Пора ли снова тихо проверить обновления (не чаще раза в сутки).

    last_check — дата прошлой авто-проверки в формате YYYY-MM-DD (пусто — ещё
    не проверяли). today — сегодняшняя дата в том же формате. Сравнение строк
    работает, потому что формат лексикографически совпадает с хронологией.
    """
    return (last_check or "") != today


def _repo() -> str:
    """Репозиторий для проверки: сначала из настроек, потом из константы."""
    try:
        from . import settings
        return (settings.get("github_repo") or "").strip() or GITHUB_REPO
    except Exception:
        return GITHUB_REPO


def _norm(v: str) -> tuple:
    """'v2.2' / '2.2.1' → кортеж чисел для сравнения версий."""
    v = v.strip().lstrip("vV")
    parts = []
    for chunk in v.split("."):
        num = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts) or (0,)


def check_update(timeout: int = 8) -> dict:
    """Проверить последний релиз на GitHub.

    Возвращает {status, current, latest, url, note}:
      status: 'update' | 'latest' | 'unconfigured' | 'error'
    """
    current = __version__
    repo = _repo()
    if not repo:
        return {"status": "unconfigured", "current": current, "latest": "",
                "url": "", "note": "Репозиторий не настроен (github_repo)."}
    if not _REPO_RE.match(repo):
        return {"status": "error", "current": current, "latest": "", "url": "",
                "note": "Некорректный формат репозитория — нужно "
                        "«владелец/название»."}
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "NetworkDoctor",
                          "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(_MAX_RESPONSE).decode("utf-8", "replace"))
        tag = str(data.get("tag_name") or data.get("name") or "")
        html = str(data.get("html_url") or "")
        if not tag:
            return {"status": "error", "current": current, "latest": "",
                    "url": "", "note": "В ответе GitHub нет тега релиза."}
        newer = _norm(tag) > _norm(current)
        return {"status": "update" if newer else "latest",
                "current": current, "latest": tag, "url": html, "note": ""}
    except Exception as e:
        return {"status": "error", "current": current, "latest": "",
                "url": "", "note": f"Не удалось проверить: {e}"}
