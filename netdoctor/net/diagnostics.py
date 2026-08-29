# -*- coding: utf-8 -*-
"""Диагностика сети: системный прокси, WinHTTP, переменные окружения,
виртуальные адаптеры и умная проверка связи."""

from __future__ import annotations

import os
import socket
import time
import urllib.request
import winreg
from concurrent.futures import ThreadPoolExecutor

from ..core import (
    OK, WARN, BAD, INFO,
    INET_SETTINGS, ENV_KEY, PROXY_ENV_NAMES, VPN_ADAPTER_HINTS,
)
from .tools import collect_fast_state, collect_remnant_state
from .hosts import read_hosts_entries

_WININET_TITLE = "Системный прокси Windows"
_ADAPTERS_TITLE = "Виртуальные адаптеры (VPN/туннели)"
_CONCLUSION = "⟹ Вывод"


def check_wininet_proxy() -> dict:
    """Проверить системный прокси Windows (WinINET) — главный виновник."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_SETTINGS) as k:
            try:
                enable = winreg.QueryValueEx(k, "ProxyEnable")[0]
            except FileNotFoundError:
                enable = 0
            try:
                server = winreg.QueryValueEx(k, "ProxyServer")[0]
            except FileNotFoundError:
                server = ""
            try:
                autocfg = winreg.QueryValueEx(k, "AutoConfigURL")[0]
            except FileNotFoundError:
                autocfg = ""
    except FileNotFoundError:
        return {"status": OK, "title": _WININET_TITLE,
                "detail": "Не настроен (прямое подключение)."}

    if enable and server:
        return {"status": WARN, "title": _WININET_TITLE,
                "detail": f"ВКЛЮЧЁН: {server}\n"
                          f"Если прокси-клиент выключен, а это осталось — "
                          f"интернет не работает. Рекомендуется сброс."}
    if autocfg:
        return {"status": WARN, "title": _WININET_TITLE,
                "detail": f"Автонастройка (PAC): {autocfg}"}
    return {"status": OK, "title": _WININET_TITLE,
            "detail": "Выключен (прямое подключение)."}


def check_winhttp_proxy(state: dict) -> dict:
    """Проверить WinHTTP-прокси (его использует часть системных служб)."""
    lines = state.get("winhttp", [])
    out = "\n".join(lines)
    low = out.lower()
    if "direct access" in low or "прямой доступ" in low or "прямого" in low:
        return {"status": OK, "title": "WinHTTP-прокси",
                "detail": "Прямой доступ (прокси не задан)."}
    # Если явно указан сервер — вытащим строку с ним.
    nonempty = [ln.strip() for ln in lines if ln.strip()]
    proxy_line = next((ln for ln in nonempty if ":" in ln and
                       any(c.isdigit() for c in ln)), "")
    return {"status": WARN, "title": "WinHTTP-прокси",
            "detail": f"Задан прокси. {proxy_line}".strip()}


def check_env_proxy() -> dict:
    """Проверить переменные окружения прокси (в процессе и в реестре).

    Пустые значения (HTTP_PROXY без адреса) не считаем проблемой — они
    безвредны и часто ставятся намеренно как «отключить прокси».
    """
    found = []
    for name in PROXY_ENV_NAMES:
        val = os.environ.get(name)
        if val and val.strip():
            found.append(f"{name}={val}")
    # Постоянные пользовательские переменные.
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ENV_KEY) as k:
            for name in PROXY_ENV_NAMES:
                try:
                    val = winreg.QueryValueEx(k, name)[0]
                    if val and str(val).strip():
                        tag = f"{name}={val} (постоянная)"
                        if tag not in found:
                            found.append(tag)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass

    if found:
        return {"status": WARN, "title": "Переменные окружения прокси",
                "detail": "Найдены (могут перенаправлять трафик):\n"
                          + "\n".join(found)}
    return {"status": OK, "title": "Переменные окружения прокси",
            "detail": "Не заданы (или пустые — это нормально)."}


def check_vpn_adapters(state: dict) -> dict:
    """Найти виртуальные адаптеры VPN/туннелей и их состояние."""
    adapters = state.get("adapters", [])
    if not adapters:
        return {"status": INFO, "title": _ADAPTERS_TITLE,
                "detail": "Не удалось получить список адаптеров."}

    hits = []
    up_hits = 0
    for name, desc, status_txt in adapters:
        blob = f"{name} {desc}".lower()
        if any(h in blob for h in VPN_ADAPTER_HINTS):
            hits.append(f"{name} — {desc} [{status_txt}]".strip())
            if status_txt.strip().lower() == "up":
                up_hits += 1
    if not hits:
        return {"status": OK, "title": _ADAPTERS_TITLE,
                "detail": "Активных VPN-адаптеров не найдено."}
    status = WARN if up_hits else INFO
    detail = "Найдены адаптеры:\n" + "\n".join(hits)
    if up_hits:
        detail += ("\n\nЕсть активные (Up). Если VPN выключен, а адаптер висит "
                   "активным — это может мешать. Отключи VPN-приложение "
                   "или глубокий сброс сети.")
    return {"status": status, "title": _ADAPTERS_TITLE, "detail": detail}


def check_firewall_blocks(rstate: dict) -> dict:
    """Проверить исходящие блок-правила брандмауэра (остатки VPN kill-switch)."""
    title = "Файрвол: блок-правила (kill-switch)"
    rules = rstate.get("firewall", [])
    if not rules:
        return {"status": OK, "title": title,
                "detail": "Исходящих блокирующих правил нет — трафик не заблокирован."}
    vpn_like = [r["name"] for r in rules if r["vpn_like"]]
    if vpn_like:
        shown = "\n".join(f"• {n}" for n in vpn_like[:8])
        return {"status": WARN, "title": title,
                "detail": ("Найдены блок-правила, похожие на VPN/kill-switch — "
                           "они могут блокировать весь интернет после падения "
                           f"VPN:\n{shown}\n\nПоможет «Убрать остатки VPN» "
                           "(сброс брандмауэра).")}
    return {"status": INFO, "title": title,
            "detail": (f"Есть исходящие блок-правила ({len(rules)} шт.). "
                       "Обычно это норма, но если интернет заблокирован целиком "
                       "после VPN — их сбрасывает «Убрать остатки VPN».")}


def check_stale_routes(rstate: dict) -> dict:
    """Проверить зависшие маршруты на отключённых адаптерах."""
    title = "Зависшие маршруты (мёртвые туннели)"
    stale = rstate.get("stale_routes", [])
    if not stale:
        return {"status": OK, "title": title,
                "detail": "Маршрутов через отключённые адаптеры нет."}
    shown = "\n".join(f"• {r['prefix']} → «{r['iface']}» ({r['status']})"
                      for r in stale[:8])
    return {"status": WARN, "title": title,
            "detail": ("Есть маршруты на адаптерах не в статусе Up — обычно "
                       "остатки крашнутого туннеля, трафик может уходить в "
                       f"никуда:\n{shown}\n\nПочинит «Убрать остатки VPN».")}


def check_hosts_file() -> dict:
    """Проверить файл hosts на нестандартные активные записи."""
    title = "Файл hosts"
    entries = read_hosts_entries()
    if not entries:
        return {"status": OK, "title": title,
                "detail": "Нестандартных записей нет (чисто)."}
    suspicious = [e["line"] for e in entries if e["suspicious"]]
    if suspicious:
        shown = "\n".join(f"• {s}" for s in suspicious[:8])
        more = f"\n…и ещё {len(suspicious) - 8}" if len(suspicious) > 8 else ""
        return {"status": WARN, "title": title,
                "detail": ("Найдены подозрительные перенаправления — реальные "
                           "домены уводятся на loopback/0.0.0.0, из-за чего "
                           f"сайты не грузятся:\n{shown}{more}\n\nОткрой файл "
                           "hosts и удали лишнее, если это не ты добавлял.")}
    # только записи dev-инструментов (Docker и т.п.) — безвредно
    shown = "\n".join(f"• {e['line']}" for e in entries[:6])
    return {"status": INFO, "title": title,
            "detail": ("Есть записи, но они выглядят безвредно (dev-инструменты "
                       f"вроде Docker):\n{shown}")}


def check_mtu(state: dict) -> dict:
    """Проверить MTU активного адаптера (туннель мог занизить)."""
    title = "MTU активного адаптера"
    name, mtu = state.get("default", ""), state.get("mtu", -1)
    if mtu < 0:
        return {"status": INFO, "title": title,
                "detail": "Не удалось определить MTU."}
    if mtu >= 1500:
        return {"status": OK, "title": title,
                "detail": f"«{name}»: MTU {mtu} — норма."}
    if mtu >= 1400:
        return {"status": INFO, "title": title,
                "detail": f"«{name}»: MTU {mtu} — чуть занижен, обычно ок."}
    return {"status": WARN, "title": title,
            "detail": (f"«{name}»: MTU {mtu} — заметно занижен (туннель мог "
                       "оставить). Из-за этого часть сайтов «висит». Вернуть "
                       "к 1500 поможет «Убрать остатки VPN».")}


def check_vpn_remnants(rstate: dict) -> list[dict]:
    """Медленные проверки остатков VPN (файрвол, зависшие маршруты)."""
    return [check_firewall_blocks(rstate), check_stale_routes(rstate)]


def _http_ok(timeout: int = 8, budget: float | None = None) -> tuple[bool, str]:
    """Пройдёт ли обычный HTTPS-запрос (с учётом системного прокси).

    urllib на Windows читает системный прокси из реестра, поэтому если прокси
    застрял/мёртв — запрос упадёт, а «сырой» TCP при этом может работать.

    budget — общий бюджет времени (сек): перебираем несколько URL, но перестаём
    начинать новые попытки, как только суммарно потратили budget. Нужен монитору,
    чтобы при полном обрыве цикл не висел timeout×(число URL) секунд.
    """
    urls = ("https://www.gstatic.com/generate_204",
            "https://cloudflare.com/cdn-cgi/trace",
            "https://api.ipify.org")
    last = ""
    start = time.monotonic()
    for url in urls:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "NetworkDoctor"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if 200 <= r.status < 400:
                    return True, url
        except Exception as e:
            last = str(e)
        if budget is not None and (time.monotonic() - start) >= budget:
            break
    return False, last


def quick_online(timeout: int = 5, budget: float | None = 8) -> bool:
    """Быстро: есть ли реально рабочий интернет (HTTPS через систему).

    По умолчанию с бюджетом ~8 с, чтобы при обрыве монитор не залипал надолго.
    """
    ok, _ = _http_ok(timeout=timeout, budget=budget)
    return ok


def check_connectivity(proxy_configured: bool,
                       http_result: tuple | None = None) -> list[dict]:
    """Умная проверка: отдельно «сырое» соединение и путь через прокси.

    Ключ: если СЫРОЙ TCP работает, HTTPS через системные настройки — нет,
    И при этом системный прокси включён → почти наверняка застрявший прокси.
    http_result — заранее посчитанный (_http_ok), чтобы не ходить в сеть дважды.
    """
    results = []

    # 1. Сырой TCP до 1.1.1.1:443 и 8.8.8.8:53 — минуя прокси на уровне сокета.
    direct_ok = False
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        try:
            socket.create_connection((host, port), timeout=4).close()
            direct_ok = True
            break
        except Exception:
            continue
    if direct_ok:
        results.append({"status": OK, "title": "Прямое соединение (TCP)",
                        "detail": "Есть связь с интернетом на уровне сети."})
    else:
        results.append({"status": BAD, "title": "Прямое соединение (TCP)",
                        "detail": "НЕТ связи даже напрямую.\nПроблема глубже "
                                  "прокси — попробуй «Обновить IP», а если не "
                                  "поможет — глубокий сброс сети."})

    # 2. DNS.
    try:
        socket.gethostbyname("example.com")
        results.append({"status": OK, "title": "DNS (разрешение имён)",
                        "detail": "Имена сайтов разрешаются нормально."})
    except Exception as e:
        results.append({"status": BAD, "title": "DNS (разрешение имён)",
                        "detail": f"НЕ работает: {e}\nПоможет сброс DNS-кеша."})

    # 3. HTTPS через системные настройки (как ходят браузеры/приложения).
    http_ok, info = http_result if http_result is not None else _http_ok()
    if http_ok:
        results.append({"status": OK, "title": "HTTPS через системные настройки",
                        "detail": "Запросы проходят нормально."})
    else:
        results.append({"status": WARN if not proxy_configured else BAD,
                        "title": "HTTPS через системные настройки",
                        "detail": f"НЕ проходит: {info}"})

    # 4. Вывод-подсказка на основе комбинации.
    if direct_ok and not http_ok and proxy_configured:
        results.append({"status": BAD, "title": _CONCLUSION,
                        "detail": "Сеть жива, системный прокси ВКЛЮЧЁН, но "
                                  "запросы через него не проходят.\n"
                                  "Скорее всего ЗАСТРЯЛ МЁРТВЫЙ ПРОКСИ. "
                                  "Нажми «Быстрая починка прокси» "
                                  "(если сейчас не пользуешься прокси-клиентом)."})
    elif direct_ok and not http_ok and not proxy_configured:
        results.append({"status": WARN, "title": _CONCLUSION,
                        "detail": "Сеть на уровне TCP есть, но HTTPS не идёт, "
                                  "а системный прокси не включён.\nЕсли сейчас "
                                  "активен туннель/прокси-клиент — это может "
                                  "быть нормой. Иначе попробуй сброс DNS/IP."})
    elif direct_ok and http_ok:
        results.append({"status": OK, "title": _CONCLUSION,
                        "detail": "Интернет работает нормально."})
    return results


def run_core_diagnosis() -> list[dict]:
    """Основные (быстрые) проверки: прокси, адаптеры, связь, hosts, MTU.

    Сбор системного состояния (PowerShell) и сетевые пробы (TCP/DNS/HTTPS)
    идут параллельно — так окно показывает результат за пару секунд.
    """
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_state = ex.submit(collect_fast_state)
        fut_http = ex.submit(_http_ok)
        state = fut_state.result()
        http_result = fut_http.result()

    wininet = check_wininet_proxy()
    winhttp = check_winhttp_proxy(state)
    env = check_env_proxy()
    proxy_configured = any(x["status"] == WARN for x in (wininet, winhttp))
    items = [wininet, winhttp, env, check_vpn_adapters(state)]
    items.extend(check_connectivity(proxy_configured, http_result))
    items.append(check_mtu(state))
    items.append(check_hosts_file())
    return items


def run_remnant_diagnosis() -> list[dict]:
    """Медленные проверки остатков VPN (файрвол, зависшие маршруты)."""
    return check_vpn_remnants(collect_remnant_state())
