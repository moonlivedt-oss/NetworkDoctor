# -*- coding: utf-8 -*-
"""Юнит-тесты чистой логики (без сети, PowerShell и Qt-цикла)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netdoctor.net import tools as nt
from netdoctor import updates
from netdoctor.net import diagnostics as diag
from netdoctor.core import OK, WARN, BAD


# --- valid_host -----------------------------------------------------------
def test_valid_host_ok():
    assert nt.valid_host("1.1.1.1")
    assert nt.valid_host("fra.login.pathofexile.com")
    assert nt.valid_host("example.com")


def test_valid_host_rejects_injection():
    assert not nt.valid_host("a.com; rm -rf /")
    assert not nt.valid_host("$(whoami)")
    assert not nt.valid_host("")
    assert not nt.valid_host("-flag")


def test_valid_host_length_limit():
    assert nt.valid_host("a" * 253)       # предельная длина DNS-имени
    assert not nt.valid_host("a" * 254)   # длиннее — отвергаем


# --- парсинг зависших маршрутов ------------------------------------------
def test_parse_stale_routes_filters_up_and_local():
    lines = [
        "0.0.0.0/0|12|happ-tun|Up|172.18.0.2",      # Up — не зависший
        "10.0.0.0/24|30|old-tun|Disconnected|10.0.0.1",  # зависший
        "127.0.0.0/8|1|loopback|Up|0.0.0.0",         # локальный — пропуск
        "192.168.1.0/24|33|dead|Missing|192.168.1.1",  # адаптер исчез
        "garbage line without pipes",
    ]
    res = nt._parse_stale_routes(lines)
    prefixes = {r["prefix"] for r in res}
    assert prefixes == {"10.0.0.0/24", "192.168.1.0/24"}
    assert all(r["status"].lower() != "up" for r in res)


# --- классификация файрвола ----------------------------------------------
def test_classify_firewall_vpn_like():
    rules = nt._classify_firewall([
        "Block All Outbound (Kill Switch)",
        "My custom rule",
        "WireGuard tunnel block",
        "",
    ])
    names = {r["name"]: r["vpn_like"] for r in rules}
    assert names["Block All Outbound (Kill Switch)"] is True
    assert names["WireGuard tunnel block"] is True
    assert names["My custom rule"] is False
    assert "" not in names  # пустые строки отброшены


# --- подозрительность записей hosts --------------------------------------
def test_hosts_entry_suspicious():
    assert nt._hosts_entry_suspicious("0.0.0.0", ["ads.example.com"]) is True
    assert nt._hosts_entry_suspicious("127.0.0.1", ["www.google.com"]) is True
    # dev-инструменты и localhost — безвредны
    assert nt._hosts_entry_suspicious("127.0.0.1", ["kubernetes.docker.internal"]) is False
    assert nt._hosts_entry_suspicious("192.168.0.5", ["host.docker.internal"]) is False
    assert nt._hosts_entry_suspicious("127.0.0.1", ["localhost"]) is False


# --- активный адаптер по эффективной метрике -----------------------------
def test_parse_default_adapter_picks_first():
    lines = ["happ-tun|0", "Беспроводная сеть|50"]
    assert nt._parse_default_adapter(lines) == "happ-tun"
    assert nt._parse_default_adapter([]) == ""


# --- разбор секций собранного состояния -----------------------------------
def test_split_sections():
    out = "===A===\nline1\nline2\n===B===\nx\n===END==="
    sec = nt._split_sections(out)
    assert sec["A"] == ["line1", "line2"]
    assert sec["B"] == ["x"]
    assert sec["END"] == []


# --- сравнение версий обновлений -----------------------------------------
def test_updates_norm_and_compare():
    assert updates._norm("v2.2") == (2, 2)
    assert updates._norm("2.2.1") == (2, 2, 1)
    assert updates._norm("2.10") > updates._norm("2.9")
    assert updates._norm("v3.0") > updates._norm("2.99")


def test_check_update_unconfigured():
    from netdoctor import settings
    old, old_cfg = updates.GITHUB_REPO, settings.get("github_repo")
    updates.GITHUB_REPO = ""
    settings._data["github_repo"] = ""
    try:
        assert updates.check_update()["status"] == "unconfigured"
    finally:
        updates.GITHUB_REPO = old
        settings._data["github_repo"] = old_cfg


def test_check_update_rejects_bad_repo():
    from netdoctor import settings
    old, old_cfg = updates.GITHUB_REPO, settings.get("github_repo")
    updates.GITHUB_REPO = ""
    try:
        for bad in ("owner/name/extra", "has space/name", "onlyowner"):
            settings._data["github_repo"] = bad
            res = updates.check_update()
            assert res["status"] == "error", bad
            assert "формат" in res["note"].lower()
    finally:
        updates.GITHUB_REPO = old
        settings._data["github_repo"] = old_cfg


def test_updates_repo_prefers_settings():
    from netdoctor import settings
    old, old_cfg = updates.GITHUB_REPO, settings.get("github_repo")
    updates.GITHUB_REPO = "fallback/repo"
    settings._data["github_repo"] = "owner/name"
    try:
        assert updates._repo() == "owner/name"
        settings._data["github_repo"] = ""
        assert updates._repo() == "fallback/repo"  # откат на константу
    finally:
        updates.GITHUB_REPO = old
        settings._data["github_repo"] = old_cfg


# --- экранирование имён для PowerShell ------------------------------------
def test_ps_quote():
    from netdoctor.core import ps_quote
    assert ps_quote("Ethernet") == "'Ethernet'"
    assert ps_quote("O'Brien Wi-Fi") == "'O''Brien Wi-Fi'"


# --- резолв системных утилит в абсолютный путь ----------------------------
def test_resolve_exe_absolute():
    from netdoctor import core
    r = core._resolve_exe("netsh")
    assert os.path.isabs(r) and r.lower().endswith("netsh.exe")
    # неизвестное имя возвращаем как есть (fallback для нестандартных систем)
    assert core._resolve_exe("no-such-exe-xyz") == "no-such-exe-xyz"


# --- типизация значений настроек ------------------------------------------
def test_settings_coerce_types():
    from netdoctor import settings
    assert settings._coerce("monitor_interval", "30") == 30       # str→int
    assert settings._coerce("monitor_interval", "abc") == \
        settings.DEFAULTS["monitor_interval"]                     # мусор→дефолт
    assert settings._coerce("autofix", "yes") == \
        settings.DEFAULTS["autofix"]                             # не bool→дефолт
    assert settings._coerce("autofix", True) is True
    assert settings._coerce("ping_host", 123) == \
        settings.DEFAULTS["ping_host"]                            # не str→дефолт
    assert settings._coerce("ping_host", "8.8.8.8") == "8.8.8.8"


# --- классификация DNS-утечки (через вердикт диалога невозможно без Qt) ----
def test_public_dns_table():
    assert "1.1.1.1" in nt.PUBLIC_DNS
    assert nt.PUBLIC_DNS["8.8.8.8"] == "Google"


# --- итоговая сводка диагностики ------------------------------------------
def test_summarize():
    from netdoctor.app import NetworkDoctor
    ok = [{"status": OK}, {"status": OK}]
    warn = [{"status": OK}, {"status": WARN}]
    bad = [{"status": WARN}, {"status": BAD}]
    assert NetworkDoctor._summarize(ok)[0] == OK
    assert NetworkDoctor._summarize(warn)[0] == WARN
    assert NetworkDoctor._summarize(bad)[0] == BAD


# --- бюджет времени в проверке онлайна ------------------------------------
def test_http_ok_respects_budget(monkeypatch):
    calls = {"n": 0}
    clock = {"t": 0.0}

    def fake_urlopen(req, timeout=8):
        calls["n"] += 1
        clock["t"] += 4          # каждая попытка «занимает» 4 c
        raise OSError("net down")

    monkeypatch.setattr(diag.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(diag.time, "monotonic", lambda: clock["t"])
    ok, _ = diag._http_ok(timeout=4, budget=8)
    assert ok is False
    assert calls["n"] == 2       # 3-я попытка отсечена бюджетом (8 ≥ 8)


def test_http_ok_no_budget_tries_all(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=8):
        calls["n"] += 1
        raise OSError("net down")

    monkeypatch.setattr(diag.urllib.request, "urlopen", fake_urlopen)
    ok, _ = diag._http_ok(timeout=1)   # budget=None → перебираем все URL
    assert ok is False
    assert calls["n"] == 3


# --- проверка hosts как карточки (использует чистую классификацию) ---------
def test_check_hosts_file_runs():
    card = diag.check_hosts_file()
    assert card["status"] in (OK, WARN, "info")
    assert card["title"] == "Файл hosts"
