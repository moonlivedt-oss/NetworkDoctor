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

# --- авто-проверка обновлений (троттлинг раз в сутки) ---------------------
def test_due_for_auto_check():
    assert updates.due_for_auto_check("", "2026-09-03") is True
    assert updates.due_for_auto_check("2026-09-02", "2026-09-03") is True
    assert updates.due_for_auto_check("2026-09-03", "2026-09-03") is False


# --- классификация системного прокси (HKCU + HKLM) ------------------------
def test_classify_wininet():
    assert diag._classify_wininet(0, "", "", "")["status"] == OK
    assert diag._classify_wininet(1, "proxy:8080", "", "")["status"] == WARN
    # прокси уровня машины виден, даже если у пользователя выключено
    r = diag._classify_wininet(0, "", "", "10.0.0.1:8080")
    assert r["status"] == WARN and "HKLM" in r["detail"]
    # автонастройка (PAC)
    assert diag._classify_wininet(0, "", "http://pac", "")["status"] == WARN


# --- движок рекомендаций после диагностики -------------------------------
def test_recommend_action_priorities():
    assert diag.recommend_action([{"title": "X", "status": OK}]) is None
    # нет даже прямого TCP → обновить IP
    assert diag.recommend_action(
        [{"title": "Прямое соединение (TCP)", "status": BAD}])["key"] == "ip"
    # вывод-подсказка «плохо» (застрявший прокси) → умная починка
    assert diag.recommend_action(
        [{"title": "⟹ Вывод", "status": BAD}])["key"] == "smart"
    # остатки VPN (kill-switch) → убрать остатки VPN
    assert diag.recommend_action(
        [{"title": "Файрвол: блок-правила (kill-switch)",
          "status": WARN}])["key"] == "vpn"
    # просто задан прокси → быстрая починка
    assert diag.recommend_action(
        [{"title": "Системный прокси Windows", "status": WARN}])["key"] == "quick"


def test_recommend_action_prefers_more_severe():
    # TCP мёртв важнее, чем предупреждение о прокси
    items = [{"title": "Системный прокси Windows", "status": WARN},
             {"title": "Прямое соединение (TCP)", "status": BAD}]
    assert diag.recommend_action(items)["key"] == "ip"


# --- DNS-бенчмарк: сборка запроса и разбор ответа -------------------------
def test_dns_encode_name():
    assert nt._encode_dns_name("example.com") == b"\x07example\x03com\x00"
    assert nt._encode_dns_name("a.b.c") == b"\x01a\x01b\x01c\x00"


def test_dns_build_query_header():
    q = nt._build_dns_query("example.com", 0x1234)
    assert q[:2] == b"\x12\x34"           # txid
    assert q[2:4] == b"\x01\x00"          # recursion desired
    assert q[4:6] == b"\x00\x01"          # QDCOUNT=1
    assert b"\x07example\x03com\x00" in q
    assert q.endswith(b"\x00\x01\x00\x01")  # QTYPE=A, QCLASS=IN


def test_dns_response_ok():
    import struct
    txid = 0xABCD
    good = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)   # ответ, rcode=0
    assert nt._dns_response_ok(good, txid) is True
    assert nt._dns_response_ok(
        struct.pack(">HHHHHH", 0x1111, 0x8180, 1, 1, 0, 0), txid) is False  # чужой id
    assert nt._dns_response_ok(
        struct.pack(">HHHHHH", txid, 0x8182, 1, 0, 0, 0), txid) is False  # SERVFAIL
    assert nt._dns_response_ok(b"\x00\x01", txid) is False    # слишком короткий


def test_benchmark_dns_sorts(monkeypatch):
    fake = {"1.1.1.1": 12.0, "8.8.8.8": 5.0, "9.9.9.9": -1,
            "208.67.222.222": 20.0, "77.88.8.8": -1}
    monkeypatch.setattr(
        nt, "dns_latency",
        lambda server, name="example.com", timeout=2.0: fake.get(server, -1))
    rows = nt.benchmark_dns()
    assert rows[0]["server"] == "8.8.8.8"       # самый быстрый — первым
    assert rows[1]["server"] == "1.1.1.1"
    assert all(r["ms"] < 0 for r in rows[-2:])  # недоступные — в конце


# --- текстовые представления диалогов (статические, без Qt-цикла) ---------
def test_dialog_as_text_helpers():
    from netdoctor.ui.dialogs import ConnectionsDialog, DnsInfoDialog
    rows = [{"name": "chrome", "pid": "12",
             "local": "1.2.3.4:5", "remote": "9.9.9.9:443"}]
    txt = ConnectionsDialog._as_text(rows)
    assert "chrome" in txt and "9.9.9.9:443" in txt
    dns = DnsInfoDialog._as_text([{"iface": "Wi-Fi", "servers": ["1.1.1.1"]}])
    assert "Wi-Fi" in dns and "1.1.1.1" in dns
