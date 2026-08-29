# -*- coding: utf-8 -*-
"""Инструменты: прокси-процессы, адаптеры, DNS, внешний IP и качество канала."""

from __future__ import annotations

import re
import time
import urllib.request

from .core import (
    PROXY_PORTS, PROXY_PROC_HINTS, VPN_ADAPTER_HINTS, run_cmd, ps_quote,
)
# hosts-логика вынесена в отдельный модуль; ре-экспортируем для обратной
# совместимости (на эти имена ссылаются fixes, diagnostics и тесты).
from .hosts import (  # noqa: F401
    _hosts_path, _hosts_entry_suspicious, read_hosts_entries,
    _HOSTS_BENIGN_SUFFIXES,
)


# ---------------------------------------------------------------------------
# Прокси-процессы, адаптеры, DNS
# ---------------------------------------------------------------------------

def _process_names() -> dict:
    """PID → имя процесса (через tasklist)."""
    _, out = run_cmd(["tasklist", "/fo", "csv", "/nh"])
    names = {}
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2:
            names[parts[1].strip('"')] = parts[0].strip('"')
    return names


def list_proxy_processes() -> list[dict]:
    """Найти процессы, похожие на прокси-клиенты: слушают прокси-порт
    на localhost ИЛИ называются как прокси-клиент."""
    _, out = run_cmd(["netstat", "-ano", "-p", "TCP"])
    listeners: dict[str, set] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" \
                and parts[3].upper() == "LISTENING":
            local, pid = parts[1], parts[4]
            if ":" in local:
                try:
                    port = int(local.rsplit(":", 1)[1])
                except ValueError:
                    continue
                listeners.setdefault(pid, set()).add(port)

    names = _process_names()
    result = []
    for pid, ports in listeners.items():
        name = names.get(pid, "?")
        proxy_ports = sorted(p for p in ports if p in PROXY_PORTS)
        name_hit = any(h in name.lower() for h in PROXY_PROC_HINTS)
        if proxy_ports or name_hit:
            result.append({"pid": pid, "name": name,
                           "ports": sorted(ports), "proxy_ports": proxy_ports,
                           "name_hit": name_hit})
    result.sort(key=lambda r: (not r["name_hit"], r["name"].lower()))
    return result


def kill_process(pid: str) -> tuple[bool, str]:
    """Принудительно завершить процесс по PID."""
    code, out = run_cmd(["taskkill", "/PID", str(pid), "/F"])
    ok = code == 0 or "success" in out.lower() or "успеш" in out.lower()
    return ok, out.strip()


def list_adapters() -> list[tuple[str, str]]:
    """Список сетевых адаптеров: [(имя, статус), …]."""
    ps = ("Get-NetAdapter | Sort-Object Status | "
          "ForEach-Object { $_.Name + '|' + $_.Status }")
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=25)
    adapters = []
    for line in out.splitlines():
        if "|" in line:
            name, _, status = line.partition("|")
            adapters.append((name.strip(), status.strip()))
    return adapters


# PS-фрагмент: активный адаптер по маршруту по умолчанию. Печатает строки
# «alias|effective_metric», отсортированные по эффективной метрике (сумма
# метрики маршрута и метрики интерфейса — именно так Windows выбирает путь).
# Заметно быстрее Get-NetIPConfiguration и учитывает активный туннель.
_DEFAULT_ADAPTER_PS = (
    "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
    "| ForEach-Object { $im=(Get-NetIPInterface -InterfaceIndex "
    "$_.InterfaceIndex -AddressFamily IPv4 "
    "-ErrorAction SilentlyContinue).InterfaceMetric; "
    "'{0}|{1}' -f $_.InterfaceAlias,([int]$_.RouteMetric+[int]$im) } "
    "| Sort-Object { [int]($_ -split '\\|')[1] }"
)


def _parse_default_adapter(lines) -> str:
    """Из строк «alias|metric» (уже отсортированных) взять первый alias."""
    for line in lines:
        alias = line.strip().split("|")[0].strip()
        if alias:
            return alias
    return ""


def default_adapter() -> str:
    """Имя адаптера, через который сейчас идёт интернет (маршрут по умолчанию)."""
    _, out = run_cmd(["powershell", "-NoProfile", "-Command",
                      _DEFAULT_ADAPTER_PS], timeout=25)
    return _parse_default_adapter(out.splitlines())


def restart_adapter(name: str) -> tuple[bool, str]:
    """Перезапустить адаптер (отключить/включить). Требует админа."""
    ps = f"Restart-NetAdapter -Name {ps_quote(name)} -Confirm:$false"
    code, out = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=45)
    ok = code == 0 and "denied" not in out.lower() and "отказ" not in out.lower()
    return ok, out.strip()


def set_dns(name: str, servers: tuple | None) -> tuple[bool, str]:
    """Задать DNS адаптеру. servers=None → вернуть автоматический (DHCP).
    Требует админа."""
    if servers is None:
        code, out = run_cmd(["netsh", "interface", "ipv4", "set", "dns",
                             f"name={name}", "dhcp"])
    else:
        code, out = run_cmd(["netsh", "interface", "ipv4", "set", "dns",
                             f"name={name}", "static", servers[0], "primary"])
        if len(servers) > 1:
            run_cmd(["netsh", "interface", "ipv4", "add", "dns",
                     f"name={name}", servers[1], "index=2"])
    run_cmd(["ipconfig", "/flushdns"])
    ok = code == 0 and "denied" not in out.lower() and "отказ" not in out.lower()
    return ok, out.strip()


# ---------------------------------------------------------------------------
# Внешний IP, страна, пинг
# ---------------------------------------------------------------------------

# Коды стран → русские названия (для сообщений о смене выходного узла).
COUNTRY_RU = {
    "JP": "Япония", "DE": "Германия", "US": "США", "GB": "Великобритания",
    "NL": "Нидерланды", "FR": "Франция", "FI": "Финляндия", "SE": "Швеция",
    "RU": "Россия", "UA": "Украина", "PL": "Польша", "TR": "Турция",
    "SG": "Сингапур", "HK": "Гонконг", "KR": "Корея", "CA": "Канада",
    "CH": "Швейцария", "AT": "Австрия", "KZ": "Казахстан", "LT": "Литва",
    "LV": "Латвия", "EE": "Эстония", "CZ": "Чехия", "IT": "Италия",
    "ES": "Испания", "AE": "ОАЭ", "IN": "Индия", "AM": "Армения",
    "GE": "Грузия", "RO": "Румыния", "BG": "Болгария", "MD": "Молдова",
    "BR": "Бразилия",
}


def country_name(code: str) -> str:
    """'JP' → 'Япония'; неизвестный код возвращаем как есть."""
    return COUNTRY_RU.get(code.upper(), code.upper()) if code else "?"


def valid_host(target: str) -> bool:
    """Разрешаем только имена хостов и IP — защита от подстановки в команду."""
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.\-:]*[A-Za-z0-9])?",
                             target or ""))


def get_exit_info(timeout: int = 6) -> tuple[str, str]:
    """Внешний IP и код страны выхода (ip, 'JP'). Через Cloudflare trace —
    он отдаёт и ip=, и loc= (код страны). Fallback: только IP через ipify."""
    try:
        req = urllib.request.Request("https://cloudflare.com/cdn-cgi/trace",
                                     headers={"User-Agent": "NetworkDoctor"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
        m_ip = re.search(r"ip=([\d.:a-fA-F]+)", body)
        m_loc = re.search(r"loc=([A-Za-z]{2})", body)
        ip = m_ip.group(1) if m_ip else ""
        loc = m_loc.group(1).upper() if m_loc else ""
        if ip:
            return ip, loc
    except Exception:
        pass
    try:
        req = urllib.request.Request("https://api.ipify.org",
                                     headers={"User-Agent": "NetworkDoctor"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace").strip(), ""
    except Exception:
        return "", ""


def download_speed(bytes_count: int = 10_000_000, timeout: int = 20) -> float:
    """Замерить скорость скачивания (Мбит/с) через Cloudflare speed-endpoint.

    Возвращает Мбит/с или -1 при ошибке. Учитывает системный прокси (как и
    браузер) — показывает реальную скорость канала.
    """
    url = f"https://speed.cloudflare.com/__down?bytes={bytes_count}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkDoctor"})
        t0 = time.time()
        total = 0
        with urllib.request.urlopen(req, timeout=timeout) as r:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
        dt = time.time() - t0
        if dt <= 0 or total <= 0:
            return -1
        return round(total * 8 / dt / 1_000_000, 1)  # Мбит/с
    except Exception:
        return -1


def ipv6_enabled(adapter: str) -> bool | None:
    """Включён ли IPv6 (ms_tcpip6) на адаптере. None — не удалось определить."""
    ps = (f"(Get-NetAdapterBinding -Name {ps_quote(adapter)} "
          f"-ComponentID ms_tcpip6 -ErrorAction SilentlyContinue).Enabled")
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=20)
    val = out.strip().splitlines()[0].strip().lower() if out.strip() else ""
    if val in ("true",):
        return True
    if val in ("false",):
        return False
    return None


def set_ipv6(adapter: str, enable: bool) -> tuple[bool, str]:
    """Включить/выключить IPv6 (ms_tcpip6) на адаптере. Требует админа."""
    verb = "Enable-NetAdapterBinding" if enable else "Disable-NetAdapterBinding"
    ps = f"{verb} -Name {ps_quote(adapter)} -ComponentID ms_tcpip6"
    code, out = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=30)
    ok = code == 0 and "denied" not in out.lower() and "отказ" not in out.lower()
    return ok, out.strip()


def apply_mtu(adapter: str, mtu: int) -> tuple[bool, str]:
    """Установить MTU (IPv4) на адаптере. Требует админа."""
    code, out = run_cmd(["netsh", "interface", "ipv4", "set", "subinterface",
                         adapter, f"mtu={mtu}", "store=persistent"])
    ok = code == 0 or "ok" in out.lower() or "успеш" in out.lower()
    return ok, out.strip()


# ---------------------------------------------------------------------------
# DNS-серверы и проверка утечки
# ---------------------------------------------------------------------------

# Известные публичные DNS-резолверы (для подсказки об утечке).
PUBLIC_DNS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "77.88.8.8": "Яндекс", "77.88.8.1": "Яндекс",
}


def list_dns_servers() -> list[dict]:
    """DNS-серверы по адаптерам (IPv4). Возвращает [{iface, servers:[...]}].

    Показываем только адаптеры со статусом Up и заданными серверами.
    """
    ps = (
        "Get-DnsClientServerAddress -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | "
        "ForEach-Object { $_.InterfaceAlias + '|' + "
        "($_.ServerAddresses -join ',') }"
    )
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=25)
    rows = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        iface, _, servers = line.partition("|")
        srv = [s.strip() for s in servers.split(",") if s.strip()]
        if iface.strip() and srv:
            rows.append({"iface": iface.strip(), "servers": srv})
    return rows


# ---------------------------------------------------------------------------
# Активные соединения
# ---------------------------------------------------------------------------

def list_connections(limit: int = 200) -> list[dict]:
    """Активные TCP-соединения (ESTABLISHED) с именем процесса.

    Возвращает [{proto, local, remote, state, pid, name}].
    """
    _, out = run_cmd(["netstat", "-ano", "-p", "TCP"])
    names = _process_names()
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" \
                and parts[3].upper() == "ESTABLISHED":
            local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
            # пропускаем локальные (loopback) соединения — интересны внешние
            rhost = remote.rsplit(":", 1)[0].strip("[]")
            if rhost.startswith("127.") or rhost == "::1":
                continue
            rows.append({"proto": "TCP", "local": local, "remote": remote,
                         "state": state, "pid": pid,
                         "name": names.get(pid, "?")})
            if len(rows) >= limit:
                break
    rows.sort(key=lambda r: r["name"].lower())
    return rows


# ---------------------------------------------------------------------------
# Детали адаптера
# ---------------------------------------------------------------------------

def adapter_details(adapter: str) -> dict:
    """Сводка по адаптеру: IPv4, шлюз, DNS, MAC, скорость линка, DHCP.

    Возвращает dict со строковыми значениями ('' если нет данных).
    """
    ps = (
        f"$n={ps_quote(adapter)};"
        "$cfg=Get-NetIPConfiguration -InterfaceAlias $n "
        "-ErrorAction SilentlyContinue;"
        "$a=Get-NetAdapter -Name $n -ErrorAction SilentlyContinue;"
        "$ip=($cfg.IPv4Address.IPAddress -join ', ');"
        "$gw=($cfg.IPv4DefaultGateway.NextHop -join ', ');"
        "$dns=($cfg.DNSServer | Where-Object {$_.AddressFamily -eq 2} | "
        "ForEach-Object {$_.ServerAddresses} ) -join ', ';"
        "$dhcp=(Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue).Dhcp;"
        "'IP|'+$ip; 'GW|'+$gw; 'DNS|'+$dns; 'MAC|'+$a.MacAddress; "
        "'LINK|'+$a.LinkSpeed; 'STATUS|'+$a.Status; 'DHCP|'+$dhcp"
    )
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=25)
    data = {"iface": adapter, "ip": "", "gw": "", "dns": "", "mac": "",
            "link": "", "status": "", "dhcp": ""}
    keymap = {"IP": "ip", "GW": "gw", "DNS": "dns", "MAC": "mac",
              "LINK": "link", "STATUS": "status", "DHCP": "dhcp"}
    for line in out.splitlines():
        key, _, val = line.partition("|")
        if key in keymap:
            data[keymap[key]] = val.strip()
    return data


# ---------------------------------------------------------------------------
# Подбор оптимального MTU (DF-пинг бинарным поиском)
# ---------------------------------------------------------------------------

def _ping_df(host: str, payload: int) -> bool:
    """Проходит ли пинг с флагом DF и полезной нагрузкой payload байт.

    False, если пакет требует фрагментации (payload+28 > MTU пути).
    """
    code, out = run_cmd(["ping", host, "-f", "-l", str(payload), "-n", "1",
                         "-w", "1500"], timeout=8)
    low = out.lower()
    if "needs to be fragmented" in low or "требуется фрагмент" in low \
            or "фрагментац" in low:
        return False
    # успех — есть ответ (TTL) и нет пометки о потере
    return ("ttl=" in low) and code == 0


def probe_optimal_mtu(host: str = "1.1.1.1") -> int:
    """Найти оптимальный MTU до host бинарным поиском DF-пинга.

    MTU = payload + 28 (20 IP + 8 ICMP). Диапазон payload 1200..1472
    (1472 соответствует стандартному MTU 1500). -1 при ошибке.
    """
    lo, hi = 1200, 1472
    if not _ping_df(host, lo):
        # даже маленький пакет не проходит — узнать нечего
        return -1
    best = lo
    while lo <= hi:
        mid = (lo + hi) // 2
        if _ping_df(host, mid):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best + 28


def ping_stats(host: str, count: int = 4) -> tuple[int, int]:
    """Пинг host `count` раз. Возвращает (доля_потерь_%, средняя_задержка_мс).
    средняя = -1, если ответов нет. Через Test-Connection (не зависит от языка)."""
    ps = (f"$r = Test-Connection -ComputerName {ps_quote(host)} -Count {count} "
          f"-ErrorAction SilentlyContinue; "
          f"$ok = @($r | Where-Object {{$_.StatusCode -eq 0}}); "
          f"$avg = if ($ok.Count) "
          f"{{[math]::Round(($ok | Measure-Object ResponseTime -Average)"
          f".Average)}} else {{-1}}; \"$($ok.Count) $avg\"")
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", ps],
                     timeout=10 + count * 3)
    try:
        ok_count, avg = out.strip().split()
        ok_count, avg = int(ok_count), int(avg)
    except Exception:
        return 100, -1
    loss = round((count - ok_count) / count * 100)
    return loss, avg


# ---------------------------------------------------------------------------
# Остатки VPN: зависшие маршруты, блок-правила файрвола, hosts, MTU
# ---------------------------------------------------------------------------

# PS-фрагмент: маршруты «prefix|ifindex|iface|status|nexthop».
# Статусы адаптеров берём одним запросом в хеш-таблицу (а не Get-NetAdapter на
# каждый маршрут) — иначе на десятках маршрутов это очень медленно.
_ROUTES_PS = (
    "$ad=@{}; Get-NetAdapter -ErrorAction SilentlyContinue | "
    "ForEach-Object { $ad[[string]$_.ifIndex]=$_.Status }; "
    "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
    "ForEach-Object { "
    "$k=[string]$_.InterfaceIndex; "
    "$st = if ($ad.ContainsKey($k)) { $ad[$k] } else { 'Missing' }; "
    "\"$($_.DestinationPrefix)|$($_.InterfaceIndex)|"
    "$($_.InterfaceAlias)|$st|$($_.NextHop)\" }"
)


def _parse_stale_routes(lines) -> list[dict]:
    """Из строк «prefix|ifindex|iface|status|nexthop» отобрать зависшие
    (адаптер не в статусе Up). Активные маршруты не включаем — их не трогаем."""
    routes = []
    for line in lines:
        parts = line.strip().split("|")
        if len(parts) < 5:
            continue
        prefix, ifindex, iface, status, nexthop = parts[:5]
        prefix = prefix.strip()
        if not prefix or prefix.startswith(("127.", "224.", "255.255.255.255")):
            continue
        if status.strip().lower() == "up":
            continue
        try:
            idx = int(ifindex)
        except ValueError:
            continue
        routes.append({"prefix": prefix, "ifindex": idx,
                       "iface": iface.strip(), "status": status.strip(),
                       "nexthop": nexthop.strip()})
    return routes


def list_stale_routes() -> list[dict]:
    """Маршруты на адаптерах, которые сейчас НЕ в статусе Up.

    Такие маршруты оставляет крашнутый tun/tap-адаптер: трафик может уходить
    через мёртвый шлюз. Возвращает [{prefix, ifindex, iface, status, nexthop}].
    """
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", _ROUTES_PS],
                     timeout=25)
    return _parse_stale_routes(out.splitlines())


# PS-фрагмент: имена включённых исходящих блок-правил брандмауэра.
# -PolicyStore ActiveStore заметно быстрее хранилища по умолчанию.
_FIREWALL_PS = (
    "Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True "
    "-Direction Outbound -Action Block -ErrorAction SilentlyContinue | "
    "ForEach-Object { $_.DisplayName }"
)


def _classify_firewall(lines) -> list[dict]:
    """Из имён блок-правил собрать [{name, vpn_like}]."""
    hints = tuple(VPN_ADAPTER_HINTS) + ("kill", "block all", "vpn", "lockdown")
    rules = []
    for line in lines:
        name = line.strip()
        if not name:
            continue
        low = name.lower()
        rules.append({"name": name,
                      "vpn_like": any(h in low for h in hints)})
    return rules


def list_firewall_blocks() -> list[dict]:
    """Включённые исходящие блокирующие правила брандмауэра.

    VPN с «kill switch» оставляет такие правила после падения — интернет
    заблокирован целиком. Возвращает [{name, vpn_like}]; vpn_like=True, если
    имя правила похоже на VPN/kill-switch.
    """
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", _FIREWALL_PS],
                     timeout=25)
    return _classify_firewall(out.splitlines())


# ---------------------------------------------------------------------------
# Сбор системного состояния пачками (меньше запусков PowerShell)
# ---------------------------------------------------------------------------
#
# Выводы разбиты маркерами ===SECTION===. И netsh, и командлеты пишут в
# OEM-кодировку консоли, поэтому блок корректно декодируется как один
# (см. run_cmd). «Быстрое» состояние собираем отдельно от «остатков VPN»
# (маршруты + файрвол медленные), чтобы окно показывало основное сразу.

# Быстрое: WinHTTP-прокси, адаптеры, активный адаптер и его MTU.
# Активный адаптер считаем ОДИН раз в $def и переиспользуем для MTU.
_FAST_STATE_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$def=@(" + _DEFAULT_ADAPTER_PS + ");"
    "'===WINHTTP===';"
    "netsh winhttp show proxy;"
    "'===ADAPTERS===';"
    "Get-NetAdapter | ForEach-Object "
    "{ $_.Name + \"`t\" + $_.InterfaceDescription + \"`t\" + $_.Status };"
    "'===DEFAULT===';"
    "$def;"
    "'===MTU===';"
    "$da=if ($def.Count) { ($def[0] -split '\\|')[0] } else { '' }; "
    "if ($da) { (Get-NetIPInterface -InterfaceAlias $da "
    "-AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu }"
)

# Остатки VPN: маршруты + блок-правила файрвола (медленные командлеты).
_REMNANT_STATE_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "'===ROUTES===';"
    + _ROUTES_PS + ";"
    "'===FIREWALL===';"
    + _FIREWALL_PS
)


def _split_sections(out: str) -> dict:
    """Разобрать вывод с маркерами ===SECTION=== на {секция: [строки]}."""
    sections: dict[str, list[str]] = {}
    cur = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("===") and s.endswith("==="):
            cur = s.strip("=").strip()
            sections[cur] = []
            continue
        if cur is not None:
            sections[cur].append(line)
    return sections


def collect_fast_state() -> dict:
    """Быстрое системное состояние одним запуском PowerShell.

    Возвращает {winhttp:[str], adapters:[(name,desc,status)], default:str,
    mtu:int}.
    """
    _, out = run_cmd(["powershell", "-NoProfile", "-Command", _FAST_STATE_PS],
                     timeout=30)
    sec = _split_sections(out)

    adapters = []
    for line in sec.get("ADAPTERS", []):
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 3:
                adapters.append((parts[0].strip(), parts[1].strip(),
                                 parts[-1].strip()))

    default = _parse_default_adapter(sec.get("DEFAULT", []))
    mtu = -1
    for x in sec.get("MTU", []):
        try:
            mtu = int(x.strip())
            break
        except ValueError:
            continue

    return {"winhttp": sec.get("WINHTTP", []), "adapters": adapters,
            "default": default, "mtu": mtu}


def collect_remnant_state() -> dict:
    """Состояние «остатков VPN» одним запуском PowerShell.

    Возвращает {stale_routes:[dict], firewall:[dict]}.
    """
    _, out = run_cmd(["powershell", "-NoProfile", "-Command",
                      _REMNANT_STATE_PS], timeout=45)
    sec = _split_sections(out)
    return {"stale_routes": _parse_stale_routes(sec.get("ROUTES", [])),
            "firewall": _classify_firewall(sec.get("FIREWALL", []))}
