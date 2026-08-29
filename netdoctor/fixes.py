# -*- coding: utf-8 -*-
"""Починка: сброс системного прокси/WinHTTP/переменных окружения, DNS, IP,
и глубокий сброс Winsock/TCP-стека."""

from __future__ import annotations

import ctypes
import datetime
import os
import winreg

from .core import INET_SETTINGS, ENV_KEY, PROXY_ENV_NAMES, run_cmd, ps_quote
from .logs import LOG_DIR
from .net_tools import default_adapter, list_stale_routes
from .hosts import _hosts_path, _hosts_entry_suspicious


def _refresh_wininet() -> None:
    """Сообщить Windows, что настройки прокси изменились (без перезагрузки)."""
    try:
        internet = ctypes.windll.wininet
        internet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        internet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:
        pass


def fix_wininet_proxy(log) -> None:
    """Выключить и очистить системный прокси Windows (WinINET) в реестре."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_SETTINGS, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            for name in ("ProxyServer", "AutoConfigURL"):
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
        _refresh_wininet()
        log("  ✓ Системный прокси Windows выключён и очищен.")
    except Exception as e:
        log(f"  ✗ Не удалось очистить системный прокси: {e}")


def fix_winhttp_proxy(log) -> None:
    """Сбросить WinHTTP-прокси (нужны права администратора)."""
    code, out = run_cmd(["netsh", "winhttp", "reset", "proxy"])
    if code == 0:
        log("  ✓ WinHTTP-прокси сброшен (прямой доступ).")
    else:
        log(f"  ✗ WinHTTP reset: {out.strip() or 'ошибка (нужен админ?)'}")


def fix_env_proxy(log) -> None:
    """Удалить переменные окружения прокси (процесс + постоянные HKCU)."""
    removed = []
    for name in PROXY_ENV_NAMES:
        if name in os.environ:
            del os.environ[name]
            removed.append(name)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ENV_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            for name in PROXY_ENV_NAMES:
                try:
                    winreg.DeleteValue(k, name)
                    if name not in removed:
                        removed.append(name)
                except FileNotFoundError:
                    pass
        # Разослать уведомление об изменении окружения.
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF, 0x1A, 0, "Environment", 0x0002, 5000, None)
    except Exception:
        pass
    if removed:
        log(f"  ✓ Удалены переменные прокси: {', '.join(sorted(set(removed)))}.")
    else:
        log("  ✓ Переменных прокси не было — нечего чистить.")


def fix_flush_dns(log) -> None:
    """Очистить кеш DNS."""
    code, out = run_cmd(["ipconfig", "/flushdns"])
    if code == 0:
        log("  ✓ Кеш DNS очищен.")
    else:
        log(f"  ✗ flushdns: {out.strip()}")


def fix_ip_renew(log) -> None:
    """Освободить и заново получить IP-адрес."""
    log("  … release/renew IP (это может занять несколько секунд)…")
    run_cmd(["ipconfig", "/release"], timeout=40)
    code, out = run_cmd(["ipconfig", "/renew"], timeout=60)
    if code == 0:
        log("  ✓ IP-адрес обновлён.")
    else:
        log(f"  ✗ renew: {out.strip()}")


def fix_winsock(log) -> None:
    """Сбросить каталог Winsock (требует перезагрузки)."""
    code, out = run_cmd(["netsh", "winsock", "reset"])
    if code == 0:
        log("  ✓ Winsock сброшен (подействует после перезагрузки).")
    else:
        log(f"  ✗ winsock reset: {out.strip() or 'нужен админ?'}")


def fix_tcpip(log) -> None:
    """Сбросить стек TCP/IP (требует перезагрузки)."""
    code, out = run_cmd(["netsh", "int", "ip", "reset"])
    # netsh int ip reset часто возвращает ненулевой код, но работает.
    if "ok" in out.lower() or "успеш" in out.lower() or code == 0:
        log("  ✓ Стек TCP/IP сброшен (подействует после перезагрузки).")
    else:
        log(f"  ~ TCP/IP reset выполнен: {out.strip()[:200]}")


# ---------------------------------------------------------------------------
# Остатки VPN: файрвол (kill-switch), зависшие маршруты, MTU
# ---------------------------------------------------------------------------

def fix_firewall_reset(log) -> None:
    """Сбросить брандмауэр Windows к настройкам по умолчанию.

    Убирает застрявшие блокирующие правила, которые VPN с «kill switch»
    оставляет после падения (интернет заблокирован целиком). Требует админа.
    ВНИМАНИЕ: сбрасывает и пользовательские правила брандмауэра.
    """
    code, out = run_cmd(["netsh", "advfirewall", "reset"])
    if code == 0 or "ok" in out.lower() or "успеш" in out.lower():
        log("  ✓ Брандмауэр Windows сброшен к значениям по умолчанию "
            "(остатки kill-switch убраны).")
    else:
        log(f"  ✗ Сброс брандмауэра: {out.strip() or 'нужен админ?'}")


def fix_stale_routes(log) -> None:
    """Удалить зависшие маршруты, оставшиеся от отключённых туннелей.

    Крашнутый tun/tap-адаптер оставляет маршруты через несуществующий шлюз —
    трафик уходит «в никуда». Удаляем только маршруты на адаптерах, которые
    сейчас НЕ в статусе Up (безопасно: активный маршрут не трогаем). Требует
    админа для удаления.
    """
    stale = list_stale_routes()
    if not stale:
        log("  ✓ Зависших маршрутов не найдено.")
        return
    removed = 0
    for r in stale:
        ps = (f"Remove-NetRoute -DestinationPrefix {ps_quote(r['prefix'])} "
              f"-InterfaceIndex {int(r['ifindex'])} -Confirm:$false "
              f"-ErrorAction SilentlyContinue")
        code, out = run_cmd(["powershell", "-NoProfile", "-Command", ps])
        if code == 0 and "denied" not in out.lower() and "отказ" not in out.lower():
            removed += 1
            log(f"  ✓ Удалён маршрут {r['prefix']} через «{r['iface']}» "
                f"(адаптер отключён).")
        else:
            log(f"  ✗ Не удалось удалить {r['prefix']} «{r['iface']}»: "
                f"{out.strip()[:120] or 'нужен админ?'}")
    if removed:
        run_cmd(["ipconfig", "/flushdns"])


def fix_mtu_reset(log) -> None:
    """Вернуть MTU активного адаптера к 1500.

    Туннели часто занижают MTU (например до 1280/1400); после их отключения
    заниженный MTU остаётся и часть сайтов «висит» или грузится наполовину.
    Требует админа.
    """
    name = default_adapter()
    if not name:
        log("  ✗ Не удалось определить активный адаптер для MTU.")
        return
    code, out = run_cmd(["netsh", "interface", "ipv4", "set", "subinterface",
                         name, "mtu=1500", "store=persistent"])
    if code == 0 or "ok" in out.lower() or "успеш" in out.lower():
        log(f"  ✓ MTU адаптера «{name}» возвращён к 1500.")
    else:
        log(f"  ✗ Установка MTU: {out.strip() or 'нужен админ?'}")


def fix_flush_arp(log) -> None:
    """Очистить ARP- и destination-кеш (залипшие соседи после смены сети). Админ."""
    code1, _ = run_cmd(["netsh", "interface", "ip", "delete", "arpcache"])
    run_cmd(["netsh", "interface", "ip", "delete", "destinationcache"])
    # Второй способ (не зависит от прав так жёстко) — на всякий случай.
    run_cmd(["arp", "-d", "*"])
    if code1 == 0:
        log("  ✓ ARP- и destination-кеш очищены.")
    else:
        log("  ~ ARP-кеш очищен частично (для полного нужен админ).")


def fix_clean_hosts(log) -> None:
    """Убрать из файла hosts ТОЛЬКО подозрительные записи (с бэкапом). Админ.

    Подозрительные — реальные домены, уведённые на loopback/0.0.0.0 (блокировка).
    Комментарии и безвредные записи (Docker и т.п.) сохраняются.
    """
    path = _hosts_path()
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        log(f"  ✗ Не удалось прочитать hosts: {e}")
        return

    kept, removed = [], []
    for raw in lines:
        line = raw.strip().lstrip("﻿").strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2 and _hosts_entry_suspicious(parts[0], parts[1:]):
                removed.append(line)
                continue
        kept.append(raw)

    if not removed:
        log("  ✓ Подозрительных записей в hosts нет — чистить нечего.")
        return

    # бэкап и запись
    d = _backup_dir()
    if d is not None:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            (d / f"hosts_{stamp}.txt").write_text("".join(lines),
                                                  encoding="utf-8")
            log(f"  ✓ Бэкап hosts сохранён в {d}")
        except Exception:
            pass
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
        run_cmd(["ipconfig", "/flushdns"])
        log(f"  ✓ Убрано подозрительных записей: {len(removed)}.")
        for r in removed[:5]:
            log(f"    − {r}")
    except Exception as e:
        log(f"  ✗ Не удалось записать hosts (нужен админ?): {e}")


def fix_disable_wpad(log) -> None:
    """Отключить авто-определение прокси (WPAD) и PAC в системных настройках.

    WPAD/PAC — частая причина «интернет сломался»: система пытается найти
    прокси по сети и висит. Чистим AutoConfigURL и снимаем биты авто-детекта /
    авто-конфига в DefaultConnectionSettings (WinINET).
    """
    # 1. Убрать PAC-URL (AutoConfigURL) и авто-детект-флаг явно.
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_SETTINGS, 0,
                            winreg.KEY_SET_VALUE) as k:
            for name in ("AutoConfigURL",):
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
    except Exception as e:
        log(f"  ~ Не удалось очистить AutoConfigURL: {e}")

    # 2. Снять биты PAC(0x04)/WPAD(0x08) в DefaultConnectionSettings.
    conn_key = INET_SETTINGS + r"\Connections"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, conn_key, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
            try:
                blob, _ = winreg.QueryValueEx(k, "DefaultConnectionSettings")
                blob = bytearray(blob)
            except FileNotFoundError:
                blob = None
            if blob and len(blob) >= 12:
                blob[8] = blob[8] & ~0x0C  # снять PAC и WPAD
                # инкремент счётчика версии (offset 4, LE)
                counter = int.from_bytes(blob[4:8], "little") + 1
                blob[4:8] = counter.to_bytes(4, "little")
                winreg.SetValueEx(k, "DefaultConnectionSettings", 0,
                                  winreg.REG_BINARY, bytes(blob))
                log("  ✓ Авто-определение прокси (WPAD) и PAC отключены.")
            else:
                log("  ~ Настройки подключения не найдены — WPAD, вероятно, "
                    "и так не задан.")
    except Exception as e:
        log(f"  ~ Не удалось изменить настройки WPAD: {e}")
    _refresh_wininet()


def fix_restart_dnscache(log) -> None:
    """Перезапустить службу DNS-клиента (когда flushdns не помогает). Админ."""
    ps = "Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue"
    code, out = run_cmd(["powershell", "-NoProfile", "-Command", ps])
    if code == 0 and "denied" not in out.lower() and "отказ" not in out.lower():
        log("  ✓ Служба DNS-клиента перезапущена.")
    else:
        # dnscache не всегда перезапускается на лету — не критично.
        log("  ~ Перезапуск службы DNS не удался (обычно не критично); "
            "кеш всё равно очищен.")
    run_cmd(["ipconfig", "/flushdns"])


def _backup_dir():
    """Папка для бэкапов сетевых настроек (внутри logs). None при ошибке."""
    try:
        d = LOG_DIR / "backups"
        d.mkdir(parents=True, exist_ok=True)
        return d
    except Exception:
        return None


def fix_firewall_backup(log) -> None:
    """Сохранить текущие правила брандмауэра перед сбросом (откат возможен).

    Экспортирует в logs/backups/firewall_<время>.wfw. Восстановить потом:
    netsh advfirewall import "<файл>". Требует админа для export.
    """
    d = _backup_dir()
    if d is None:
        log("  ~ Не удалось подготовить папку бэкапа — продолжаю без него.")
        return
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = d / f"firewall_{stamp}.wfw"
    code, out = run_cmd(["netsh", "advfirewall", "export", str(path)])
    if code == 0 or "ok" in out.lower() or "успеш" in out.lower():
        log(f"  ✓ Бэкап правил брандмауэра: {path}")
        log("    (откат: netsh advfirewall import \"путь\")")
    else:
        log(f"  ~ Бэкап брандмауэра не удался: {out.strip()[:120] or 'ошибка'} "
            "— продолжаю.")


def backup_network_state(log) -> None:
    """Сохранить снимок сетевых настроек перед глубоким сбросом (для справки).

    Пишет ipconfig /all, таблицу маршрутов и правила брандмауэра в один текстовый
    файл logs/backups/network_<время>.txt. Не критично при ошибке.
    """
    d = _backup_dir()
    if d is None:
        log("  ~ Не удалось подготовить папку бэкапа — продолжаю без него.")
        return
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = d / f"network_{stamp}.txt"
    parts = []
    for title, cmd in (("=== ipconfig /all ===", ["ipconfig", "/all"]),
                       ("=== route print ===", ["route", "print"]),
                       ("=== netsh int ip show config ===",
                        ["netsh", "int", "ip", "show", "config"])):
        _, out = run_cmd(cmd, timeout=30)
        parts.append(f"{title}\n{out}\n")
    try:
        path.write_text("\n".join(parts), encoding="utf-8")
        log(f"  ✓ Снимок сетевых настроек сохранён: {path}")
    except Exception as e:
        log(f"  ~ Снимок сохранить не удалось: {e} — продолжаю.")
    # заодно экспорт правил брандмауэра рядом
    fix_firewall_backup(log)


def create_restore_point(log) -> None:
    """Создать точку восстановления перед глубокими изменениями. Админ.

    Работает, только если в системе включено «Восстановление системы».
    Ошибку не считаем фатальной — просто предупреждаем.
    """
    ps = ("Checkpoint-Computer -Description 'NetworkDoctor' "
          "-RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop")
    code, out = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=90)
    if code == 0:
        log("  ✓ Точка восстановления создана.")
    else:
        log("  ~ Точку восстановления создать не удалось "
            "(возможно, «Восстановление системы» выключено) — продолжаю.")
