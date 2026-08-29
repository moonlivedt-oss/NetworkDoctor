# -*- coding: utf-8 -*-
"""Фоновые потоки (QThread), чтобы окно не зависало во время сетевых операций."""

from __future__ import annotations

import time

from PyQt6.QtCore import QThread, pyqtSignal

from .core import is_admin
from .diagnostics import run_core_diagnosis, run_remnant_diagnosis, quick_online
from .fixes import (
    fix_wininet_proxy, fix_winhttp_proxy, fix_env_proxy, fix_flush_dns,
    fix_ip_renew, fix_restart_dnscache, fix_stale_routes, fix_disable_wpad,
)
from .net_tools import get_exit_info


class DiagnoseWorker(QThread):
    """Диагностика в две фазы: сперва быстрое «ядро» (показываем сразу),
    затем медленные «остатки VPN» (файрвол/маршруты) — догружаются в фоне."""
    core_ready = pyqtSignal(list)
    remnants_ready = pyqtSignal(list)

    def run(self):
        try:
            self.core_ready.emit(run_core_diagnosis())
        except Exception:
            self.core_ready.emit([])
        try:
            self.remnants_ready.emit(run_remnant_diagnosis())
        except Exception:
            # даже при сбое медленной фазы шлём сигнал — иначе окно «зависнет»
            self.remnants_ready.emit([])


class FixWorker(QThread):
    log_line = pyqtSignal(str)
    finished_ok = pyqtSignal()

    def __init__(self, steps: list):
        super().__init__()
        self.steps = steps  # список функций fix_*(log)

    def run(self):
        for step in self.steps:
            step(self.log_line.emit)
        self.finished_ok.emit()


class TaskWorker(QThread):
    """Выполнить любую функцию в фоне и вернуть её результат."""
    done = pyqtSignal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:  # чтобы окно не падало
            self.done.emit(e)


class SmartFixWorker(QThread):
    """«Починить умно»: делает шаги по порядку и останавливается, как только
    интернет вернулся. Не завершает работающие приложения и не требует
    перезагрузки — только сброс настроек прокси и обновление IP."""
    log_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool)

    def run(self):
        log = self.log_line.emit
        if quick_online():
            log("  Интернет уже работает — чинить нечего.")
            self.finished_ok.emit(True)
            return

        log("  Шаг 1: сброс системного прокси, WPAD и DNS…")
        fix_wininet_proxy(log)
        fix_winhttp_proxy(log)
        fix_env_proxy(log)
        fix_disable_wpad(log)
        fix_flush_dns(log)
        if quick_online():
            log("  Интернет вернулся после сброса прокси.")
            self.finished_ok.emit(True)
            return

        admin = is_admin()

        # Шаг 2 (админ): убрать зависшие маршруты от мёртвых туннелей.
        if admin:
            log("  Шаг 2: чищу зависшие маршруты и службу DNS…")
            fix_stale_routes(log)
            fix_restart_dnscache(log)
            if quick_online():
                log("  Интернет вернулся после чистки маршрутов/DNS.")
                self.finished_ok.emit(True)
                return

        log(f"  Шаг {3 if admin else 2}: обновление IP-адреса…")
        fix_ip_renew(log)
        if quick_online():
            log("  Интернет вернулся после обновления IP.")
            self.finished_ok.emit(True)
            return

        log("  Автоматически починить не удалось.")
        self.finished_ok.emit(False)


class MonitorWorker(QThread):
    """Фоновый монитор: раз в interval секунд проверяет, жив ли интернет
    (лёгкий HTTPS-запрос через системные настройки — ловит и застрявший
    прокси), а внешний IP/страну выхода тянет заметно реже (exit_every), чтобы
    не бомбить внешний сервис запросами каждые 20 секунд круглосуточно.

    Эмитит dict {online, ip, loc}: ip/loc заполнены только в те циклы, когда
    реально запрашивался выходной узел (иначе пустые — приёмник их игнорирует).
    """
    status = pyqtSignal(dict)

    def __init__(self, interval: int = 20, exit_every: int = 180):
        super().__init__()
        self.interval = max(5, int(interval))
        self.exit_every = max(self.interval, int(exit_every))
        self._running = True

    def _due_for_exit(self, now: float, last_exit) -> bool:
        """Пора ли снова спрашивать внешний IP/страну (throttle).

        last_exit=None (ещё не спрашивали) → да, сразу при старте.
        """
        return last_exit is None or (now - last_exit) >= self.exit_every

    def run(self):
        last_exit = None
        while self._running:
            # короткий per-request timeout + бюджет в quick_online → при обрыве
            # цикл не висит по timeout на каждый из нескольких URL
            online = quick_online(timeout=4)
            ip = loc = ""
            now = time.monotonic()
            # выходной узел проверяем реже и только когда связь есть
            if online and self._due_for_exit(now, last_exit):
                ip, loc = get_exit_info(timeout=6)
                last_exit = now
            self.status.emit({"online": online, "ip": ip, "loc": loc})
            # спим короткими шагами, чтобы быстро останавливаться
            for _ in range(self.interval * 2):
                if not self._running:
                    return
                self.msleep(500)

    def stop(self):
        self._running = False
