# -*- coding: utf-8 -*-
"""Тесты MonitorWorker: клампинг интервала, троттлинг запросов выходного узла.

Сеть и Qt-цикл не задействованы: quick_online/get_exit_info замоканы, а run()
вызывается напрямую (синхронно) — слот, подключённый к сигналу status в том же
потоке, вызывается прямой связью, поэтому останавливает цикл после N эмиссий.
Часы (time.monotonic) подменяются на управляемые, чтобы детерминированно
проверить период проверки выходного узла.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from PyQt6.QtCore import QCoreApplication

from netdoctor import workers


@pytest.fixture(scope="module")
def qapp():
    # QCoreApplication нужен, чтобы прямые связи сигнал→слот доставлялись
    # синхронно (дисплей не требуется — это не GUI-приложение).
    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    yield app


def test_interval_and_exit_every_clamped(qapp):
    w = workers.MonitorWorker(interval=1, exit_every=2)
    assert w.interval == 5              # нижняя граница интервала
    assert w.exit_every == 5            # exit_every не может быть меньше interval

    w2 = workers.MonitorWorker(interval=30, exit_every=180)
    assert w2.interval == 30
    assert w2.exit_every == 180


def test_due_for_exit_math(qapp):
    w = workers.MonitorWorker(interval=10, exit_every=30)
    assert w._due_for_exit(0.0, None) is True     # первый раз — сразу
    assert w._due_for_exit(10.0, 0.0) is False    # прошло 10 < 30
    assert w._due_for_exit(30.0, 0.0) is True     # ровно 30 ≥ 30
    assert w._due_for_exit(45.0, 30.0) is False   # прошло 15 < 30


def test_run_throttles_exit_lookup(qapp, monkeypatch):
    calls = {"online": 0, "exit": 0}

    def fake_online(timeout=6):
        calls["online"] += 1
        return True

    def fake_exit(timeout=6):
        calls["exit"] += 1
        return ("1.2.3.4", "US")

    clock = {"t": 0.0}
    monkeypatch.setattr(workers, "quick_online", fake_online)
    monkeypatch.setattr(workers, "get_exit_info", fake_exit)
    monkeypatch.setattr(workers.time, "monotonic", lambda: clock["t"])

    w = workers.MonitorWorker(interval=10, exit_every=30)
    w.msleep = lambda ms=0: None        # не спать между циклами в тесте
    emitted = []

    def on_status(info):
        emitted.append(info)
        clock["t"] += w.interval        # промотать время на цикл вперёд
        if len(emitted) >= 4:
            w._running = False          # остановить после 4 циклов

    w.status.connect(on_status)
    w.run()  # синхронно: emit вызывает on_status прямой связью

    # liveness-проверка идёт каждый цикл
    assert calls["online"] == 4
    # выход спрашиваем на цикле 0 (t=0, last_exit=None) и на цикле 3
    # (t=30, 30-0 ≥ 30) — итого 2 раза за 4 цикла
    assert calls["exit"] == 2
    # ip/loc заполнены только там, где реально ходили за выходом
    assert [bool(e["ip"]) for e in emitted] == [True, False, False, True]
    assert all(e["online"] for e in emitted)


def test_run_skips_exit_when_offline(qapp, monkeypatch):
    exit_calls = {"n": 0}

    def fake_exit(timeout=6):
        exit_calls["n"] += 1
        return ("x", "US")

    monkeypatch.setattr(workers, "quick_online", lambda timeout=6: False)
    monkeypatch.setattr(workers, "get_exit_info", fake_exit)
    monkeypatch.setattr(workers.time, "monotonic", lambda: 0.0)

    w = workers.MonitorWorker(interval=10, exit_every=30)
    got = []

    def on_status(info):
        got.append(info)
        w._running = False              # хватит одного цикла

    w.status.connect(on_status)
    w.run()

    assert exit_calls["n"] == 0         # офлайн → внешний IP не дёргаем вовсе
    assert got and got[0]["online"] is False
    assert got[0]["ip"] == "" and got[0]["loc"] == ""


def test_stop_sets_flag(qapp):
    w = workers.MonitorWorker()
    assert w._running is True
    w.stop()
    assert w._running is False
