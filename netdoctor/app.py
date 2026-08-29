# -*- coding: utf-8 -*-
"""Главное окно NetworkDoctor и точка входа main()."""

from __future__ import annotations

import ctypes
import datetime
import os
import sys
from pathlib import Path

from PyQt6.QtCore import (
    Qt, QSize, QTimer, QPropertyAnimation, QEasingCurve,
)
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QGraphicsOpacityEffect, QHBoxLayout,
    QInputDialog, QLabel, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from .core import OK, WARN, BAD, is_admin, relaunch_as_admin, relaunch_self
from . import settings
from .updates import check_update
from .logs import (
    setup_logging, install_excepthook, record_state, build_report,
    LOG_DIR, logger,
)
from .net.fixes import (
    fix_wininet_proxy, fix_winhttp_proxy, fix_env_proxy, fix_flush_dns,
    fix_ip_renew, fix_winsock, fix_tcpip,
    fix_firewall_reset, fix_stale_routes, fix_mtu_reset, fix_restart_dnscache,
    create_restore_point, fix_firewall_backup, backup_network_state,
    fix_flush_arp, fix_clean_hosts, fix_disable_wpad,
)
from .net.tools import (
    list_proxy_processes, list_adapters, default_adapter, restart_adapter,
    set_dns, get_exit_info, ping_stats, country_name,
    download_speed, ipv6_enabled, set_ipv6,
    list_dns_servers, list_connections, adapter_details, probe_optimal_mtu,
    apply_mtu, valid_host,
)
from .ui.theme import (
    make_app_icon, hline, Spinner, STYLE, CLR_BUSY,
    C_MUTED, C_FAINT, CLR_OK, CLR_WARN, CLR_BAD, _rgba,
)
from .workers import (
    DiagnoseWorker, FixWorker, TaskWorker, SmartFixWorker, MonitorWorker,
)
from .ui.dialogs import (
    ResultCard, ProxyProcessDialog, DnsDialog, HistoryDialog,
    AdapterDetailsDialog, DnsInfoDialog, ConnectionsDialog, SettingsDialog,
)
from .autostart import (
    is_autostart_enabled, enable_autostart, disable_autostart,
)


class NetworkDoctor(QMainWindow):
    def __init__(self, start_hidden: bool = False):
        super().__init__()
        self.setWindowTitle("NetworkDoctor — сетевой доктор")
        self.resize(660, 860)
        self.setMinimumSize(560, 720)
        self.setStyleSheet(STYLE)
        self._worker = None
        self._tworker = None
        self._smart = None
        self._mon = None
        self._tray = None
        self._threads = []  # живые QThread — держим ссылки, иначе Qt уронит
        #                     процесс, если объект соберётся во время работы
        self._last_online = None
        self._last_loc = None
        self._last_ip = None
        self._last_items = None  # последняя диагностика — для экспорта отчёта
        self._auto_done = False
        self._diag_busy = False        # идёт ли сейчас диагностика (2 фазы)
        self._force_quit = False       # настоящий выход (из трея)
        self._tray_hint_shown = False  # показали ли подсказку про трей
        self._start_hidden = start_hidden

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        # Шапка: логотип + заголовок + автозапуск + мониторинг
        head = QHBoxLayout()
        head.setSpacing(8)
        logo = QLabel()
        logo.setPixmap(make_app_icon().pixmap(QSize(34, 34)))
        head.addWidget(logo, 0, Qt.AlignmentFlag.AlignVCenter)
        title = QLabel("NetworkDoctor")
        title.setObjectName("title")
        head.addWidget(title, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addStretch()

        self.btn_autostart = QPushButton("Автозапуск")
        self.btn_autostart.setObjectName("toggle")
        self.btn_autostart.setCheckable(True)
        self.btn_autostart.setToolTip("Запускать NetworkDoctor вместе с Windows "
                                      "свёрнутым в трей, чтобы мониторинг был "
                                      "всегда наготове.")
        self.btn_autostart.setChecked(is_autostart_enabled())
        self.btn_autostart.toggled.connect(self.on_toggle_autostart)
        head.addWidget(self.btn_autostart, 0, Qt.AlignmentFlag.AlignVCenter)

        self.btn_monitor = QPushButton("Мониторинг: выкл")
        self.btn_monitor.setObjectName("toggle")
        self.btn_monitor.setCheckable(True)
        self.btn_monitor.setToolTip("Тихо следит за интернетом и выходным "
                                    "узлом; уведомляет при обрыве или смене "
                                    "страны выхода.")
        self.btn_monitor.toggled.connect(self.on_toggle_monitor)
        head.addWidget(self.btn_monitor, 0, Qt.AlignmentFlag.AlignVCenter)

        self._autofix_enabled = bool(settings.get("autofix"))
        self.btn_autofix = QPushButton(
            "Авто-починка: вкл" if self._autofix_enabled else "Авто-починка: выкл")
        self.btn_autofix.setObjectName("toggle")
        self.btn_autofix.setCheckable(True)
        self.btn_autofix.setChecked(self._autofix_enabled)
        self.btn_autofix.setToolTip(
            "Если при мониторинге пропал интернет — автоматически запускать "
            "«Починить умно». ВНИМАНИЕ: сбрасывает системный прокси, поэтому "
            "может отключить активный прокси-клиент. Включай, если прокси не "
            "используешь.")
        self.btn_autofix.toggled.connect(self.on_toggle_autofix)
        head.addWidget(self.btn_autofix, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(head)

        sub = QLabel("Чинит интернет, когда застрял прокси или намусорили "
                     "VPN-туннели.")
        sub.setObjectName("subtitle")
        sub.setWordWrap(True)
        root.addWidget(sub)

        # Статус прав администратора
        if is_admin():
            adm = QLabel("Запущено с правами администратора — доступны все "
                         "функции.")
            adm.setObjectName("adminOk")
            adm.setWordWrap(True)
            root.addWidget(adm)
        else:
            adm_row = QHBoxLayout()
            adm_row.setSpacing(8)
            adm = QLabel("Без прав администратора. Диагностика и сброс прокси "
                         "работают; глубокий сброс и чистка остатков VPN — нет.")
            adm.setObjectName("adminBad")
            adm.setWordWrap(True)
            adm_row.addWidget(adm, 1)
            self.btn_uac = QPushButton("Перезапустить с правами")
            self.btn_uac.setObjectName("primary")
            self.btn_uac.setToolTip("Перезапустить NetworkDoctor от имени "
                                    "администратора (запросит UAC).")
            self.btn_uac.clicked.connect(self.on_relaunch_admin)
            adm_row.addWidget(self.btn_uac, 0, Qt.AlignmentFlag.AlignVCenter)
            root.addLayout(adm_row)

        # Сводный индикатор состояния (плашка здоровья) со спиннером
        self.health_frame = QFrame()
        self.health_frame.setObjectName("health")
        hl = QHBoxLayout(self.health_frame)
        hl.setContentsMargins(16, 12, 16, 12)
        hl.setSpacing(12)
        self.health_dot = QLabel()
        self.health_dot.setFixedSize(12, 12)
        hl.addWidget(self.health_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        self.health_spin = Spinner(20)
        hl.addWidget(self.health_spin, 0, Qt.AlignmentFlag.AlignVCenter)
        self.health_label = QLabel()
        self.health_label.setWordWrap(True)
        hl.addWidget(self.health_label, 1)
        root.addWidget(self.health_frame)
        self.set_health("idle", "Проверяю состояние сети…")

        # Основные действия: проверить + починить умно
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.btn_diag = QPushButton("Проверить сеть")
        self.btn_diag.clicked.connect(self.on_diagnose)
        self.btn_smart = QPushButton("Починить умно")
        self.btn_smart.setObjectName("primary")
        self.btn_smart.setToolTip("Сама выполнит нужные шаги и остановится, "
                                  "как только интернет вернётся.")
        self.btn_smart.clicked.connect(self.on_smart_fix)
        actions.addWidget(self.btn_diag, 1)
        actions.addWidget(self.btn_smart, 1)
        root.addLayout(actions)

        # Область результатов (прокручиваемая)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.results_host = QWidget()
        self.results_lay = QVBoxLayout(self.results_host)
        self.results_lay.setContentsMargins(0, 0, 0, 0)
        self.results_lay.setSpacing(8)
        self.results_lay.addStretch()
        self.scroll.setWidget(self.results_host)
        root.addWidget(self.scroll, 1)

        self._placeholder("Нажми «Проверить сеть», чтобы увидеть состояние.")

        # Кнопки починки
        fixes = QHBoxLayout()
        fixes.setSpacing(8)
        self.btn_quick = QPushButton("Быстрая починка прокси")
        self.btn_quick.setToolTip("Сброс системного прокси + WinHTTP + "
                                  "переменных окружения + DNS. Без перезагрузки.")
        self.btn_quick.clicked.connect(self.on_quick_fix)
        self.btn_ip = QPushButton("Обновить IP")
        self.btn_ip.setToolTip("ipconfig release + renew.")
        self.btn_ip.clicked.connect(self.on_ip_fix)
        fixes.addWidget(self.btn_quick, 2)
        fixes.addWidget(self.btn_ip, 1)
        root.addLayout(fixes)

        self.btn_vpn_remnants = QPushButton("Убрать остатки VPN "
                                            "(файрвол / маршруты / MTU)")
        self.btn_vpn_remnants.setToolTip(
            "Снимает застрявшую блокировку брандмауэра (kill-switch), удаляет "
            "зависшие маршруты мёртвых туннелей и возвращает MTU к 1500. "
            "Без перезагрузки. Требует прав администратора.")
        self.btn_vpn_remnants.clicked.connect(self.on_fix_vpn_remnants)
        root.addWidget(self.btn_vpn_remnants)

        self.btn_deep = QPushButton("Глубокий сброс сети (нужна перезагрузка)")
        self.btn_deep.setObjectName("danger")
        self.btn_deep.setToolTip("netsh winsock reset + netsh int ip reset. "
                                 "Полностью пересобирает сетевой стек.")
        self.btn_deep.clicked.connect(self.on_deep_fix)
        root.addWidget(self.btn_deep)

        # Раздел «Инструменты»
        root.addWidget(hline())
        tools_lbl = QLabel("ИНСТРУМЕНТЫ")
        tools_lbl.setObjectName("section")
        root.addWidget(tools_lbl)

        tools_row1 = QHBoxLayout()
        tools_row1.setSpacing(8)
        self.btn_procs = QPushButton("Зависшие прокси-процессы")
        self.btn_procs.setToolTip("Показать процессы на прокси-портах и "
                                  "завершить лишние.")
        self.btn_procs.clicked.connect(self.on_proxy_procs)
        self.btn_adapter = QPushButton("Перезапустить адаптер")
        self.btn_adapter.setToolTip("Отключить/включить сетевой адаптер "
                                    "(без перезагрузки).")
        self.btn_adapter.clicked.connect(self.on_restart_adapter)
        tools_row1.addWidget(self.btn_procs)
        tools_row1.addWidget(self.btn_adapter)
        root.addLayout(tools_row1)

        tools_row2 = QHBoxLayout()
        tools_row2.setSpacing(8)
        self.btn_dns = QPushButton("Переключить DNS")
        self.btn_dns.setToolTip("Поставить 1.1.1.1 / 8.8.8.8 или вернуть авто.")
        self.btn_dns.clicked.connect(self.on_dns)
        self.btn_ipinfo = QPushButton("Мой IP и качество канала")
        self.btn_ipinfo.setToolTip("Внешний IP (проверка утечки) + "
                                   "ping/потери пакетов.")
        self.btn_ipinfo.clicked.connect(self.on_ip_info)
        tools_row2.addWidget(self.btn_dns)
        tools_row2.addWidget(self.btn_ipinfo)
        root.addLayout(tools_row2)

        tools_row3 = QHBoxLayout()
        tools_row3.setSpacing(8)
        self.btn_ipv6 = QPushButton("Переключить IPv6")
        self.btn_ipv6.setToolTip("Включить/выключить IPv6 на активном адаптере. "
                                 "Частый виновник глюков после VPN. Требует "
                                 "админа.")
        self.btn_ipv6.clicked.connect(self.on_ipv6_toggle)
        self.btn_dnsinfo = QPushButton("Текущий DNS / утечка")
        self.btn_dnsinfo.setToolTip("Какие DNS-серверы реально используются на "
                                    "адаптерах + подсказка об утечке DNS.")
        self.btn_dnsinfo.clicked.connect(self.on_dns_info)
        tools_row3.addWidget(self.btn_ipv6)
        tools_row3.addWidget(self.btn_dnsinfo)
        root.addLayout(tools_row3)

        tools_row4 = QHBoxLayout()
        tools_row4.setSpacing(8)
        self.btn_conns = QPushButton("Активные соединения")
        self.btn_conns.setToolTip("Внешние TCP-соединения с именем процесса — "
                                  "куда подключён твой ПК.")
        self.btn_conns.clicked.connect(self.on_connections)
        self.btn_adapter_info = QPushButton("Детали адаптера")
        self.btn_adapter_info.setToolTip("IP, шлюз, DNS, MAC, скорость линка, "
                                         "DHCP выбранного адаптера.")
        self.btn_adapter_info.clicked.connect(self.on_adapter_details)
        tools_row4.addWidget(self.btn_conns)
        tools_row4.addWidget(self.btn_adapter_info)
        root.addLayout(tools_row4)

        tools_row5 = QHBoxLayout()
        tools_row5.setSpacing(8)
        self.btn_ping = QPushButton("Пинг хоста")
        self.btn_ping.setToolTip("Пинг и потери до любого адреса (IP или домен).")
        self.btn_ping.clicked.connect(self.on_ping_host)
        self.btn_mtu = QPushButton("Подобрать MTU")
        self.btn_mtu.setToolTip("Найти оптимальный MTU (DF-пинг) и предложить "
                                "установить его. Установка требует админа.")
        self.btn_mtu.clicked.connect(self.on_probe_mtu)
        tools_row5.addWidget(self.btn_ping)
        tools_row5.addWidget(self.btn_mtu)
        root.addLayout(tools_row5)

        # список кнопок-инструментов, чтобы блокировать во время работы
        self._tool_btns = [self.btn_procs, self.btn_adapter, self.btn_dns,
                           self.btn_ipinfo, self.btn_ipv6, self.btn_dnsinfo,
                           self.btn_conns, self.btn_adapter_info,
                           self.btn_ping, self.btn_mtu]
        # кнопки починки — блокируем на время диагностики (иначе починка и
        # фоновая до-загрузка «остатков VPN» подерутся за один воркер)
        self._fix_btns = [self.btn_quick, self.btn_ip, self.btn_deep,
                          self.btn_vpn_remnants]

        # Журнал
        root.addWidget(hline())
        log_head = QHBoxLayout()
        log_lbl = QLabel("ЖУРНАЛ")
        log_lbl.setObjectName("section")
        log_head.addWidget(log_lbl)
        log_head.addStretch()
        for text, tip, slot in (
            ("Настройки", "Тема оформления и хост по умолчанию для пинга.",
             self.on_settings),
            ("Обновления", "Проверить новую версию на GitHub.",
             self.on_check_update),
            ("Копировать", "Скопировать отчёт (диагностика + журнал) в буфер "
             "обмена.", self.on_copy_report),
            ("Отчёт", "Сохранить состояние сети и журнал в текстовый файл.",
             self.on_export_report),
            ("История", "Сохранённые снимки состояния сети и событий монитора.",
             self.on_history),
            ("Папка логов", "Открыть папку с файлами логов и историей.",
             self.on_open_logs),
        ):
            b = QPushButton(text)
            b.setObjectName("link")
            b.setToolTip(tip)
            b.clicked.connect(slot)
            log_head.addWidget(b)
        btn_clear = QPushButton("Очистить")
        btn_clear.setObjectName("link")
        btn_clear.clicked.connect(lambda: self.log.clear())
        log_head.addWidget(btn_clear)
        root.addLayout(log_head)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(150)
        self.log.setPlaceholderText("Здесь появится журнал действий…")
        root.addWidget(self.log)

    # -- фоновые потоки ----------------------------------------------------
    def _track(self, thread):
        """Удержать ссылку на QThread до его завершения и вернуть его же.

        Без этого перезапись self._worker/_tworker роняет ещё работающий
        поток под сборку мусора → крах Qt «Destroyed while thread is running».
        """
        self._threads.append(thread)
        thread.finished.connect(
            lambda: self._threads.remove(thread)
            if thread in self._threads else None)
        return thread

    # -- журнал ------------------------------------------------------------
    def log_line(self, text: str) -> None:
        self.log.appendPlainText(text)
        logger.info(text.strip())  # дублируем в файл

    def on_export_report(self) -> None:
        report = build_report(self._last_items, self.log.toPlainText())
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default = str(LOG_DIR / f"NetworkDoctor_отчёт_{stamp}.txt")
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить отчёт", default, "Текстовый файл (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(report, encoding="utf-8")
        except Exception as e:
            self.log_line(f"  ✗ Не удалось сохранить отчёт: {e}")
            return
        self.log_line(f"✔ Отчёт сохранён: {path}")
        record_state("tool", info=f"Экспортирован отчёт: {path}")
        if QMessageBox.question(
                self, "Отчёт сохранён",
                f"Отчёт сохранён:\n{path}\n\nОткрыть его сейчас?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                ) == QMessageBox.StandardButton.Yes:
            try:
                os.startfile(path)
            except Exception as e:
                self.log_line(f"  ✗ Не удалось открыть отчёт: {e}")

    def on_copy_report(self) -> None:
        report = build_report(self._last_items, self.log.toPlainText())
        QApplication.clipboard().setText(report)
        self.log_line("✔ Отчёт скопирован в буфер обмена.")

    def on_settings(self) -> None:
        dlg = SettingsDialog(self)
        if dlg.exec() and dlg.result_value:
            self.log_line("✔ Настройки сохранены.")
            if dlg.result_value.get("theme_changed"):
                ans = QMessageBox.question(
                    self, "Смена темы",
                    "Тема изменена. Перезапустить NetworkDoctor сейчас, "
                    "чтобы применить?",
                    QMessageBox.StandardButton.Yes
                    | QMessageBox.StandardButton.No)
                if ans == QMessageBox.StandardButton.Yes:
                    try:
                        relaunch_self()
                    except Exception as e:
                        self.log_line(f"  ✗ Не удалось перезапустить: {e}")
                        return
                    self._force_quit = True
                    self.close()

    def on_check_update(self) -> None:
        self.log_line("▶ Проверяю обновления…")
        self._run_task(check_update, self._show_update)

    def _show_update(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка проверки обновлений: {res}")
            return
        status = res.get("status")
        cur, latest = res.get("current", ""), res.get("latest", "")
        if status == "update":
            self.log_line(f"  Доступна новая версия: {latest} (у тебя {cur}).")
            box = QMessageBox(self)
            box.setWindowTitle("Доступно обновление")
            box.setText(f"Доступна новая версия: {latest}\nТекущая: {cur}\n\n"
                        f"{res.get('url', '')}")
            box.exec()
        elif status == "latest":
            self.log_line(f"  Установлена последняя версия ({cur}).")
            QMessageBox.information(self, "Обновления",
                                    f"У тебя последняя версия ({cur}).")
        elif status == "unconfigured":
            self.log_line("  Проверка обновлений не настроена (github_repo).")
            QMessageBox.information(
                self, "Обновления",
                "Репозиторий для проверки обновлений не указан.\n"
                "Впиши его в logs/config.json → \"github_repo\" в формате "
                "\"владелец/название\" (или в netdoctor/updates.py → "
                "GITHUB_REPO).")
        else:
            self.log_line(f"  ✗ {res.get('note', 'не удалось проверить')}")
            QMessageBox.warning(self, "Обновления",
                                res.get("note", "Не удалось проверить."))

    def on_history(self) -> None:
        HistoryDialog(self).exec()

    def on_open_logs(self) -> None:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            os.startfile(str(LOG_DIR))
        except Exception as e:
            self.log_line(f"  ✗ Не удалось открыть папку логов: {e}")

    # -- результаты --------------------------------------------------------
    def _clear_results(self) -> None:
        while self.results_lay.count():
            item = self.results_lay.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _placeholder(self, text: str) -> None:
        self._clear_results()
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color:{C_FAINT}; padding:20px;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_lay.addWidget(lbl)
        self.results_lay.addStretch()

    def _add_card(self, item: dict, delay: int) -> None:
        """Создать карточку результата и плавно проявить её через delay мс."""
        card = ResultCard(item)
        self.results_lay.addWidget(card)
        effect = QGraphicsOpacityEffect(card)
        effect.setOpacity(0.0)
        card.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", card)
        anim.setDuration(320)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        card._anim = anim  # держим ссылку, иначе анимация умрёт
        QTimer.singleShot(delay, anim.start)

    def _show_results(self, items: list[dict]) -> None:
        self._clear_results()
        for i, it in enumerate(items):
            self._add_card(it, i * 55)
        self.results_lay.addStretch()

    def _append_results(self, items: list[dict]) -> None:
        """Дописать карточки в конец (не перерисовывая уже показанные)."""
        if not items:
            return
        # снять хвостовой stretch, добавить карточки, вернуть stretch
        last = self.results_lay.takeAt(self.results_lay.count() - 1)
        if last is not None and last.widget() is not None:
            # на всякий случай: если последним оказался виджет, вернём его
            self.results_lay.addItem(last)
        for i, it in enumerate(items):
            self._add_card(it, i * 55)
        self.results_lay.addStretch()

    # -- сводный индикатор состояния ---------------------------------------
    def set_health(self, kind: str, text: str) -> None:
        """kind: 'ok' | 'warn' | 'bad' | 'busy' | 'idle'."""
        colors = {OK: CLR_OK, WARN: CLR_WARN, BAD: CLR_BAD,
                  "busy": CLR_BUSY, "idle": C_MUTED}
        c = colors.get(kind, C_MUTED)
        self.health_frame.setStyleSheet(
            f"QFrame#health{{background:{_rgba(c, 0.10)}; "
            f"border:1px solid {_rgba(c, 0.33)}; border-radius:12px;}}")
        self.health_label.setStyleSheet(
            f"color:{c}; font-size:15px; font-weight:600;")
        self.health_label.setText(text)
        if kind == "busy":
            self.health_dot.hide()
            self.health_spin.start()
        else:
            self.health_spin.stop()
            self.health_dot.setStyleSheet(f"background:{c}; border-radius:6px;")
            self.health_dot.show()

    @staticmethod
    def _summarize(items: list[dict]) -> tuple[str, str]:
        statuses = [i["status"] for i in items]
        if BAD in statuses:
            return BAD, ("Похоже, есть проблема с сетью. Попробуй "
                         "«Починить умно».")
        if WARN in statuses:
            return WARN, ("Интернет работает, но есть замечания "
                          "(например, задан прокси).")
        return OK, "Интернет работает нормально."

    # -- диагностика -------------------------------------------------------
    def on_diagnose(self) -> None:
        if getattr(self, "_diag_busy", False):
            return
        self._diag_busy = True
        self.btn_diag.setEnabled(False)
        self.btn_smart.setEnabled(False)
        for b in self._fix_btns:
            b.setEnabled(False)
        self.btn_diag.setText("Проверяю…")
        self.set_health("busy", "Проверяю состояние сети…")
        self._placeholder("Идёт проверка сети…")
        self.log_line("▶ Диагностика запущена.")
        self._worker = DiagnoseWorker()
        self._worker.core_ready.connect(self._core_done)
        self._worker.remnants_ready.connect(self._remnants_done)
        self._track(self._worker).start()

    def _core_done(self, items: list[dict]) -> None:
        # Основные проверки готовы — показываем сразу, кнопки снова активны.
        self._last_items = items
        self._show_results(items)
        self.btn_diag.setEnabled(True)
        self.btn_smart.setEnabled(True)
        self.btn_diag.setText("Проверить сеть")
        kind, msg = self._summarize(items)
        self.set_health(kind, msg + "  Проверяю остатки VPN…")

    def _remnants_done(self, rem_items: list[dict]) -> None:
        # Медленные проверки догрузились — дописываем карточки и итог.
        self._diag_busy = False
        for b in self._fix_btns:
            b.setEnabled(True)
        self._last_items = (self._last_items or []) + rem_items
        self._append_results(rem_items)
        kind, msg = self._summarize(self._last_items)
        self.set_health(kind, msg)
        bad = sum(1 for i in self._last_items if i["status"] in (BAD, WARN))
        self.log_line(f"✔ Диагностика завершена. Замечаний: {bad}.")
        record_state("diagnosis", summary=kind,
                     items=[{"title": i["title"], "status": i["status"]}
                            for i in self._last_items])

    # -- запуск набора починок --------------------------------------------
    def _run_fixes(self, steps: list, done_msg: str,
                   reboot: bool = False) -> None:
        for b in (self.btn_quick, self.btn_ip, self.btn_deep, self.btn_diag,
                  self.btn_smart, self.btn_vpn_remnants):
            b.setEnabled(False)
        self._worker = FixWorker(steps)
        self._worker.log_line.connect(self.log_line)
        self._worker.finished_ok.connect(
            lambda: self._fixes_done(done_msg, reboot))
        self._track(self._worker).start()

    def _fixes_done(self, done_msg: str, reboot: bool) -> None:
        for b in (self.btn_quick, self.btn_ip, self.btn_deep, self.btn_diag,
                  self.btn_smart, self.btn_vpn_remnants):
            b.setEnabled(True)
        self.log_line(done_msg)
        record_state("fix", action=done_msg, reboot=reboot)
        if reboot:
            QMessageBox.information(
                self, "Нужна перезагрузка",
                "Глубокий сброс выполнен.\n\nЧтобы изменения вступили в силу, "
                "перезагрузи компьютер.")
        else:
            self.on_diagnose()

    # -- обработчики починки -----------------------------------------------
    def on_quick_fix(self) -> None:
        ans = QMessageBox.question(
            self, "Быстрая починка прокси",
            "Будет выполнено (безопасно, без перезагрузки):\n\n"
            "• выключить и очистить системный прокси Windows\n"
            "• сбросить WinHTTP-прокси\n"
            "• удалить переменные окружения прокси\n"
            "• отключить авто-определение прокси (WPAD/PAC)\n"
            "• очистить кеш DNS\n\n"
            "Продолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.log_line("▶ Быстрая починка прокси…")
        self._run_fixes(
            [fix_wininet_proxy, fix_winhttp_proxy, fix_env_proxy,
             fix_disable_wpad, fix_flush_dns],
            "✔ Быстрая починка завершена. Перепроверяю сеть…")

    def on_ip_fix(self) -> None:
        ans = QMessageBox.question(
            self, "Обновить IP",
            "Освободить и заново получить IP-адрес?\n"
            "На пару секунд пропадёт сеть — это нормально.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.log_line("▶ Обновление IP…")
        self._run_fixes([fix_ip_renew], "✔ Обновление IP завершено.")

    def on_deep_fix(self) -> None:
        if not is_admin():
            QMessageBox.warning(
                self, "Нужны права администратора",
                "Глубокий сброс требует запуска от администратора.\n\n"
                "Закрой программу и запусти через «Запуск (админ).bat».")
            return
        ans = QMessageBox.warning(
            self, "Глубокий сброс сети",
            "ВНИМАНИЕ. Будет выполнено:\n\n"
            "• netsh winsock reset\n"
            "• netsh int ip reset\n\n"
            "Это полностью пересобирает сетевой стек и ТРЕБУЕТ ПЕРЕЗАГРУЗКИ. "
            "Делай это, если быстрая починка не помогла.\n\nПродолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.log_line("▶ Глубокий сброс сети…")
        self._run_fixes([create_restore_point, backup_network_state,
                         fix_winsock, fix_tcpip],
                        "✔ Глубокий сброс выполнен.", reboot=True)

    def on_fix_vpn_remnants(self) -> None:
        if not is_admin():
            QMessageBox.warning(
                self, "Нужны права администратора",
                "Чистка остатков VPN требует запуска от администратора.\n\n"
                "Нажми «Перезапустить с правами» вверху окна.")
            return
        ans = QMessageBox.warning(
            self, "Убрать остатки VPN",
            "Будет выполнено (без перезагрузки):\n\n"
            "• бэкап текущих правил брандмауэра в logs/backups (откат возможен);\n"
            "• СБРОС брандмауэра Windows к настройкам по умолчанию — снимает "
            "застрявшую блокировку kill-switch. ВНИМАНИЕ: это также удалит "
            "твои собственные правила брандмауэра, если они есть.\n"
            "• удаление зависших маршрутов от отключённых туннелей;\n"
            "• возврат MTU активного адаптера к 1500.\n\n"
            "Делай это, если после VPN интернет заблокирован или часть сайтов "
            "не грузится. Продолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.log_line("▶ Убираю остатки VPN (файрвол/маршруты/MTU/ARP/hosts)…")
        self._run_fixes(
            [fix_firewall_backup, fix_firewall_reset, fix_stale_routes,
             fix_mtu_reset, fix_flush_arp, fix_clean_hosts,
             fix_restart_dnscache],
            "✔ Остатки VPN убраны. Перепроверяю сеть…")

    def on_relaunch_admin(self) -> None:
        ans = QMessageBox.question(
            self, "Перезапуск с правами администратора",
            "Перезапустить NetworkDoctor от имени администратора?\n"
            "Текущее окно закроется, появится запрос UAC.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        try:
            relaunch_as_admin()
        except Exception as e:
            self.log_line(f"  ✗ Не удалось перезапустить: {e}")
            QMessageBox.warning(
                self, "Не удалось",
                f"Не удалось перезапустить с правами: {e}\n\n"
                "Запусти вручную через «Запуск (админ).bat».")
            return
        self._force_quit = True
        self.close()

    # -- инструменты -------------------------------------------------------
    def _run_task(self, fn, on_done) -> None:
        """Выполнить fn в фоне; по завершении вызвать on_done(результат)."""
        for b in self._tool_btns:
            b.setEnabled(False)
        self._tworker = TaskWorker(fn)

        def _wrap(res):
            for b in self._tool_btns:
                b.setEnabled(True)
            on_done(res)

        self._tworker.done.connect(_wrap)
        self._track(self._tworker).start()

    def _need_admin(self) -> bool:
        if is_admin():
            return True
        QMessageBox.warning(
            self, "Нужны права администратора",
            "Эта функция требует запуска от администратора.\n\n"
            "Закрой программу и запусти через «Запуск (админ).bat».")
        return False

    # --- зависшие прокси-процессы ---
    def on_proxy_procs(self) -> None:
        self.log_line("▶ Ищу прокси-процессы…")
        self._run_task(list_proxy_processes, self._show_procs)

    def _show_procs(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        self.log_line(f"  Найдено прокси-процессов: {len(res)}")
        ProxyProcessDialog(self, res).exec()

    # --- перезапуск адаптера ---
    def on_restart_adapter(self) -> None:
        if not self._need_admin():
            return
        self.log_line("▶ Получаю список адаптеров…")
        self._run_task(lambda: (list_adapters(), default_adapter()),
                       self._pick_adapter)

    def _pick_adapter(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        adapters, default = res
        if not adapters:
            QMessageBox.warning(self, "Нет адаптеров",
                                "Не удалось получить список адаптеров.")
            return
        items = [f"{n} — {s}" for n, s in adapters]
        cur = next((i for i, (n, _) in enumerate(adapters) if n == default), 0)
        choice, ok = QInputDialog.getItem(
            self, "Перезапуск адаптера",
            "Какой адаптер перезапустить?\n(активный отмечен как «Up»)",
            items, cur, False)
        if not ok:
            return
        name = adapters[items.index(choice)][0]
        ans = QMessageBox.question(
            self, "Перезапустить адаптер",
            f"Отключить и снова включить «{name}»?\n"
            f"Связь пропадёт на пару секунд.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.log_line(f"▶ Перезапуск адаптера «{name}»…")
        self._run_task(lambda: restart_adapter(name), self._adapter_done)

    def _adapter_done(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        ok, msg = res
        if ok:
            self.log_line("  ✓ Адаптер перезапущен.")
        else:
            self.log_line(f"  ✗ Не удалось: {msg or 'нужен админ?'}")

    # --- переключение DNS ---
    def on_dns(self) -> None:
        if not self._need_admin():
            return
        self.log_line("▶ Получаю адаптеры для DNS…")
        self._run_task(lambda: (list_adapters(), default_adapter()),
                       self._open_dns)

    def _open_dns(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        adapters, default = res
        if not adapters:
            QMessageBox.warning(self, "Нет адаптеров",
                                "Не удалось получить список адаптеров.")
            return
        dlg = DnsDialog(self, adapters, default)
        if dlg.exec() and dlg.result_value:
            name, servers = dlg.result_value
            desc = "авто (DHCP)" if servers is None else " / ".join(servers)
            self.log_line(f"▶ Ставлю DNS на «{name}»: {desc}…")
            self._run_task(lambda: set_dns(name, servers), self._dns_done)

    def _dns_done(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        ok, msg = res
        if ok:
            self.log_line("  ✓ DNS применён, кеш DNS очищен.")
        else:
            self.log_line(f"  ✗ Не удалось: {msg or 'нужен админ?'}")

    # --- переключение IPv6 ---
    def on_ipv6_toggle(self) -> None:
        if not self._need_admin():
            return
        self.log_line("▶ Проверяю состояние IPv6…")

        def work():
            adapter = default_adapter()
            return adapter, ipv6_enabled(adapter)

        self._run_task(work, self._ipv6_state)

    def _ipv6_state(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        adapter, enabled = res
        if not adapter:
            QMessageBox.warning(self, "IPv6",
                                "Не удалось определить активный адаптер.")
            return
        if enabled is None:
            QMessageBox.warning(self, "IPv6",
                                f"Не удалось определить состояние IPv6 на "
                                f"«{adapter}».")
            return
        cur = "включён" if enabled else "выключен"
        action = "выключить" if enabled else "включить"
        ans = QMessageBox.question(
            self, "Переключить IPv6",
            f"На адаптере «{adapter}» IPv6 сейчас {cur}.\n\n"
            f"IPv6 — частый виновник глюков после VPN. {action.capitalize()} "
            f"его?\nСвязь может кратко прерваться.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self.log_line(f"▶ {action.capitalize()} IPv6 на «{adapter}»…")
        self._run_task(lambda: set_ipv6(adapter, not enabled), self._ipv6_done)

    def _ipv6_done(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        ok, msg = res
        if ok:
            self.log_line("  ✓ IPv6 переключён.")
            record_state("tool", info="Переключён IPv6 на активном адаптере")
        else:
            self.log_line(f"  ✗ Не удалось: {msg or 'нужен админ?'}")

    # --- внешний IP и качество канала ---
    def on_ip_info(self) -> None:
        self.log_line("▶ Проверяю внешний IP, канал и скорость…")

        def work():
            return (get_exit_info(),
                    ping_stats("1.1.1.1"), ping_stats("8.8.8.8"),
                    download_speed(8_000_000))

        self._run_task(work, self._show_ip_info)

    def _show_ip_info(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        (ip, loc), p1, p2, speed = res

        def fmt(name, stat):
            loss, avg = stat
            if avg < 0:
                return f"{name}: нет ответа (потери {loss}%)"
            ms = "<1 мс" if avg == 0 else f"{avg} мс"
            return f"{name}: {ms}, потери {loss}%"

        where = f"{ip} ({country_name(loc)})" if ip and loc else \
            (ip or "не удалось определить")
        speed_line = (f"Скорость скачивания: {speed} Мбит/с" if speed >= 0
                      else "Скорость скачивания: не удалось измерить")
        lines = [f"Внешний IP: {where}",
                 fmt("Ping 1.1.1.1", p1), fmt("Ping 8.8.8.8", p2), speed_line]
        for ln in lines:
            self.log_line("  " + ln)
        record_state("tool", info="Мой IP и качество канала: " +
                     "; ".join(lines), ip=ip, loc=loc)
        QMessageBox.information(
            self, "Мой IP и качество канала",
            "\n".join(lines) + "\n\nЕсли внешний IP отличается от твоего "
            "реального адреса — трафик идёт через VPN/прокси (утечки нет).")

    # --- текущий DNS / утечка ---
    def on_dns_info(self) -> None:
        self.log_line("▶ Смотрю текущие DNS-серверы…")
        self._run_task(lambda: (list_dns_servers(), get_exit_info()),
                       self._show_dns_info)

    def _show_dns_info(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        rows, (ip, loc) = res
        summary = "; ".join(f"{r['iface']}={'/'.join(r['servers'])}"
                            for r in rows) or "не задано"
        self.log_line(f"  DNS: {summary}")
        record_state("tool", info=f"Текущий DNS: {summary}")
        DnsInfoDialog(self, rows, loc).exec()

    # --- активные соединения ---
    def on_connections(self) -> None:
        self.log_line("▶ Собираю активные соединения…")
        self._run_task(list_connections, self._show_connections)

    def _show_connections(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        self.log_line(f"  Внешних соединений: {len(res)}")
        record_state("tool", info=f"Активные соединения: {len(res)}")
        ConnectionsDialog(self, res).exec()

    # --- детали адаптера ---
    def on_adapter_details(self) -> None:
        self.log_line("▶ Получаю список адаптеров…")
        self._run_task(lambda: (list_adapters(), default_adapter()),
                       self._pick_adapter_details)

    def _pick_adapter_details(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        adapters, default = res
        if not adapters:
            QMessageBox.warning(self, "Нет адаптеров",
                                "Не удалось получить список адаптеров.")
            return
        items = [f"{n} — {s}" for n, s in adapters]
        cur = next((i for i, (n, _) in enumerate(adapters) if n == default), 0)
        choice, ok = QInputDialog.getItem(
            self, "Детали адаптера", "Выбери адаптер:", items, cur, False)
        if not ok:
            return
        name = adapters[items.index(choice)][0]
        self.log_line(f"▶ Детали адаптера «{name}»…")
        self._run_task(lambda: adapter_details(name), self._show_adapter_details)

    def _show_adapter_details(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        AdapterDetailsDialog(self, res).exec()

    # --- пинг произвольного хоста ---
    def on_ping_host(self) -> None:
        host, ok = QInputDialog.getText(
            self, "Пинг хоста", "IP-адрес или домен:",
            text=settings.get("ping_host"))
        if not ok or not host.strip():
            return
        host = host.strip()
        if not valid_host(host):
            QMessageBox.warning(self, "Пинг хоста", "Некорректный адрес.")
            return
        settings.set("ping_host", host)
        self.log_line(f"▶ Пингую {host}…")
        self._run_task(lambda: ping_stats(host, count=6),
                       lambda r: self._show_ping_host(host, r))

    def _show_ping_host(self, host, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        loss, avg = res
        if avg < 0:
            msg = f"{host}: нет ответа (потери {loss}%)."
        else:
            ms = "<1 мс" if avg == 0 else f"{avg} мс"
            msg = f"{host}: {ms}, потери {loss}%."
        self.log_line("  " + msg)
        record_state("tool", info=f"Пинг хоста: {msg}")
        QMessageBox.information(self, "Пинг хоста", msg)

    # --- подбор оптимального MTU ---
    def on_probe_mtu(self) -> None:
        self.log_line("▶ Подбираю оптимальный MTU (DF-пинг)…")
        self._run_task(lambda: probe_optimal_mtu("1.1.1.1"), self._show_mtu)

    def _show_mtu(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        mtu = res
        if mtu < 0:
            self.log_line("  ✗ Не удалось подобрать MTU (нет ответа на пинг).")
            QMessageBox.warning(self, "Подобрать MTU",
                                "Не удалось подобрать MTU — сервер не ответил "
                                "на пинг с флагом DF.")
            return
        self.log_line(f"  Оптимальный MTU: {mtu}.")
        record_state("tool", info=f"Подобран MTU: {mtu}")
        name = default_adapter()
        ans = QMessageBox.question(
            self, "Подобрать MTU",
            f"Оптимальный MTU до 1.1.1.1: {mtu}.\n"
            f"Текущий активный адаптер: «{name}».\n\n"
            f"Установить MTU {mtu} на этот адаптер? (Требует прав "
            f"администратора.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        if not self._need_admin():
            return
        self.log_line(f"▶ Ставлю MTU {mtu} на «{name}»…")
        self._run_task(lambda: apply_mtu(name, mtu), self._mtu_applied)

    def _mtu_applied(self, res) -> None:
        if isinstance(res, Exception):
            self.log_line(f"  ✗ Ошибка: {res}")
            return
        ok, msg = res
        if ok:
            self.log_line("  ✓ MTU установлен.")
        else:
            self.log_line(f"  ✗ Не удалось: {msg or 'нужен админ?'}")

    # -- «Починить умно» ---------------------------------------------------
    def on_smart_fix(self) -> None:
        ans = QMessageBox.question(
            self, "Починить умно",
            "Утилита сама выполнит нужные шаги по порядку и остановится, "
            "как только интернет заработает:\n\n"
            "• сброс системного прокси + DNS\n"
            "• при необходимости — обновление IP\n\n"
            "Внимание: это сбросит настройки системного прокси. Если сейчас "
            "работает прокси-клиент через системный прокси, он отключится.\n\n"
            "Продолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        self._start_smart_fix()

    def _start_smart_fix(self, auto: bool = False) -> bool:
        """Запустить умную починку. auto=True — без диалога (из авто-починки).
        Возвращает False, если починка уже идёт."""
        if self._smart is not None and self._smart.isRunning():
            return False
        for b in (self.btn_smart, self.btn_diag, self.btn_quick, self.btn_ip,
                  self.btn_deep, self.btn_vpn_remnants, *self._tool_btns):
            b.setEnabled(False)
        self.set_health("busy", "Чиню сеть…")
        self.log_line("▶ Авто-починка…" if auto else "▶ Умная починка…")
        if auto:
            self._notify("Авто-починка", "Пропал интернет — пробую починить сам.")
        self._smart = SmartFixWorker()
        self._smart.log_line.connect(self.log_line)
        self._smart.finished_ok.connect(
            lambda ok: self._smart_done(ok, auto))
        self._track(self._smart).start()
        return True

    def _smart_done(self, ok: bool, auto: bool = False) -> None:
        for b in (self.btn_smart, self.btn_diag, self.btn_quick, self.btn_ip,
                  self.btn_deep, self.btn_vpn_remnants, *self._tool_btns):
            b.setEnabled(True)
        record_state("fix", action="Авто-починка" if auto else "Починить умно",
                     result="успех" if ok else "не помогло")
        if ok:
            self.log_line("✔ Готово: интернет работает.")
            if auto:
                self._notify("Авто-починка", "Интернет восстановлен.")
        else:
            self.log_line("✗ Автоматически починить не удалось.")
            if auto:
                self._notify("Авто-починка",
                             "Не помогло — открой NetworkDoctor вручную.")
            else:
                QMessageBox.information(
                    self, "Не удалось автоматически",
                    "Быстрые шаги не помогли. Что можно попробовать:\n\n"
                    "• «Зависшие прокси-процессы» — завершить лишние "
                    "sing-box/xray;\n"
                    "• «Перезапустить адаптер»;\n"
                    "• «Глубокий сброс сети» (нужна перезагрузка).")
        # окно на виду — перепроверим сеть; в трее не дёргаем UI-диагностику
        if self.isVisible():
            self.on_diagnose()

    # -- автозапуск --------------------------------------------------------
    def on_toggle_autostart(self, on: bool) -> None:
        ok, msg = enable_autostart() if on else disable_autostart()
        self.log_line(("▶ " if ok else "✗ ") + msg)
        if not ok:
            # откатить состояние кнопки, не вызывая обработчик заново
            self.btn_autostart.blockSignals(True)
            self.btn_autostart.setChecked(is_autostart_enabled())
            self.btn_autostart.blockSignals(False)
            QMessageBox.warning(self, "Автозапуск", msg)

    def on_toggle_autofix(self, on: bool) -> None:
        self._autofix_enabled = on
        settings.set("autofix", on)
        self.btn_autofix.setText("Авто-починка: вкл" if on else
                                 "Авто-починка: выкл")
        if on and not self.btn_monitor.isChecked():
            # авто-починка работает только при включённом мониторинге
            self.btn_monitor.setChecked(True)
        self.log_line("▶ Авто-починка включена." if on else
                      "■ Авто-починка выключена.")

    # -- фоновый мониторинг ------------------------------------------------
    def on_toggle_monitor(self, on: bool) -> None:
        if on:
            self.btn_monitor.setText("Мониторинг: вкл")
            self._last_online = None
            self._last_loc = None
            self._last_ip = None
            self._ensure_tray()
            interval = int(settings.get("monitor_interval") or 20)
            self._mon = MonitorWorker(interval=interval)
            self._mon.status.connect(self._on_mon_status)
            self._track(self._mon).start()
            self.log_line(f"▶ Мониторинг включён (проверка каждые "
                          f"{self._mon.interval} с).")
        else:
            self.btn_monitor.setText("Мониторинг: выкл")
            if self._mon:
                self._mon.stop()
                self._mon.wait(1500)
                self._mon = None
            self.log_line("■ Мониторинг выключен.")

    def _on_mon_status(self, info: dict) -> None:
        online = info.get("online", False)
        ip = info.get("ip", "")
        loc = info.get("loc", "")

        prev = self._last_online
        self._last_online = online
        if prev is True and not online:
            record_state("monitor", event="Интернет пропал",
                         offline=True, ip=ip, loc=loc)
            if self._autofix_enabled:
                # запускаем умную починку сами (без диалога)
                self._start_smart_fix(auto=True)
            else:
                self._notify("Интернет пропал",
                             "Связь с сетью потеряна. Открой NetworkDoctor и "
                             "нажми «Починить умно».")
        elif prev is False and online:
            self._notify("Интернет восстановлен", "Связь снова есть.")
            record_state("monitor", event="Интернет восстановлен",
                         offline=False, ip=ip, loc=loc)

        if online and loc:
            prev_loc = self._last_loc
            if prev_loc and loc != prev_loc:
                self._notify(
                    "Выходной узел сменился",
                    f"{country_name(prev_loc)} → {country_name(loc)}. "
                    f"Внешний IP и страна выхода изменились — если это неожиданно, "
                    f"проверь VPN/прокси-клиент.")
                record_state(
                    "monitor",
                    event=f"Смена выхода: {country_name(prev_loc)} → "
                          f"{country_name(loc)}",
                    offline=False, ip=ip, loc=loc)
            self._last_loc = loc
            self._last_ip = ip
            if self._tray is not None:
                self._tray.setToolTip(
                    f"NetworkDoctor — выход: {country_name(loc)} ({ip})")

    def _ensure_tray(self) -> None:
        if self._tray is not None or not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self._tray = QSystemTrayIcon(self.windowIcon(), self)
        menu = QMenu()
        act_open = menu.addAction("Открыть NetworkDoctor")
        act_open.triggered.connect(self._show_from_tray)
        act_quit = menu.addAction("Выход")
        act_quit.triggered.connect(self._quit_from_tray)
        self._tray.setContextMenu(menu)
        self._tray.setToolTip("NetworkDoctor")
        self._tray.activated.connect(
            lambda reason: self._show_from_tray()
            if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        self._tray.show()

    def _notify(self, title: str, msg: str) -> None:
        self.log_line(f"! {title}: {msg}")
        if self._tray is not None:
            self._tray.showMessage(
                title, msg, QSystemTrayIcon.MessageIcon.Information, 6000)

    def _show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _quit_from_tray(self) -> None:
        self._force_quit = True
        self.close()

    # -- автозапуск диагностики, сворачивание, закрытие --------------------
    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._auto_done:
            self._auto_done = True
            QTimer.singleShot(350, self.on_diagnose)  # автодиагностика

    def start_in_tray(self) -> None:
        """Запуск свёрнутым в трей: включить мониторинг, окно не показывать."""
        self._auto_done = True  # без всплывающей автодиагностики
        self.btn_monitor.setChecked(True)  # включит мониторинг и создаст трей
        if self._tray is not None:
            self._tray.showMessage(
                "NetworkDoctor работает в трее",
                "Мониторинг включён. Открыть — клик по значку.",
                QSystemTrayIcon.MessageIcon.Information, 4000)

    def closeEvent(self, event) -> None:
        # Если есть трей и это не настоящий выход — сворачиваемся в трей.
        if self._tray is not None and not self._force_quit:
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self._tray.showMessage(
                    "NetworkDoctor свернулся в трей",
                    "Мониторинг продолжает работать. Правый клик по значку → "
                    "«Выход», чтобы закрыть полностью.",
                    QSystemTrayIcon.MessageIcon.Information, 5000)
            return
        if self._mon:
            self._mon.stop()
        # дождаться фоновых потоков, чтобы Qt не разрушил их на ходу при выходе
        # («QThread: Destroyed while thread is still running»)
        for t in list(self._threads):
            try:
                if t.isRunning():
                    t.wait(2000)
            except RuntimeError:
                pass  # объект потока уже удалён — ждать нечего
        if self._tray:
            self._tray.hide()
        super().closeEvent(event)


def main() -> None:
    # Логи и перехват падений — до создания окна, чтобы поймать любые ошибки.
    setup_logging()
    install_excepthook()

    # Отдельный AppUserModelID — чтобы Windows показывала нашу иконку.
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "NetworkDoctor.App")
    except Exception:
        pass

    start_hidden = "--tray" in sys.argv

    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    icon = make_app_icon()
    app.setWindowIcon(icon)
    win = NetworkDoctor(start_hidden=start_hidden)
    win.setWindowIcon(icon)
    if start_hidden:
        win.start_in_tray()  # окно не показываем — сидим в трее
    else:
        win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
