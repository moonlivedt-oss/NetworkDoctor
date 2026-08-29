# -*- coding: utf-8 -*-
"""Диалоговые окна: результаты, прокси-процессы, DNS, история состояний."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QScrollArea, QSpinBox, QVBoxLayout, QWidget,
)

from ..core import OK, WARN, BAD
from ..logs import STATE_FILE, read_state_history
from ..net.tools import country_name, kill_process, PUBLIC_DNS, valid_host
from .. import settings
from . import theme


class ResultCard(QFrame):
    """Одна карточка результата проверки."""

    def __init__(self, item: dict):
        super().__init__()
        self.setObjectName("card")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(12)

        sym, color = theme.ICONS.get(item["status"], ("•", "#9aa3b2"))
        badge = QLabel(sym)
        badge.setFixedSize(28, 28)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(
            f"background:{theme._rgba(color, 0.12)}; color:{color}; "
            f"border-radius:14px; font-weight:600; font-size:14px;")
        lay.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(3)
        title = QLabel(item["title"])
        title.setStyleSheet(f"font-weight:600; font-size:14px; color:{theme.C_TITLE};")
        detail = QLabel(item["detail"])
        detail.setWordWrap(True)
        detail.setStyleSheet(f"color:{theme.C_MUTED}; font-size:12px;")
        text.addWidget(title)
        text.addWidget(detail)
        lay.addLayout(text, 1)


class ProxyProcessDialog(QDialog):
    """Список процессов-прокси с кнопками «Завершить»."""

    def __init__(self, parent, procs: list[dict]):
        super().__init__(parent)
        self.setWindowTitle("Зависшие прокси-процессы")
        self.setStyleSheet(theme.STYLE)
        self.resize(520, 420)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        if not procs:
            info = QLabel("Прокси-процессов не найдено. Чисто ✓")
            info.setStyleSheet(f"color:{theme.CLR_OK}; font-size:14px; padding:20px;")
            info.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(info)
        else:
            hint = QLabel("Это процессы, которые слушают прокси-порты или "
                          "называются как прокси-клиенты. Заверши лишние, "
                          "если интернет не работает из-за застрявшего прокси.")
            hint.setWordWrap(True)
            hint.setStyleSheet(f"color:{theme.C_MUTED};")
            lay.addWidget(hint)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            host = QWidget()
            self.rows = QVBoxLayout(host)
            self.rows.setSpacing(8)
            for p in procs:
                self.rows.addWidget(self._make_row(p))
            self.rows.addStretch()
            scroll.setWidget(host)
            lay.addWidget(scroll, 1)

        close = QPushButton("Закрыть")
        close.clicked.connect(self.accept)
        lay.addWidget(close)

    def _make_row(self, p: dict) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        h = QHBoxLayout(card)
        h.setContentsMargins(12, 10, 12, 10)
        ports = ", ".join(str(x) for x in p["proxy_ports"]) or \
            ", ".join(str(x) for x in p["ports"][:6])
        mark = "» " if p["name_hit"] else ""
        info = QLabel(f"{mark}<b>{p['name']}</b>  (PID {p['pid']})<br>"
                      f"<span style='color:{theme.C_MUTED}'>порты: {ports}</span>")
        info.setTextFormat(Qt.TextFormat.RichText)
        h.addWidget(info, 1)
        btn = QPushButton("Завершить")
        btn.setObjectName("danger")
        btn.setFixedWidth(110)
        btn.clicked.connect(lambda: self._kill(p, card, btn))
        h.addWidget(btn)
        return card

    def _kill(self, p: dict, card: QFrame, btn: QPushButton) -> None:
        ans = QMessageBox.question(
            self, "Завершить процесс",
            f"Завершить «{p['name']}» (PID {p['pid']})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ans != QMessageBox.StandardButton.Yes:
            return
        ok, msg = kill_process(p["pid"])
        if ok:
            btn.setText("Завершён ✓")
            btn.setEnabled(False)
            card.setStyleSheet(
                f"QFrame#card{{background:{theme._rgba(theme.CLR_OK, 0.12)};"
                f"border:1px solid {theme._rgba(theme.CLR_OK, 0.40)};border-radius:12px;}}")
        else:
            QMessageBox.warning(self, "Не удалось",
                                f"Не удалось завершить: {msg or 'нужен админ?'}")


class DnsDialog(QDialog):
    """Выбор адаптера и режима DNS."""

    def __init__(self, parent, adapters: list[tuple], default_name: str):
        super().__init__(parent)
        self.setWindowTitle("Переключение DNS")
        self.setStyleSheet(theme.STYLE)
        self.resize(420, 220)
        self.result_value = None  # (adapter_name, servers|None)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)
        lay.addWidget(QLabel("Адаптер:"))
        self.combo = QComboBox()
        idx_default = 0
        for i, (name, status) in enumerate(adapters):
            self.combo.addItem(f"{name} — {status}", name)
            if name == default_name:
                idx_default = i
        self.combo.setCurrentIndex(idx_default)
        lay.addWidget(self.combo)

        lay.addWidget(QLabel("Поставить DNS:"))
        for label, servers in (
            ("Cloudflare  (1.1.1.1 / 1.0.0.1)", ("1.1.1.1", "1.0.0.1")),
            ("Google  (8.8.8.8 / 8.8.4.4)", ("8.8.8.8", "8.8.4.4")),
            ("Авто (получать от роутера / DHCP)", None),
        ):
            b = QPushButton(label)
            b.clicked.connect(lambda _, s=servers: self._choose(s))
            lay.addWidget(b)

    def _choose(self, servers) -> None:
        self.result_value = (self.combo.currentData(), servers)
        self.accept()


class HistoryDialog(QDialog):
    """История состояний сети — последние сохранённые события из журнала."""

    KIND_RU = {"diagnosis": "Диагностика", "fix": "Починка",
               "monitor": "Монитор", "tool": "Инструмент"}

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("История состояний сети")
        self.setStyleSheet(theme.STYLE)
        self.resize(580, 500)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        entries = read_state_history(limit=80)
        head = QLabel(f"Сохраняется в: {STATE_FILE}")
        head.setStyleSheet(f"color:{theme.C_FAINT}; font-size:11px;")
        head.setWordWrap(True)
        head.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(head)

        if not entries:
            info = QLabel("История пока пуста. Проверь сеть или включи "
                          "мониторинг — и события начнут сохраняться.")
            info.setStyleSheet(f"color:{theme.C_MUTED}; padding:24px;")
            info.setWordWrap(True)
            info.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(info, 1)
        else:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            host = QWidget()
            col = QVBoxLayout(host)
            col.setSpacing(6)
            col.setContentsMargins(0, 0, 0, 0)
            for e in entries:
                col.addWidget(self._row(e))
            col.addStretch()
            scroll.setWidget(host)
            lay.addWidget(scroll, 1)

        close = QPushButton("Закрыть")
        close.clicked.connect(self.accept)
        lay.addWidget(close)

    def _row(self, e: dict) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        v = QVBoxLayout(card)
        v.setContentsMargins(12, 8, 12, 8)
        v.setSpacing(2)

        ts = str(e.get("ts", "")).replace("T", "  ")
        kind = self.KIND_RU.get(e.get("kind"), str(e.get("kind", "?")))
        color = self._kind_color(e)
        top = QLabel(f"<b style='color:{color}'>{kind}</b>  "
                     f"<span style='color:{theme.C_FAINT}'>{ts}</span>")
        top.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(top)

        body = self._describe(e)
        if body:
            lbl = QLabel(body)
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color:{theme.C_MUTED}; font-size:12px;")
            v.addWidget(lbl)
        return card

    @staticmethod
    def _kind_color(e: dict) -> str:
        if e.get("kind") == "diagnosis":
            return {OK: theme.CLR_OK, WARN: theme.CLR_WARN,
                    BAD: theme.CLR_BAD}.get(e.get("summary"), theme.C_TITLE)
        if e.get("kind") == "monitor":
            return theme.CLR_WARN if e.get("offline") else theme.CLR_INFO
        return theme.C_TITLE

    @staticmethod
    def _describe(e: dict) -> str:
        kind = e.get("kind")
        if kind == "diagnosis":
            summ = {OK: "всё в порядке", WARN: "есть замечания",
                    BAD: "проблема с сетью"}.get(
                        e.get("summary"), str(e.get("summary", "")))
            probs = [i.get("title", "") for i in e.get("items", [])
                     if i.get("status") in (WARN, BAD)]
            txt = f"Итог: {summ}."
            if probs:
                txt += " Замечания: " + ", ".join(probs)
            return txt
        if kind == "monitor":
            ev = str(e.get("event", ""))
            loc, ip = e.get("loc", ""), e.get("ip", "")
            if loc:
                ev += f" — {country_name(loc)} ({ip})"
            return ev.strip()
        if kind == "fix":
            return str(e.get("action", ""))
        if kind == "tool":
            return str(e.get("info", ""))
        return ""


def _kv_row(lay: QVBoxLayout, label: str, value: str) -> None:
    """Строка «ключ: значение» с выделяемым значением."""
    row = QLabel(f"<span style='color:{theme.C_FAINT}'>{label}:</span>  "
                 f"<b>{value or '—'}</b>")
    row.setTextFormat(Qt.TextFormat.RichText)
    row.setWordWrap(True)
    row.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    lay.addWidget(row)


class AdapterDetailsDialog(QDialog):
    """Детали адаптера: IP, шлюз, DNS, MAC, скорость линка, DHCP."""

    def __init__(self, parent, data: dict):
        super().__init__(parent)
        self.setWindowTitle(f"Адаптер — {data.get('iface', '')}")
        self.setStyleSheet(theme.STYLE)
        self.resize(480, 320)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(8)

        head = QLabel(f"<b>{data.get('iface', '')}</b>  "
                      f"<span style='color:{theme.C_FAINT}'>"
                      f"[{data.get('status', '')}]</span>")
        head.setTextFormat(Qt.TextFormat.RichText)
        head.setStyleSheet(f"color:{theme.C_TITLE}; font-size:15px;")
        lay.addWidget(head)

        for label, key in (("IPv4-адрес", "ip"), ("Шлюз", "gw"),
                           ("DNS-серверы", "dns"), ("MAC-адрес", "mac"),
                           ("Скорость линка", "link"), ("DHCP", "dhcp")):
            _kv_row(lay, label, data.get(key, ""))
        lay.addStretch()

        close = QPushButton("Закрыть")
        close.clicked.connect(self.accept)
        lay.addWidget(close)


class DnsInfoDialog(QDialog):
    """Текущие DNS-серверы по адаптерам + подсказка об утечке."""

    def __init__(self, parent, rows: list[dict], exit_loc: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Текущий DNS")
        self.setStyleSheet(theme.STYLE)
        self.resize(520, 420)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        status, text = self._verdict(rows)
        _banner(lay, status, text)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        host = QWidget()
        col = QVBoxLayout(host)
        col.setSpacing(6)
        col.setContentsMargins(0, 0, 0, 0)
        for r in rows:
            col.addWidget(self._row(r))
        col.addStretch()
        scroll.setWidget(host)
        lay.addWidget(scroll, 1)

        close = QPushButton("Закрыть")
        close.clicked.connect(self.accept)
        lay.addWidget(close)

    @staticmethod
    def _verdict(rows: list[dict]) -> tuple[str, str]:
        if not rows:
            return WARN, ("DNS-серверы не заданы явно (получаются от роутера/DHCP "
                          "или туннеля). Обычно это норма.")
        all_srv = [s for r in rows for s in r["servers"]]
        public = [s for s in all_srv if s in PUBLIC_DNS]
        if public:
            names = sorted({PUBLIC_DNS[s] for s in public})
            return OK, ("Используются публичные DNS: " + ", ".join(names) +
                        ". Если ты на VPN и DNS-запросы должны идти внутри "
                        "туннеля — публичный DNS может означать утечку DNS. "
                        "Проверь настройки VPN-клиента (Block outside DNS).")
        return OK, "DNS заданы вручную. Утечки по публичным резолверам не видно."

    def _row(self, r: dict) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        h = QVBoxLayout(card)
        h.setContentsMargins(12, 9, 12, 9)
        h.setSpacing(2)
        name = QLabel(f"<b>{r['iface']}</b>")
        name.setTextFormat(Qt.TextFormat.RichText)
        h.addWidget(name)
        srv = QLabel(", ".join(r["servers"]))
        srv.setStyleSheet(f"color:{theme.C_MUTED}; font-family:Consolas,monospace;")
        srv.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        srv.setWordWrap(True)
        h.addWidget(srv)
        return card


class ConnectionsDialog(QDialog):
    """Активные TCP-соединения с именем процесса и удалённым адресом."""

    def __init__(self, parent, rows: list[dict]):
        super().__init__(parent)
        self.setWindowTitle("Активные соединения")
        self.setStyleSheet(theme.STYLE)
        self.resize(640, 520)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        head = QLabel(f"Установленных внешних TCP-соединений: <b>{len(rows)}</b>. "
                      "Смотри, какие процессы куда подключены.")
        head.setTextFormat(Qt.TextFormat.RichText)
        head.setWordWrap(True)
        head.setStyleSheet(f"color:{theme.C_MUTED};")
        lay.addWidget(head)

        if not rows:
            info = QLabel("Внешних соединений не найдено.")
            info.setStyleSheet(f"color:{theme.C_FAINT}; padding:24px;")
            info.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(info, 1)
        else:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            hostw = QWidget()
            col = QVBoxLayout(hostw)
            col.setSpacing(6)
            col.setContentsMargins(0, 0, 0, 0)
            for r in rows:
                col.addWidget(self._row(r))
            col.addStretch()
            scroll.setWidget(hostw)
            lay.addWidget(scroll, 1)

        close = QPushButton("Закрыть")
        close.clicked.connect(self.accept)
        lay.addWidget(close)

    def _row(self, r: dict) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        h = QHBoxLayout(card)
        h.setContentsMargins(12, 8, 12, 8)
        h.setSpacing(10)
        left = QLabel(f"<b>{r['name']}</b>  "
                      f"<span style='color:{theme.C_FAINT}'>PID {r['pid']}</span>")
        left.setTextFormat(Qt.TextFormat.RichText)
        h.addWidget(left, 1)
        remote = QLabel(r["remote"])
        remote.setStyleSheet(f"color:{theme.C_TEXT}; font-family:Consolas,monospace; "
                             f"font-size:12px;")
        remote.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        h.addWidget(remote)
        return card


class SettingsDialog(QDialog):
    """Настройки: тема, акцент, хост по умолчанию для «Пинг хоста», период.

    Тема и акцент применяются на лету при сохранении (без перезапуска).
    result_value = {'saved': True} после сохранения.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setStyleSheet(theme.STYLE)
        self.resize(420, 320)
        self.result_value = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        two = QHBoxLayout()
        two.setSpacing(10)
        theme_col = QVBoxLayout()
        theme_col.setSpacing(4)
        theme_col.addWidget(QLabel("Тема оформления:"))
        self.combo_theme = QComboBox()
        self.combo_theme.addItem("Тёмная", "dark")
        self.combo_theme.addItem("Светлая", "light")
        self.combo_theme.setCurrentIndex(
            1 if settings.get("theme") == "light" else 0)
        theme_col.addWidget(self.combo_theme)
        two.addLayout(theme_col, 1)

        accent_col = QVBoxLayout()
        accent_col.setSpacing(4)
        accent_col.addWidget(QLabel("Акцентный цвет:"))
        self.combo_accent = QComboBox()
        for key, label in theme.ACCENT_LABELS.items():
            self.combo_accent.addItem(label, key)
        cur_accent = settings.get("accent")
        idx = self.combo_accent.findData(cur_accent)
        self.combo_accent.setCurrentIndex(idx if idx >= 0 else 0)
        accent_col.addWidget(self.combo_accent)
        two.addLayout(accent_col, 1)
        lay.addLayout(two)

        note = QLabel("Тема и акцент применяются сразу — перезапуск не нужен.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{theme.C_FAINT}; font-size:11px;")
        lay.addWidget(note)

        lay.addWidget(QLabel("Хост по умолчанию для «Пинг хоста»:"))
        self.edit_host = QLineEdit(settings.get("ping_host"))
        lay.addWidget(self.edit_host)

        lay.addWidget(QLabel("Период проверки мониторингом (сек):"))
        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(5, 600)
        self.spin_interval.setSingleStep(5)
        self.spin_interval.setValue(int(settings.get("monitor_interval") or 20))
        self.spin_interval.setToolTip("Как часто фоновый мониторинг проверяет "
                                      "связь. Реже — меньше внешних запросов. "
                                      "Применится при следующем включении "
                                      "мониторинга.")
        lay.addWidget(self.spin_interval)

        lay.addStretch()
        row = QHBoxLayout()
        row.addStretch()
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(self.reject)
        save = QPushButton("Сохранить")
        save.setObjectName("primary")
        save.clicked.connect(self._save)
        row.addWidget(cancel)
        row.addWidget(save)
        lay.addLayout(row)

    def _save(self) -> None:
        host = self.edit_host.text().strip()
        if host and not valid_host(host):
            QMessageBox.warning(self, "Настройки", "Некорректный хост для пинга.")
            return
        if host:
            settings.set("ping_host", host)
        settings.set("monitor_interval", int(self.spin_interval.value()))
        # тема/акцент — на лету (обновит настройки и перерисует окно-подписчик)
        theme.set_appearance(name=self.combo_theme.currentData(),
                             accent=self.combo_accent.currentData())
        self.result_value = {"saved": True}
        self.accept()


def _banner(lay: QVBoxLayout, status: str, text: str) -> None:
    """Цветная плашка-вывод по статусу (восстановлена для новых диалогов)."""
    c = {OK: theme.CLR_OK, WARN: theme.CLR_WARN, BAD: theme.CLR_BAD}.get(status, theme.C_MUTED)
    banner = QLabel(text)
    banner.setWordWrap(True)
    banner.setStyleSheet(
        f"background:{theme._rgba(c, 0.10)}; border:1px solid {theme._rgba(c, 0.33)}; "
        f"border-radius:12px; padding:12px 14px; color:{c}; font-weight:600;")
    lay.addWidget(banner)
