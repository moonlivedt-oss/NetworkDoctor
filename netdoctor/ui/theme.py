# -*- coding: utf-8 -*-
"""Тема оформления: живой движок тем, палитры, акценты, стили Qt, иконка, спиннер.

Тема и акцент выбираются по настройкам ('theme', 'accent'), но, в отличие от
прежней версии, применяются НА ЛЕТУ: модульные константы (C_TEXT, STYLE, ICONS…)
переприсваиваются при смене темы, поэтому потребители должны обращаться к ним
через модуль (``theme.C_TEXT``), а не захватывать имена при импорте.

Смена темы:
    theme.set_appearance(name='light', accent='blue')  # обновит палитру и стили
    theme.subscribe(callback)  # окно перерисует динамические (inline) стили
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF
from PyQt6.QtGui import (
    QBrush, QColor, QIcon, QLinearGradient, QPainter, QPen, QPixmap,
)
from PyQt6.QtWidgets import QFrame, QWidget

from ..core import OK, WARN, BAD, INFO
from .. import settings


def _rgba(hex_color: str, alpha: float) -> str:
    """'#rrggbb' + прозрачность → строка rgba() для Qt-стилей.
    (Qt трактует 8-значный hex как #AARRGGBB, поэтому нельзя просто дописать
    альфу в конец — используем rgba().)"""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


# --- Базовые палитры (нейтральные, без акцента) ----------------------------
# Акцентные цвета (кнопка primary, тумблеры, ссылки) наложатся сверху из ACCENTS.
_DARK = {
    "bg1": "#1d1a28", "bg2": "#17141f",
    "text": "#e8e5f2", "muted": "#948eaa", "faint": "#6b6681", "title": "#f0edf8",
    "ok": "#9ad9b8", "warn": "#e6c893", "bad": "#e2a0ac", "info": "#a6b6ec",
    "btn_bg": "#262231", "btn_border": "#332f42", "btn_hover_bg": "#2f2a3d",
    "btn_hover_border": "#4a4560", "btn_pressed": "#25212f",
    "btn_dis_text": "#5f5a72", "btn_dis_bg": "#201d28", "btn_dis_border": "#2a2733",
    "primary_text": "#1c1826",
    "danger_bg": "#33222b", "danger_border": "#6a4753", "danger_text": "#e2a0ac",
    "danger_h_bg": "#3e2a34", "danger_h_border": "#855764", "danger_pressed": "#2c1d25",
    "card_bg": "#221f2d", "card_border": "#2c2938",
    "card_h_border": "#3a3550", "card_h_bg": "#262233",
    "hline": "#272433",
    "input_bg": "#151220", "input_text": "#b6b0ca", "input_border": "#2a2735",
    "combo_view_bg": "#221f2d", "combo_sel": "#3a3550",
    "tooltip_bg": "#2a2636", "tooltip_text": "#e8e5f2", "tooltip_border": "#45405a",
    "scroll": "#37324a", "scroll_h": "#494360",
    "strip_bg": "#1a1724", "strip_border": "#2a2636",
    "icon_grad1": "#2b2542", "icon_grad2": "#1b1830",
}

_LIGHT = {
    "bg1": "#f4f2fb", "bg2": "#e9e6f5",
    "text": "#2b2740", "muted": "#5f5a72", "faint": "#8b86a0", "title": "#241f38",
    "ok": "#2f8f66", "warn": "#a9791f", "bad": "#c05463", "info": "#4f63b8",
    "btn_bg": "#ffffff", "btn_border": "#d7d2e6", "btn_hover_bg": "#f0edf8",
    "btn_hover_border": "#b7afd2", "btn_pressed": "#e6e1f2",
    "btn_dis_text": "#a9a4bd", "btn_dis_bg": "#efedf5", "btn_dis_border": "#e0dcec",
    "primary_text": "#ffffff",
    "danger_bg": "#fbe9ec", "danger_border": "#e2a9b2", "danger_text": "#b04050",
    "danger_h_bg": "#f6dbe0", "danger_h_border": "#d090a0", "danger_pressed": "#f0cdd4",
    "card_bg": "#ffffff", "card_border": "#e4e0ef",
    "card_h_border": "#c9c2e0", "card_h_bg": "#faf9fd",
    "hline": "#e0dcec",
    "input_bg": "#ffffff", "input_text": "#3a3552", "input_border": "#d7d2e6",
    "combo_view_bg": "#ffffff", "combo_sel": "#e6e1f2",
    "tooltip_bg": "#2a2636", "tooltip_text": "#f0edf8", "tooltip_border": "#45405a",
    "scroll": "#cdc7de", "scroll_h": "#b3abcc",
    "strip_bg": "#efecf8", "strip_border": "#e0dcec",
    "icon_grad1": "#2b2542", "icon_grad2": "#1b1830",
}


# --- Акценты (наложение поверх базовой палитры) -----------------------------
# Для каждого акцента — вариант под тёмную и под светлую тему.
ACCENTS: dict[str, dict[str, dict]] = {
    "violet": {
        "dark": {"primary1": "#a294dd", "primary2": "#8f80cc",
                 "primary_h1": "#b0a3e8", "primary_h2": "#9a8bd6",
                 "primary_pressed": "#8676c9",
                 "accent": "#a294dd", "accent_soft": "#cdc1f2", "busy": "#b0a3e8"},
        "light": {"primary1": "#8f80cc", "primary2": "#7b6bbd",
                  "primary_h1": "#9a8bd6", "primary_h2": "#8676c9",
                  "primary_pressed": "#6d5fae",
                  "accent": "#7b6bbd", "accent_soft": "#5b4f92", "busy": "#6d5fae"},
    },
    "blue": {
        "dark": {"primary1": "#7ea6e8", "primary2": "#6a90d8",
                 "primary_h1": "#90b4ef", "primary_h2": "#7ba0e2",
                 "primary_pressed": "#6488cf",
                 "accent": "#7ea6e8", "accent_soft": "#bcd2f5", "busy": "#8fb4f0"},
        "light": {"primary1": "#5a86d8", "primary2": "#4a72c4",
                  "primary_h1": "#6a94e0", "primary_h2": "#5580cf",
                  "primary_pressed": "#3f63b8",
                  "accent": "#3f63b8", "accent_soft": "#33518f", "busy": "#4f63b8"},
    },
    "teal": {
        "dark": {"primary1": "#5fc6b4", "primary2": "#49b0a0",
                 "primary_h1": "#74d3c2", "primary_h2": "#57bdac",
                 "primary_pressed": "#45a898",
                 "accent": "#5fc6b4", "accent_soft": "#b6ece2", "busy": "#74d3c2"},
        "light": {"primary1": "#2f9f8c", "primary2": "#1f8a78",
                  "primary_h1": "#3aab98", "primary_h2": "#279684",
                  "primary_pressed": "#177466",
                  "accent": "#1f8a78", "accent_soft": "#17685a", "busy": "#1f8a78"},
    },
    "emerald": {
        "dark": {"primary1": "#5fce8f", "primary2": "#46b978",
                 "primary_h1": "#74d89f", "primary_h2": "#55c488",
                 "primary_pressed": "#3fa96c",
                 "accent": "#5fce8f", "accent_soft": "#bceccd", "busy": "#74d89f"},
        "light": {"primary1": "#2f9f63", "primary2": "#1f8a52",
                  "primary_h1": "#3aab6f", "primary_h2": "#27965c",
                  "primary_pressed": "#17743f",
                  "accent": "#1f8a52", "accent_soft": "#176840", "busy": "#1f8a52"},
    },
    "amber": {
        "dark": {"primary1": "#e3b563", "primary2": "#d0a045",
                 "primary_h1": "#edc47a", "primary_h2": "#d8ab52",
                 "primary_pressed": "#c6963f",
                 "accent": "#e3b563", "accent_soft": "#f2e0b6", "busy": "#edc47a"},
        "light": {"primary1": "#b5842f", "primary2": "#9f7220",
                  "primary_h1": "#c2923c", "primary_h2": "#ab7e28",
                  "primary_pressed": "#8a6218",
                  "accent": "#9f7220", "accent_soft": "#7a5716", "busy": "#9f7220"},
    },
    "rose": {
        "dark": {"primary1": "#e090ac", "primary2": "#cf7a9a",
                 "primary_h1": "#ec9dbb", "primary_h2": "#d886a6",
                 "primary_pressed": "#c67493",
                 "accent": "#e090ac", "accent_soft": "#f5cdda", "busy": "#ec9dbb"},
        "light": {"primary1": "#cf6f92", "primary2": "#bd5a80",
                  "primary_h1": "#d97f9f", "primary_h2": "#c76a8c",
                  "primary_pressed": "#a83f63",
                  "accent": "#b8496e", "accent_soft": "#8f3a56", "busy": "#b8496e"},
    },
}

# Человекочитаемые названия акцентов (для настроек / всплывающих подсказок).
# Порядок — по спектру (для свотчей в шапке и списка в настройках).
ACCENT_LABELS = {"violet": "Фиолетовый", "blue": "Синий", "teal": "Бирюзовый",
                 "emerald": "Изумрудный", "amber": "Янтарный", "rose": "Розовый"}


def _compose(name: str, accent: str) -> dict:
    """Собрать полную палитру: базовая тема + наложенный акцент."""
    mode = "light" if name == "light" else "dark"
    base = dict(_LIGHT if mode == "light" else _DARK)
    acc = ACCENTS.get(accent) or ACCENTS["violet"]
    base.update(acc[mode])
    return base


def _build_style(p: dict) -> str:
    """Собрать QSS из палитры p."""
    acc = _rgba(p["accent"], 0.22)
    acc_soft = _rgba(p["accent"], 0.12)
    focus = _rgba(p["accent"], 0.55)
    return f"""
QMainWindow, QDialog {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {p['bg1']}, stop:1 {p['bg2']});
    color: {p['text']};
}}
QWidget {{ color: {p['text']}; }}
QLabel#title {{ font-size: 22px; font-weight: 700; color: {p['title']};
               letter-spacing: 0.3px; }}
QLabel#subtitle {{ color: {p['muted']}; }}
QLabel#adminBad {{ color: {p['warn']}; }}
QLabel#adminOk {{ color: {p['ok']}; }}
QPushButton {{
    background: {p['btn_bg']}; color: {p['text']}; border: 1px solid {p['btn_border']};
    border-radius: 11px; padding: 11px 14px; font-size: 13px; outline: none;
    min-height: 18px;  /* нижний предел высоты — подпись никогда не обрежется */
}}
QPushButton:hover {{ background: {p['btn_hover_bg']}; border-color: {p['btn_hover_border']}; }}
QPushButton:pressed {{ background: {p['btn_pressed']}; }}
QPushButton:focus {{ border-color: {focus}; }}
QPushButton:disabled {{ color: {p['btn_dis_text']}; background: {p['btn_dis_bg']};
                       border-color: {p['btn_dis_border']}; }}
QPushButton#primary {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {p['primary1']}, stop:1 {p['primary2']});
    border: 1px solid {p['primary1']}; color: {p['primary_text']}; font-weight: 600;
}}
QPushButton#primary:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {p['primary_h1']}, stop:1 {p['primary_h2']});
}}
QPushButton#primary:pressed {{ background: {p['primary_pressed']}; }}
QPushButton#danger {{
    background: {p['danger_bg']}; border: 1px solid {p['danger_border']};
    color: {p['danger_text']};
}}
QPushButton#danger:hover {{ background: {p['danger_h_bg']};
                           border-color: {p['danger_h_border']}; }}
QPushButton#danger:pressed {{ background: {p['danger_pressed']}; }}
QFrame#card {{ background: {p['card_bg']}; border: 1px solid {p['card_border']};
              border-radius: 12px; }}
QFrame#card:hover {{ border-color: {p['card_h_border']}; background: {p['card_h_bg']}; }}
QFrame#strip {{ background: {p['strip_bg']}; border: 1px solid {p['strip_border']};
               border-radius: 12px; }}
QFrame#panel {{ background: {p['strip_bg']}; border: 1px solid {p['strip_border']};
               border-radius: 12px; }}
QFrame#hline {{ background: {p['hline']}; border: none; max-height: 1px; }}
QPushButton#toggle {{ padding: 8px 13px; border-radius: 9px; font-size: 12px; }}
QPushButton#toggle:checked {{
    background: {acc}; border-color: {p['accent']};
    color: {p['accent_soft']}; font-weight: 600;
}}
QPushButton#toggle:checked:hover {{ background: {_rgba(p['accent'], 0.30)}; }}
QLabel#section {{ color: {p['muted']}; font-weight: 600; letter-spacing: 0.6px;
                 font-size: 11px; }}
QPushButton#link {{
    background: transparent; border: none; color: {p['muted']};
    padding: 2px 8px; font-size: 12px; border-radius: 6px;
}}
QPushButton#link:hover {{ color: {p['accent_soft']}; background: {acc_soft}; }}
QPushButton#appBtn {{
    background: {p['btn_bg']}; border: 1px solid {p['btn_border']};
    border-radius: 9px; padding: 6px 10px; font-size: 14px; min-width: 16px;
}}
QPushButton#appBtn:hover {{ background: {p['btn_hover_bg']};
                           border-color: {p['btn_hover_border']}; }}
QPlainTextEdit {{
    background: {p['input_bg']}; color: {p['input_text']};
    border: 1px solid {p['input_border']};
    border-radius: 10px; font-family: Consolas, monospace;
    font-size: 12px; padding: 6px;
}}
QScrollArea {{ border: none; background: transparent; }}
QComboBox, QLineEdit, QSpinBox {{
    background: {p['input_bg']}; border: 1px solid {p['input_border']};
    border-radius: 8px; padding: 7px 10px; color: {p['text']};
}}
QComboBox:hover, QLineEdit:hover, QSpinBox:hover {{ border-color: {p['btn_hover_border']}; }}
QComboBox:focus, QLineEdit:focus, QSpinBox:focus {{ border-color: {focus}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {p['combo_view_bg']}; color: {p['text']};
    border: 1px solid {p['btn_border']};
    border-radius: 8px; selection-background-color: {p['combo_sel']}; outline: none;
}}
QToolTip {{
    background: {p['tooltip_bg']}; color: {p['tooltip_text']};
    border: 1px solid {p['tooltip_border']}; border-radius: 6px; padding: 5px 7px;
}}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {p['scroll']}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {p['scroll_h']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
"""


# --- Живое состояние темы ---------------------------------------------------
# Все нижеследующие имена переприсваиваются в _rebuild() при смене темы.
THEME_NAME = "light" if settings.get("theme") == "light" else "dark"
ACCENT_NAME = settings.get("accent") if settings.get("accent") in ACCENTS else "violet"

_PALETTE: dict = {}
PALETTE: dict = {}
C_TEXT = C_MUTED = C_FAINT = C_TITLE = ""
CLR_OK = CLR_WARN = CLR_BAD = CLR_INFO = CLR_BUSY = CLR_ACCENT = ""
STYLE = ""
ICONS: dict = {}

_listeners: list = []


def _rebuild() -> None:
    """Пересобрать активную палитру, константы, QSS и таблицу иконок."""
    global _PALETTE, PALETTE, STYLE, ICONS
    global C_TEXT, C_MUTED, C_FAINT, C_TITLE
    global CLR_OK, CLR_WARN, CLR_BAD, CLR_INFO, CLR_BUSY, CLR_ACCENT
    _PALETTE = PALETTE = _compose(THEME_NAME, ACCENT_NAME)
    C_TEXT = _PALETTE["text"]
    C_MUTED = _PALETTE["muted"]
    C_FAINT = _PALETTE["faint"]
    C_TITLE = _PALETTE["title"]
    CLR_OK = _PALETTE["ok"]
    CLR_WARN = _PALETTE["warn"]
    CLR_BAD = _PALETTE["bad"]
    CLR_INFO = _PALETTE["info"]
    CLR_BUSY = _PALETTE["busy"]
    CLR_ACCENT = _PALETTE["accent"]
    STYLE = _build_style(_PALETTE)
    ICONS = {OK: ("✓", CLR_OK), WARN: ("•", CLR_WARN),
             BAD: ("✕", CLR_BAD), INFO: ("i", CLR_INFO)}


_rebuild()


def subscribe(callback) -> None:
    """Подписать callback на смену темы (окно перерисует inline-стили)."""
    if callback not in _listeners:
        _listeners.append(callback)


def set_appearance(name: str | None = None, accent: str | None = None) -> bool:
    """Сменить тему и/или акцент на лету. Возвращает True, если что-то изменилось.

    Обновляет настройки, пересобирает палитру/стили и уведомляет подписчиков —
    те переприменяют QSS и перерисовывают динамические (inline) стили.
    """
    global THEME_NAME, ACCENT_NAME
    changed = False
    if name is not None:
        name = "light" if name == "light" else "dark"
        if name != THEME_NAME:
            THEME_NAME = name
            settings.set("theme", name)
            changed = True
    if accent is not None and accent in ACCENTS and accent != ACCENT_NAME:
        ACCENT_NAME = accent
        settings.set("accent", accent)
        changed = True
    if changed:
        _rebuild()
        for cb in list(_listeners):
            try:
                cb()
            except Exception:
                pass
    return changed


def hline() -> QFrame:
    """Тонкая горизонтальная линия-разделитель между секциями."""
    line = QFrame()
    line.setObjectName("hline")
    line.setFixedHeight(1)
    return line


def make_app_icon() -> QIcon:
    """Нарисовать мягкую иконку в тон акценту (сигнал + точка)."""
    size = 256
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    grad = QLinearGradient(0, 0, 0, size)
    grad.setColorAt(0, QColor(_PALETTE["icon_grad1"]))
    grad.setColorAt(1, QColor(_PALETTE["icon_grad2"]))
    p.setBrush(QBrush(grad))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(8, 8, size - 16, size - 16, 54, 54)

    cx, cy = size // 2, int(size * 0.62)
    pen = QPen(QColor(_PALETTE["busy"]))
    pen.setWidth(16)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    for r in (44, 84, 124):
        p.drawArc(QRectF(cx - r, cy - r, 2 * r, 2 * r), 42 * 16, 96 * 16)

    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(_PALETTE["ok"]))
    p.drawEllipse(QPointF(cx, cy), 13, 13)
    p.end()
    return QIcon(pm)


class Spinner(QWidget):
    """Маленький крутящийся индикатор для состояния «идёт проверка»."""

    def __init__(self, size: int = 20, color: str | None = None):
        super().__init__()
        self._angle = 0
        self._color = QColor(color or CLR_BUSY)
        self.setFixedSize(size, size)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.hide()

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def start(self) -> None:
        self.show()
        self._timer.start(55)

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def _tick(self) -> None:
        self._angle = (self._angle + 30) % 360
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self._color)
        pen.setWidth(3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        rect = QRectF(3, 3, self.width() - 6, self.height() - 6)
        p.drawArc(rect, -self._angle * 16, 100 * 16)
