# -*- coding: utf-8 -*-
"""Тема оформления: тёмная и светлая палитры, стили Qt, иконка, спиннер.

Активная тема выбирается при импорте по настройке settings.get('theme').
Смена темы применяется после перезапуска (константы захватываются на импорте).
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF
from PyQt6.QtGui import (
    QBrush, QColor, QIcon, QLinearGradient, QPainter, QPen, QPixmap,
)
from PyQt6.QtWidgets import QFrame, QWidget

from .core import OK, WARN, BAD, INFO
from . import settings


def _rgba(hex_color: str, alpha: float) -> str:
    """'#rrggbb' + прозрачность → строка rgba() для Qt-стилей.
    (Qt трактует 8-значный hex как #AARRGGBB, поэтому нельзя просто дописать
    альфу в конец — используем rgba().)"""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


# --- Палитры ---------------------------------------------------------------
# Мягкая тёмная (сине-сливовая) и светлая (тёплая, низкоконтрастная).
_DARK = {
    "bg1": "#1d1a28", "bg2": "#17141f",
    "text": "#e8e5f2", "muted": "#948eaa", "faint": "#6b6681", "title": "#f0edf8",
    "ok": "#9ad9b8", "warn": "#e6c893", "bad": "#e2a0ac",
    "info": "#a6b6ec", "busy": "#b0a3e8",
    "btn_bg": "#262231", "btn_border": "#332f42", "btn_hover_bg": "#2f2a3d",
    "btn_hover_border": "#4a4560", "btn_pressed": "#25212f",
    "btn_dis_text": "#5f5a72", "btn_dis_bg": "#201d28", "btn_dis_border": "#2a2733",
    "primary1": "#a294dd", "primary2": "#8f80cc", "primary_text": "#1c1826",
    "primary_h1": "#b0a3e8", "primary_h2": "#9a8bd6",
    "danger_bg": "#33222b", "danger_border": "#6a4753", "danger_text": "#e2a0ac",
    "danger_h_bg": "#3e2a34", "danger_h_border": "#855764",
    "card_bg": "#221f2d", "card_border": "#2c2938",
    "card_h_border": "#3a3550", "card_h_bg": "#262233",
    "hline": "#272433", "accent": "#a294dd", "accent_soft": "#cdc1f2",
    "input_bg": "#151220", "input_text": "#b6b0ca", "input_border": "#2a2735",
    "combo_view_bg": "#221f2d", "combo_sel": "#3a3550",
    "tooltip_bg": "#2a2636", "tooltip_border": "#45405a",
    "scroll": "#37324a", "scroll_h": "#494360",
    "icon_grad1": "#2b2542", "icon_grad2": "#1b1830",
}

_LIGHT = {
    "bg1": "#f4f2fb", "bg2": "#e9e6f5",
    "text": "#2b2740", "muted": "#5f5a72", "faint": "#8b86a0", "title": "#241f38",
    "ok": "#2f8f66", "warn": "#a9791f", "bad": "#c05463",
    "info": "#4f63b8", "busy": "#6d5fae",
    "btn_bg": "#ffffff", "btn_border": "#d7d2e6", "btn_hover_bg": "#f0edf8",
    "btn_hover_border": "#b7afd2", "btn_pressed": "#e6e1f2",
    "btn_dis_text": "#a9a4bd", "btn_dis_bg": "#efedf5", "btn_dis_border": "#e0dcec",
    "primary1": "#8f80cc", "primary2": "#7b6bbd", "primary_text": "#ffffff",
    "primary_h1": "#9a8bd6", "primary_h2": "#8676c9",
    "danger_bg": "#fbe9ec", "danger_border": "#e2a9b2", "danger_text": "#b04050",
    "danger_h_bg": "#f6dbe0", "danger_h_border": "#d090a0",
    "card_bg": "#ffffff", "card_border": "#e4e0ef",
    "card_h_border": "#c9c2e0", "card_h_bg": "#faf9fd",
    "hline": "#e0dcec", "accent": "#7b6bbd", "accent_soft": "#5b4f92",
    "input_bg": "#ffffff", "input_text": "#3a3552", "input_border": "#d7d2e6",
    "combo_view_bg": "#ffffff", "combo_sel": "#e6e1f2",
    "tooltip_bg": "#2a2636", "tooltip_border": "#45405a",
    "scroll": "#cdc7de", "scroll_h": "#b3abcc",
    "icon_grad1": "#2b2542", "icon_grad2": "#1b1830",
}


def _build_style(p: dict) -> str:
    """Собрать QSS из палитры p."""
    acc = _rgba(p["accent"], 0.22)
    acc_soft = _rgba(p["accent"], 0.12)
    return f"""
QMainWindow, QDialog {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {p['bg1']}, stop:1 {p['bg2']});
    color: {p['text']};
}}
QWidget {{ color: {p['text']}; }}
QLabel#title {{ font-size: 21px; font-weight: 700; color: {p['title']};
               letter-spacing: 0.3px; }}
QLabel#subtitle {{ color: {p['muted']}; }}
QLabel#adminBad {{ color: {p['warn']}; }}
QLabel#adminOk {{ color: {p['ok']}; }}
QPushButton {{
    background: {p['btn_bg']}; color: {p['text']}; border: 1px solid {p['btn_border']};
    border-radius: 11px; padding: 11px 14px; font-size: 13px;
}}
QPushButton:hover {{ background: {p['btn_hover_bg']}; border-color: {p['btn_hover_border']}; }}
QPushButton:pressed {{ background: {p['btn_pressed']}; }}
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
QPushButton#danger {{
    background: {p['danger_bg']}; border: 1px solid {p['danger_border']};
    color: {p['danger_text']};
}}
QPushButton#danger:hover {{ background: {p['danger_h_bg']};
                           border-color: {p['danger_h_border']}; }}
QFrame#card {{ background: {p['card_bg']}; border: 1px solid {p['card_border']};
              border-radius: 12px; }}
QFrame#card:hover {{ border-color: {p['card_h_border']}; background: {p['card_h_bg']}; }}
QFrame#hline {{ background: {p['hline']}; border: none; max-height: 1px; }}
QPushButton#toggle:checked {{
    background: {acc}; border-color: {p['accent']};
    color: {p['accent_soft']}; font-weight: 600;
}}
QLabel#section {{ color: {p['muted']}; font-weight: 600; letter-spacing: 0.6px; }}
QPushButton#link {{
    background: transparent; border: none; color: {p['muted']};
    padding: 2px 8px; font-size: 12px; border-radius: 6px;
}}
QPushButton#link:hover {{ color: {p['accent_soft']}; background: {acc_soft}; }}
QPlainTextEdit {{
    background: {p['input_bg']}; color: {p['input_text']};
    border: 1px solid {p['input_border']};
    border-radius: 10px; font-family: Consolas, monospace;
    font-size: 12px; padding: 6px;
}}
QScrollArea {{ border: none; background: transparent; }}
QComboBox {{
    background: {p['btn_bg']}; border: 1px solid {p['btn_border']}; border-radius: 8px;
    padding: 7px 10px; color: {p['text']};
}}
QComboBox:hover {{ border-color: {p['btn_hover_border']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {p['combo_view_bg']}; color: {p['text']};
    border: 1px solid {p['btn_border']};
    border-radius: 8px; selection-background-color: {p['combo_sel']}; outline: none;
}}
QToolTip {{
    background: {p['tooltip_bg']}; color: #e8e5f2; border: 1px solid {p['tooltip_border']};
    border-radius: 6px; padding: 5px 7px;
}}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {p['scroll']}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {p['scroll_h']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
"""


# --- Активная палитра (выбирается по настройке при импорте) ---
_PALETTE = _LIGHT if settings.get("theme") == "light" else _DARK

C_TEXT = _PALETTE["text"]
C_MUTED = _PALETTE["muted"]
C_FAINT = _PALETTE["faint"]
C_TITLE = _PALETTE["title"]
CLR_OK = _PALETTE["ok"]
CLR_WARN = _PALETTE["warn"]
CLR_BAD = _PALETTE["bad"]
CLR_INFO = _PALETTE["info"]
CLR_BUSY = _PALETTE["busy"]

STYLE = _build_style(_PALETTE)

ICONS = {OK: ("✓", CLR_OK), WARN: ("•", CLR_WARN),
         BAD: ("✕", CLR_BAD), INFO: ("i", CLR_INFO)}


def hline() -> QFrame:
    """Тонкая горизонтальная линия-разделитель между секциями."""
    line = QFrame()
    line.setObjectName("hline")
    line.setFixedHeight(1)
    return line


def make_app_icon() -> QIcon:
    """Нарисовать мягкую иконку в тон темы (сигнал + точка)."""
    size = 256
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    grad = QLinearGradient(0, 0, 0, size)
    grad.setColorAt(0, QColor("#2b2542"))
    grad.setColorAt(1, QColor("#1b1830"))
    p.setBrush(QBrush(grad))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(8, 8, size - 16, size - 16, 54, 54)

    cx, cy = size // 2, int(size * 0.62)
    pen = QPen(QColor("#b0a3e8"))
    pen.setWidth(16)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    for r in (44, 84, 124):
        p.drawArc(QRectF(cx - r, cy - r, 2 * r, 2 * r), 42 * 16, 96 * 16)

    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#9ad9b8"))
    p.drawEllipse(QPointF(cx, cy), 13, 13)
    p.end()
    return QIcon(pm)


class Spinner(QWidget):
    """Маленький крутящийся индикатор для состояния «идёт проверка»."""

    def __init__(self, size: int = 20, color: str = CLR_BUSY):
        super().__init__()
        self._angle = 0
        self._color = QColor(color)
        self.setFixedSize(size, size)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.hide()

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
