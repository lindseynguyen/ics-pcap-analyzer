"""
OT PCAP Analyzer - small modern UI components
=============================================
Cards, KPI tiles, painted bar lists and pills. All colours are read from the
active theme at paint time, so they follow the light/dark switch.
"""
from typing import Iterable, List, Optional, Tuple

from PyQt5.QtCore import QRectF, QSize, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QPainter
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from .gui_style import ENGINE, token

SEVERITY_TOKEN = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class Card(QFrame):
    """Rounded surface with a title row and a body layout."""

    def __init__(self, title: str = "", subtitle: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(10)
        self.header = QHBoxLayout()
        self.header.setSpacing(8)
        if title:
            self.title_label = QLabel(title.upper())
            self.title_label.setObjectName("SectionTitle")
            self.header.addWidget(self.title_label)
        self.header.addStretch()
        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("Muted")
            self.header.addWidget(sub)
        outer.addLayout(self.header)
        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        outer.addLayout(self.body, 1)


class KpiCard(QFrame):
    """Large number with a label, a coloured accent dot and a caption."""
    clicked = pyqtSignal()

    def __init__(self, label: str, accent: str = "accent", caption: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.accent = accent
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(104)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(4)
        top = QHBoxLayout()
        self.dot = QLabel("●")
        top.addWidget(self.dot)
        name = QLabel(label.upper())
        name.setObjectName("SectionTitle")
        top.addWidget(name)
        top.addStretch()
        lay.addLayout(top)
        self.value_label = QLabel("–")
        self.value_label.setObjectName("ValueLarge")
        lay.addWidget(self.value_label)
        self.caption_label = QLabel(caption)
        self.caption_label.setObjectName("Muted")
        lay.addWidget(self.caption_label)
        self.update_theme()

    def set_value(self, value, caption: Optional[str] = None):
        self.value_label.setText(str(value))
        if caption is not None:
            self.caption_label.setText(caption)

    def update_theme(self):
        self.dot.setStyleSheet(f"color: {token(self.accent)}; font-size: 10px;")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class Pill(QLabel):
    """Small rounded status label tinted with a semantic colour."""

    def __init__(self, text: str = "", tone: str = "accent", parent=None):
        super().__init__(text, parent)
        self.tone = tone
        self.setFixedHeight(26)
        self.setAlignment(Qt.AlignCenter)
        self.update_theme()

    def set(self, text: str, tone: str):
        self.tone = tone
        self.setText(text)
        self.update_theme()

    def update_theme(self):
        self.setStyleSheet(
            f"background-color: {ENGINE.tint(self.tone)}; color: {token(self.tone)};"
            "border-radius: 12px; padding: 0 12px; font-weight: 600; font-size: 12px;")


class BarList(QWidget):
    """Horizontal bars (label · bar · value), painted with theme colours.

    ``rows`` is a list of ``(label, value, token_name)``.
    """
    ROW_H = 30

    def __init__(self, empty_text: str = "No data yet", max_rows: int = 8, parent=None):
        super().__init__(parent)
        self.rows: List[Tuple[str, float, str]] = []
        self.empty_text = empty_text
        self.max_rows = max_rows
        self.value_format = "{:,.0f}"
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def set_rows(self, rows: Iterable[Tuple[str, float, str]]):
        self.rows = list(rows)[: self.max_rows]
        self.updateGeometry()
        self.update()

    def sizeHint(self):
        return QSize(320, max(len(self.rows), 3) * self.ROW_H + 4)

    def minimumSizeHint(self):
        return QSize(200, 3 * self.ROW_H)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        font = QFont(self.font())
        p.setFont(font)
        fm = QFontMetrics(font)
        w = self.width()
        if not self.rows:
            p.setPen(QColor(token("text_3")))
            p.drawText(self.rect(), Qt.AlignCenter, self.empty_text)
            return
        label_w = min(int(w * 0.42), max(fm.horizontalAdvance(r[0]) for r in self.rows) + 12)
        value_w = max(fm.horizontalAdvance(self.value_format.format(r[1])) for r in self.rows) + 12
        bar_x, bar_w = label_w, max(w - label_w - value_w, 20)
        peak = max((r[1] for r in self.rows), default=1) or 1
        track = QColor(token("surface_2"))
        for i, (label, value, tone) in enumerate(self.rows):
            y = i * self.ROW_H
            text_rect = QRectF(0, y, label_w - 8, self.ROW_H)
            p.setPen(QColor(token("text_2")))
            p.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft,
                       fm.elidedText(label, Qt.ElideRight, int(text_rect.width())))
            bar_rect = QRectF(bar_x, y + self.ROW_H / 2 - 4, bar_w, 8)
            p.setPen(Qt.NoPen)
            p.setBrush(track)
            p.drawRoundedRect(bar_rect, 4, 4)
            fill = QRectF(bar_rect)
            fill.setWidth(max(bar_w * (value / peak), 6 if value else 0))
            p.setBrush(QColor(token(tone)))
            p.drawRoundedRect(fill, 4, 4)
            p.setPen(QColor(token("text")))
            p.drawText(QRectF(bar_x + bar_w, y, value_w, self.ROW_H),
                       Qt.AlignVCenter | Qt.AlignRight, self.value_format.format(value))


class KeyValueList(QWidget):
    """Two-column list of facts (label on the left, value on the right)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(0)

    def set_items(self, items: Iterable[Tuple[str, str]]):
        while self._lay.count():
            it = self._lay.takeAt(0)
            w = it.widget()
            if w is not None:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        for label, value in items:
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 7, 0, 7)
            k = QLabel(label)
            k.setObjectName("Muted")
            v = QLabel(str(value))
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            v.setWordWrap(True)
            v.setTextFormat(Qt.PlainText)
            rl.addWidget(k)
            rl.addWidget(v, 1)
            self._lay.addWidget(row)
        self._lay.addStretch()


_ACRONYMS = {"IT", "OT", "ICS", "HTTP", "HTTPS", "DNS", "SMB", "RDP", "SSH", "ARP", "TCP", "UDP", "ICMP",
             "PLC", "HMI", "RTU", "S7", "S7COMM", "DNP3", "CIP", "ENIP", "OPC", "UA", "MQTT", "IEC104",
             "SQL", "XSS", "C2", "IOC", "ML", "TLS", "FTP", "NTLM", "LDAP", "SNMP", "BACNET", "MITM", "DOS"}


def pretty_type(value) -> str:
    """'IT_LATERAL_MOVEMENT' -> 'IT Lateral Movement' (keeps protocol acronyms)."""
    words = str(value).replace("-", "_").split("_")
    return " ".join(w if w.upper() in _ACRONYMS and (w.upper() == w) else w.capitalize()
                    for w in words if w) or str(value)


def short_time(ts) -> str:
    """UTC timestamp without microseconds / offset, e.g. '2026-01-01 00:00:22'."""
    from datetime import datetime
    from .utils import utc_str
    if isinstance(ts, datetime):
        text = ts.strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(ts, str):
        text = ts
    else:
        text = utc_str(ts)
    return text[:19] if len(text) >= 19 else text


def severity_item(severity: str):
    """QTableWidgetItem coloured by severity (bold text)."""
    from PyQt5.QtWidgets import QTableWidgetItem
    item = QTableWidgetItem(severity)
    item.setForeground(QColor(token(SEVERITY_TOKEN.get(str(severity).upper(), "text_3"))))
    f = item.font()
    f.setBold(True)
    item.setFont(f)
    return item
