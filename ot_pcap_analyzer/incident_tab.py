"""
OT PCAP Analyzer - Incident / Attack Story View Tab
==========================================================================================
DARK MODE SOC DASHBOARD WITH ADVANCED VISUALIZATIONS:
- Navy/Slate dark mode color scheme for reduced eye strain
- Sparkline micro-charts in stat cards showing trends
- Node-Link flowchart timeline with visual connections
- Collapsible accordion sections for better organization
- Interactive action checklists with clickable checkboxes
- Gradient backgrounds and soft shadows throughout
- Improved padding and professional typography
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QGroupBox, QFrame, QScrollArea, QSplitter, QSizePolicy,
    QProgressBar, QCheckBox, QPushButton, QToolButton
)
from PyQt5.QtCore import Qt, pyqtSignal, QSize, QPropertyAnimation, QEasingCurve, QRect
from PyQt5.QtGui import QFont, QColor, QCursor, QLinearGradient, QPainter, QPen, QPainterPath
from PyQt5.QtWidgets import QGraphicsDropShadowEffect

from datetime import datetime
from typing import List, Dict, Optional
import html

from .models import AttackChain, AttackPhase, AttackStoryline
from .storyline import ATTACK_PHASES
from .utils import normalize_timestamp


# =============================================================================
# DARK THEME COLOR PALETTE (SOC Standard - Brighter Edition)
# =============================================================================

DARK_THEME = {
    # Main backgrounds - BRIGHTER for better readability
    "bg_primary": "#1c2128",      # Brighter main background
    "bg_secondary": "#252b33",    # Card backgrounds - more visible
    "bg_tertiary": "#3d444d",     # Elevated surfaces - brighter
    "bg_elevated": "#424a53",     # Borders/dividers - more contrast

    # Text colors (Very bright for better readability)
    "text_primary": "#f0f6fc",    # Primary text - bright white
    "text_secondary": "#e6edf3",  # Secondary text - brighter
    "text_muted": "#a0a8b2",      # Muted text - brighter gray

    # Accent colors (Brighter semantic colors)
    "accent_blue": "#58a6ff",     # Primary accent - bright blue
    "accent_cyan": "#74c0fc",     # Cyan accent
    "accent_green": "#3fb950",    # Normal/Success - bright green
    "accent_amber": "#ffd43b",    # Warning - bright amber
    "accent_red": "#ff6b6b",      # Critical - bright red
    "accent_purple": "#bc8cff",   # Info - bright purple

    # Border colors - more visible
    "border": "#484f58",          # Primary border - brighter
    "border_light": "#6e7681",    # Lighter border - more visible
}

# =============================================================================
# MODERN ICONS (Unicode symbols for better visualization)
# =============================================================================

STAT_ICONS = {
    "chains": "⚡",      # Attack chains
    "ot_impact": "🏭",  # OT Impact
    "critical": "🔴",   # Critical severity
    "storylines": "📖", # Storylines/narratives
    "escalation": "📈"  # OT Escalation
}

PHASE_ICONS = {
    0: "🔍",  # Reconnaissance
    1: "🎯",  # Initial Access
    2: "⚙️",  # Execution
    3: "🔐",  # Persistence
    4: "⬆️",  # Privilege Escalation
    5: "🛡️",  # Defense Evasion
    6: "🔑",  # Credential Access
    7: "🔭",  # Discovery
    8: "➡️",  # Lateral Movement
    9: "📦",  # Collection
    10: "📤", # Exfiltration
    11: "💥", # Impact
}

ACTION_ICONS = {
    "immediate": "🚨",
    "short_term": "⏰",
    "long_term": "📋"
}


# =============================================================================
# CONSTANTS
# =============================================================================

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

SEVERITY_BG = {
    "CRITICAL": "#fde7ea",
    "HIGH": "#fff9e3",
    "MEDIUM": "#e3f0fa",
    "LOW": "#e6f4ea",
}

SEVERITY_TEXT = {
    "CRITICAL": "#dc2626",
    "HIGH": "#d97706",
    "MEDIUM": "#1d4ed8",
    "LOW": "#166534",
}

PHASE_COLORS = {
    0: "#3b82f6", 1: "#8b5cf6", 2: "#ef4444", 3: "#f59e0b",
    4: "#ef4444", 5: "#f59e0b", 6: "#8b5cf6", 7: "#ef4444", 8: "#dc2626",
}

ESCALATION_LEVELS = [
    (0.8, "DANGER - OT escalation", "#fde7ea", "#dc2626"),
    (0.5, "WARNING - OT at risk", "#fff9e3", "#d97706"),
    (0.2, "MONITOR - OT needs monitoring", "#e3f0fa", "#1d4ed8"),
    (0.0, "SAFE - No OT impact yet", "#e6f4ea", "#166534"),
]

# Dark theme GroupBox style
GROUPBOX_STYLE = """
    QGroupBox {
        background-color: #3d444d;
        border: 2px solid #484f58;
        border-radius: 8px;
        margin-top: 16px;
        padding: 16px;
        font-weight: 600;
        font-size: 15px;
        color: #f0f6fc;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 8px;
        color: #f0f6fc;
        background-color: #3d444d;
    }
"""


# =============================================================================
# SPARKLINE WIDGET - Mini Chart for Stats
# =============================================================================

class SparklineWidget(QFrame):
    """
    Mini line chart widget for displaying trends in StatCards.
    Draws a simple sparkline using QPainter.
    """

    def __init__(self, data: List[float] = None, color: str = "#3b82f6", parent=None):
        super().__init__(parent)
        self._data = data or [0, 1, 3, 2, 4, 3, 5, 4, 6, 5]  # Sample data
        self._color = QColor(color)
        self.setFixedSize(60, 28)
        self.setStyleSheet("background: transparent; border: none;")

    def set_data(self, data: List[float], color: str = None):
        """Update sparkline data."""
        self._data = data if data else [0]
        if color:
            self._color = QColor(color)
        self.update()

    def paintEvent(self, event):
        """Draw the sparkline chart."""
        if not self._data or len(self._data) < 2:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        width = self.width() - 4
        height = self.height() - 4
        padding = 2

        # Normalize data to fit height
        min_val = min(self._data)
        max_val = max(self._data)
        range_val = max_val - min_val if max_val != min_val else 1

        # Create gradient for the line
        gradient = QLinearGradient(0, 0, width, 0)
        gradient.setColorAt(0, self._color.lighter(120))
        gradient.setColorAt(1, self._color)

        pen = QPen(gradient, 2)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)

        # Create path for sparkline
        path = QPainterPath()

        for i, val in enumerate(self._data):
            x = padding + (i * width / (len(self._data) - 1))
            y = padding + height - ((val - min_val) / range_val * height)

            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        painter.drawPath(path)

        # Draw endpoint dot
        if self._data:
            last_x = padding + width
            last_y = padding + height - ((self._data[-1] - min_val) / range_val * height)
            painter.setBrush(self._color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(int(last_x) - 3, int(last_y) - 3, 6, 6)


# =============================================================================
# COLLAPSIBLE SECTION WIDGET - Accordion Style
# =============================================================================

class CollapsibleSection(QFrame):
    """
    Collapsible accordion section for organizing content.
    Click header to expand/collapse content.
    """

    def __init__(self, title: str, icon: str = "📁",
                 accent_color: str = "#3b82f6", parent=None):
        super().__init__(parent)
        self._expanded = True
        self._accent = accent_color
        self._animation = None

        self.setObjectName("CollapsibleSection")
        self.setStyleSheet(f"""
            QFrame#CollapsibleSection {{
                background-color: {DARK_THEME['bg_secondary']};
                border: 1px solid {DARK_THEME['border']};
                border-radius: 8px;
                margin: 8px 0;
            }}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header (clickable)
        self.header = QFrame()
        self.header.setCursor(QCursor(Qt.PointingHandCursor))
        self.header.setStyleSheet(f"""
            QFrame {{
                background-color: {DARK_THEME['bg_tertiary']};
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
                padding: 8px 16px;
            }}
            QFrame:hover {{
                background-color: {DARK_THEME['bg_elevated']};
            }}
        """)

        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        header_layout.setSpacing(10)

        # Icon
        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 18px; background: transparent;")
        header_layout.addWidget(icon_label)

        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 14px;
            font-weight: 700;
            color: {DARK_THEME['text_primary']};
            background: transparent;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        """)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        # Toggle arrow
        self.toggle_btn = QLabel("▼")
        self.toggle_btn.setStyleSheet(f"""
            font-size: 12px;
            color: {DARK_THEME['text_secondary']};
            background: transparent;
        """)
        header_layout.addWidget(self.toggle_btn)

        main_layout.addWidget(self.header)

        # Content container
        self.content = QFrame()
        self.content.setStyleSheet(f"""
            QFrame {{
                background-color: {DARK_THEME['bg_secondary']};
                border-bottom-left-radius: 10px;
                border-bottom-right-radius: 10px;
            }}
        """)
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(14, 10, 14, 12)
        self.content_layout.setSpacing(6)

        main_layout.addWidget(self.content)

        # Connect click
        self.header.mousePressEvent = self._toggle

    def _toggle(self, event):
        """Toggle expanded state."""
        self._expanded = not self._expanded
        self.content.setVisible(self._expanded)
        self.toggle_btn.setText("▼" if self._expanded else "▶")

        # Update header border radius based on state
        if self._expanded:
            self.header.setStyleSheet(f"""
                QFrame {{
                    background-color: {DARK_THEME['bg_tertiary']};
                    border-top-left-radius: 8px;
                    border-top-right-radius: 8px;
                    border-bottom-left-radius: 0px;
                    border-bottom-right-radius: 0px;
                }}
                QFrame:hover {{
                    background-color: {DARK_THEME['bg_elevated']};
                }}
            """)
        else:
            self.header.setStyleSheet(f"""
                QFrame {{
                    background-color: {DARK_THEME['bg_tertiary']};
                    border-radius: 8px;
                }}
                QFrame:hover {{
                    background-color: {DARK_THEME['bg_elevated']};
                }}
            """)

    def add_widget(self, widget):
        """Add widget to content area."""
        self.content_layout.addWidget(widget)

    def set_expanded(self, expanded: bool):
        """Set expanded state programmatically."""
        if self._expanded != expanded:
            self._toggle(None)


# =============================================================================
# INTERACTIVE CHECKLIST WIDGET
# =============================================================================

class ActionChecklistItem(QFrame):
    """Single action item with interactive checkbox."""

    toggled = pyqtSignal(bool, str)

    def __init__(self, text: str, priority: str = "normal", parent=None):
        super().__init__(parent)
        self._text = text
        self._checked = False

        # Priority colors
        priority_colors = {
            "urgent": DARK_THEME['accent_red'],
            "high": DARK_THEME['accent_amber'],
            "normal": DARK_THEME['accent_blue'],
            "low": DARK_THEME['accent_green']
        }
        accent = priority_colors.get(priority, DARK_THEME['accent_blue'])

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {DARK_THEME['bg_tertiary']};
                border-left: 3px solid {accent};
                border-radius: 6px;
                margin: 2px 0;
            }}
            QFrame:hover {{
                background-color: {DARK_THEME['bg_elevated']};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        # Checkbox
        self.checkbox = QCheckBox()
        self.checkbox.setStyleSheet(f"""
            QCheckBox {{
                spacing: 5px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {DARK_THEME['text_muted']};
                background-color: transparent;
            }}
            QCheckBox::indicator:hover {{
                border: 2px solid {accent};
            }}
            QCheckBox::indicator:checked {{
                background-color: {accent};
                border: 2px solid {accent};
            }}
        """)
        self.checkbox.toggled.connect(self._on_toggle)
        layout.addWidget(self.checkbox)

        # Text
        self.text_label = QLabel(text)
        self.text_label.setWordWrap(True)
        self.text_label.setStyleSheet(f"""
            font-size: 14px;
            color: {DARK_THEME['text_primary']};
            background: transparent;
        """)
        layout.addWidget(self.text_label, stretch=1)

    def _on_toggle(self, checked: bool):
        """Handle checkbox toggle."""
        self._checked = checked
        # Strike through text if checked
        if checked:
            self.text_label.setStyleSheet(f"""
                font-size: 14px;
                color: {DARK_THEME['text_muted']};
                text-decoration: line-through;
                background: transparent;
            """)
        else:
            self.text_label.setStyleSheet(f"""
                font-size: 14px;
                color: {DARK_THEME['text_primary']};
                background: transparent;
            """)
        self.toggled.emit(checked, self._text)


class ActionChecklist(QFrame):
    """Container for action checklist items with progress indicator."""

    def __init__(self, title: str = "Actions", parent=None):
        super().__init__(parent)
        self._items: List[ActionChecklistItem] = []

        self.setStyleSheet(f"""
            QFrame {{
                background: transparent;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: {DARK_THEME['bg_tertiary']};
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background-color: {DARK_THEME['accent_green']};
                border-radius: 2px;
            }}
        """)
        layout.addWidget(self.progress)

        # Items container
        self.items_layout = QVBoxLayout()
        self.items_layout.setContentsMargins(0, 6, 0, 0)
        self.items_layout.setSpacing(4)
        layout.addLayout(self.items_layout)

    def add_action(self, text: str, priority: str = "normal"):
        """Add an action item."""
        item = ActionChecklistItem(text, priority)
        item.toggled.connect(self._update_progress)
        self.items_layout.addWidget(item)
        self._items.append(item)
        self._update_progress()

    def clear_actions(self):
        """Clear all action items."""
        for item in self._items:
            item.setParent(None)
            item.deleteLater()
        self._items.clear()
        self.progress.setValue(0)

    def _update_progress(self):
        """Update progress bar based on checked items."""
        if not self._items:
            self.progress.setValue(0)
            return
        checked = sum(1 for item in self._items if item._checked)
        self.progress.setMaximum(len(self._items))
        self.progress.setValue(checked)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def _fmt_ts(ts: float) -> str:
    """Format timestamp to readable string with robust error handling."""
    if ts <= 0:
        return "N/A"
    try:
        normalized = normalize_timestamp(ts)
        if normalized is None:
            return "Invalid Time"
        return datetime.fromtimestamp(normalized).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "Time Error"
    except Exception:
        return "??"


def _fmt_ts_short(ts: float) -> str:
    """Format timestamp to short time only."""
    if ts <= 0:
        return "N/A"
    try:
        normalized = normalize_timestamp(ts)
        if normalized is None:
            return "??"
        return datetime.fromtimestamp(normalized).strftime("%H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "??"
    except Exception:
        return "??"


def _escape_html(text: str) -> str:
    """Safely escape HTML special characters."""
    if not text:
        return ""
    return html.escape(str(text))


def _safe_get_attr(obj, attr: str, default=""):
    """Safely get attribute from object with default value."""
    try:
        return getattr(obj, attr, default)
    except AttributeError:
        return default


# =============================================================================
# MODERN STAT CARD - WITH ICONS & GRADIENT
# =============================================================================

class StatCard(QFrame):
    """
    Modern stat card with icon, sparkline micro-chart, and dark theme.

    DARK MODE DESIGN:
    - Navy/Slate background with accent glow
    - Sparkline micro-chart showing trends
    - Large emoji/icon
    - Hover animation effects
    - Clean typography
    """

    def __init__(self, title: str, value: str = "0", color: str = "#3b82f6", icon: str = "📊"):
        super().__init__()
        self.setObjectName("StatCard")
        self._color = color
        self._icon = icon
        self._history: List[float] = []  # Track values for sparkline

        # Size constraints - slightly larger for sparkline
        self.setMinimumSize(QSize(185, 115))
        self.setMaximumSize(QSize(250, 115))
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

        # Dark theme color mapping
        color_map = {
            "#ef4444": ("#ef4444", "#1c1c1c", "#2a1515"),  # Red - dark bg
            "#f59e0b": ("#f59e0b", "#1c1c1c", "#2a2015"),  # Amber
            "#3b82f6": ("#3b82f6", "#1c1c1c", "#151a2a"),  # Blue
            "#8b5cf6": ("#8b5cf6", "#1c1c1c", "#1f152a"),  # Purple
            "#10b981": ("#10b981", "#1c1c1c", "#152a1f"),  # Green
        }
        accent, bg_base, bg_hover = color_map.get(color, (color, "#1c1c1c", "#252525"))

        # Dark card styling with accent glow
        self.setStyleSheet(f"""
            QFrame#StatCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {DARK_THEME['bg_secondary']}, stop:1 {DARK_THEME['bg_tertiary']});
                border-radius: 8px;
                border: 1px solid {DARK_THEME['border']};
                border-left: 4px solid {accent};
            }}
            QFrame#StatCard:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {DARK_THEME['bg_tertiary']}, stop:1 {DARK_THEME['bg_elevated']});
                border: 1px solid {accent};
                border-left: 4px solid {accent};
            }}
        """)

        # Shadow with colored glow
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(16)
        shadow.setColor(QColor(accent))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)

        # Main layout - horizontal
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Icon container (left side)
        icon_frame = QFrame()
        icon_frame.setFixedSize(48, 48)
        icon_frame.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {DARK_THEME['bg_tertiary']}, stop:1 {DARK_THEME['bg_elevated']});
                border-radius: 8px;
                border: 1px solid {accent}50;
            }}
        """)
        icon_layout = QVBoxLayout(icon_frame)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 24px; background: transparent; border: none;")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_layout.addWidget(icon_label)
        layout.addWidget(icon_frame)

        # Center container (title + value)
        center_layout = QVBoxLayout()
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(2)

        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            color: {DARK_THEME['text_secondary']};
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: transparent;
        """)
        title_label.setWordWrap(True)
        center_layout.addWidget(title_label)

        # Value
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"""
            color: {DARK_THEME['text_primary']};
            font-size: 36px;
            font-weight: 800;
            background: transparent;
        """)
        center_layout.addWidget(self.value_label)

        center_layout.addStretch()
        layout.addLayout(center_layout)

        # Sparkline (right side)
        self.sparkline = SparklineWidget(color=accent)
        layout.addWidget(self.sparkline, alignment=Qt.AlignBottom)

    def set_value(self, value: str):
        """Update value and sparkline with new data point."""
        self.value_label.setText(str(value))

        # Add to history for sparkline
        try:
            numeric_val = float(value)
            self._history.append(numeric_val)
            # Keep last 10 values
            if len(self._history) > 10:
                self._history = self._history[-10:]
            self.sparkline.set_data(self._history)
        except (ValueError, TypeError):
            pass  # Non-numeric value, skip sparkline update


# =============================================================================
# MODERN ESCALATION BADGE - DARK THEME
# =============================================================================

class EscalationBadge(QFrame):
    """Modern escalation badge with icon and progress indicator (Dark Theme)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("EscalationBadge")
        self.setFixedHeight(44)
        self.setMaximumWidth(480)
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(10)

        # Icon
        self.icon_label = QLabel("🛡️")
        self.icon_label.setStyleSheet("font-size: 22px; background: transparent;")
        layout.addWidget(self.icon_label)

        # Text
        self.text_label = QLabel("Safe")
        self.text_label.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {DARK_THEME['text_primary']}; background: transparent;")
        layout.addWidget(self.text_label)

        # Score
        self.score_label = QLabel("(0.00)")
        self.score_label.setStyleSheet(f"font-size: 13px; color: {DARK_THEME['text_muted']}; background: transparent;")
        layout.addWidget(self.score_label)

        layout.addStretch()

        self.update_level(0.0, False)

    def update_level(self, ot_escalation_score: float, has_ot_impact: bool):
        """Update badge appearance with dark theme styling."""
        ot_escalation_score = max(0.0, min(1.0, float(ot_escalation_score)))

        icons = ["🛡️", "⚠️", "🔶", "🔴"]

        # Dark theme escalation colors
        dark_escalation = [
            (0.8, "DANGER", DARK_THEME['accent_red'], "#4a2020"),
            (0.5, "WARNING", DARK_THEME['accent_amber'], "#4a3515"),
            (0.2, "MONITOR", DARK_THEME['accent_blue'], "#152a3b"),
            (0.0, "SAFE", DARK_THEME['accent_green'], "#153b1f"),
        ]

        for i, (threshold, label, text_color, bg) in enumerate(dark_escalation):
            if ot_escalation_score >= threshold:
                if has_ot_impact and threshold < 0.5:
                    label = "OT WARNING"
                    text_color = DARK_THEME['accent_amber']
                    bg = "#4a3515"
                    icon = "⚠️"
                else:
                    icon = icons[i] if i < len(icons) else "🛡️"

                self.icon_label.setText(icon)
                self.text_label.setText(label)
                self.text_label.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {text_color}; background: transparent;")
                self.score_label.setText(f"({ot_escalation_score:.2f})")

                self.setStyleSheet(f"""
                    QFrame#EscalationBadge {{
                        background-color: {bg};
                        border-radius: 8px;
                        border: 1px solid {text_color}50;
                    }}
                """)
                return


# =============================================================================
# MODERN CHAIN LIST ITEM - DARK THEME
# =============================================================================

class ChainListItem(QFrame):
    """Modern chain list item with progress bar and dark theme."""

    clicked = pyqtSignal(object)

    def __init__(self, chain: AttackChain, storyline: Optional[AttackStoryline] = None,
                 parent=None):
        super().__init__(parent)
        self.chain = chain
        self.storyline = storyline
        self._selected = False

        # Size constraints
        self.setMinimumHeight(120)
        self.setMaximumHeight(135)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setObjectName("ChainListItem")
        self._apply_style(False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        # Row 1: ID + severity badge
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        # Chain icon
        chain_icon = QLabel("⚡")
        chain_icon.setStyleSheet("font-size: 16px; background: transparent;")
        row1.addWidget(chain_icon)

        chain_id = _safe_get_attr(chain, 'chain_id', 'Unknown')
        # Shorten chain ID for display
        short_id = chain_id[:18] + "..." if len(chain_id) > 18 else chain_id
        id_label = QLabel(_escape_html(short_id))
        id_label.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {DARK_THEME['text_primary']};")
        id_label.setToolTip(chain_id)
        row1.addWidget(id_label)
        row1.addStretch()

        # Severity badge with icon - dark theme compatible
        sev = _safe_get_attr(chain, 'overall_severity', 'MEDIUM')
        sev_colors_dark = {
            "CRITICAL": (DARK_THEME['accent_red'], "#4a2020"),
            "HIGH": (DARK_THEME['accent_amber'], "#4a3515"),
            "MEDIUM": (DARK_THEME['accent_blue'], "#152a3b"),
            "LOW": (DARK_THEME['accent_green'], "#153b1f"),
        }
        sev_text, sev_bg = sev_colors_dark.get(sev, (DARK_THEME['text_secondary'], DARK_THEME['bg_tertiary']))
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        sev_icon = sev_icons.get(sev, "⚪")

        sev_label = QLabel(f"{sev_icon} {sev}")
        sev_label.setStyleSheet(f"""
            background-color: {sev_bg}; color: {sev_text};
            border-radius: 8px; padding: 5px 12px;
            font-size: 13px; font-weight: 700;
        """)
        sev_label.setFixedHeight(26)
        row1.addWidget(sev_label)
        layout.addLayout(row1)

        # Row 2: Source -> Target with arrow
        row2 = QHBoxLayout()
        row2.setSpacing(4)

        source_ips = _safe_get_attr(chain, 'source_ips', set())
        src_list = list(source_ips) if source_ips else []
        src_text = src_list[0] if src_list else "N/A"
        if len(src_list) > 1:
            src_text += f" +{len(src_list)-1}"

        target_ips = _safe_get_attr(chain, 'target_ips', set())
        tgt_list = list(target_ips) if target_ips else []
        tgt_text = tgt_list[0] if tgt_list else "N/A"
        if len(tgt_list) > 1:
            tgt_text += f" +{len(tgt_list)-1}"

        flow_label = QLabel(f"📍 {_escape_html(src_text)}  ➔  🎯 {_escape_html(tgt_text)}")
        flow_label.setStyleSheet(f"font-size: 14px; color: {DARK_THEME['text_secondary']};")
        flow_label.setWordWrap(True)
        row2.addWidget(flow_label)
        layout.addLayout(row2)

        # Row 3: Stats with icons
        row3 = QHBoxLayout()
        row3.setSpacing(12)

        phase_count = _safe_get_attr(chain, 'phase_count', 0)
        total_events = _safe_get_attr(chain, 'total_events', 0)
        has_ot_impact = _safe_get_attr(chain, 'has_ot_impact', False)

        stats_parts = [
            f"📊 {phase_count} phases",
            f"📋 {total_events} events"
        ]
        if has_ot_impact:
            stats_parts.append("🏭 OT!")

        stats_label = QLabel("  |  ".join(stats_parts))
        stats_label.setStyleSheet(f"font-size: 13px; color: {DARK_THEME['text_muted']};")
        row3.addWidget(stats_label)
        row3.addStretch()
        layout.addLayout(row3)

        # Row 4: OT Escalation Progress Bar
        ot_esc = _safe_get_attr(chain, 'ot_escalation_score', 0.0)
        if ot_esc > 0 or has_ot_impact:
            progress_container = QFrame()
            progress_container.setStyleSheet("background: transparent;")
            progress_layout = QHBoxLayout(progress_container)
            progress_layout.setContentsMargins(0, 4, 0, 0)
            progress_layout.setSpacing(6)

            esc_icon = QLabel("📈")
            esc_icon.setStyleSheet("font-size: 10px; background: transparent;")
            progress_layout.addWidget(esc_icon)

            progress = QProgressBar()
            progress.setFixedHeight(6)
            progress.setMinimum(0)
            progress.setMaximum(100)
            progress.setValue(int(ot_esc * 100))
            progress.setTextVisible(False)

            # Color based on escalation level
            if ot_esc >= 0.75:
                bar_color = DARK_THEME['accent_red']
            elif ot_esc >= 0.5:
                bar_color = DARK_THEME['accent_amber']
            elif ot_esc >= 0.25:
                bar_color = "#eab308"
            else:
                bar_color = DARK_THEME['accent_green']

            progress.setStyleSheet(f"""
                QProgressBar {{
                    background-color: {DARK_THEME['bg_tertiary']};
                    border-radius: 3px;
                    border: none;
                }}
                QProgressBar::chunk {{
                    background-color: {bar_color};
                    border-radius: 3px;
                }}
            """)
            progress_layout.addWidget(progress, stretch=1)

            esc_label = QLabel(f"{ot_esc:.0%}")
            esc_label.setStyleSheet(f"font-size: 13px; font-weight: 600; color: {bar_color};")
            progress_layout.addWidget(esc_label)

            layout.addWidget(progress_container)

    def _apply_style(self, selected: bool):
        """Apply dark theme styling."""
        if selected:
            self.setStyleSheet(f"""
                QFrame#ChainListItem {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #1e3a5f, stop:1 #152a3b);
                    border: 2px solid {DARK_THEME['accent_blue']};
                    border-radius: 8px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QFrame#ChainListItem {{
                    background-color: {DARK_THEME['bg_secondary']};
                    border: 1px solid {DARK_THEME['border']};
                    border-radius: 8px;
                }}
                QFrame#ChainListItem:hover {{
                    background-color: {DARK_THEME['bg_tertiary']};
                    border: 1px solid {DARK_THEME['border_light']};
                }}
            """)

    def set_selected(self, selected: bool):
        self._selected = selected
        self._apply_style(selected)

    def mousePressEvent(self, event):
        self.clicked.emit(self.chain)
        super().mousePressEvent(event)


# =============================================================================
# MODERN CHAIN LIST PANEL
# =============================================================================

class ChainListPanel(QGroupBox):
    """Modern left panel with chain list - Dark Theme."""

    chain_selected = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__("📋 Attack Chain List", parent)
        self.setStyleSheet(GROUPBOX_STYLE)

        self.setMinimumWidth(300)
        self.setMaximumWidth(380)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        self._items: List[ChainListItem] = []
        self._current_chain: Optional[AttackChain] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 20, 12, 12)
        layout.setSpacing(8)

        # Scroll area with dark theme styling
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                border: none;
                background: transparent;
            }}
            QScrollBar:vertical {{
                background-color: {DARK_THEME['bg_tertiary']};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {DARK_THEME['border_light']};
                border-radius: 4px;
                min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {DARK_THEME['accent_blue']};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
        """)

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background: transparent;")
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 4, 0)
        self.scroll_layout.setSpacing(8)

        self.scroll_area.setWidget(self.scroll_content)
        layout.addWidget(self.scroll_area)

    def populate(self, chains: List[AttackChain], storylines: List[AttackStoryline]):
        """Populate chain list."""
        # Clear old items
        for item in self._items:
            item.setParent(None)
            item.deleteLater()
        self._items.clear()
        self._current_chain = None

        if not chains:
            return

        # Build storyline lookup
        storyline_map = {s.chain_id: s for s in storylines if hasattr(s, 'chain_id')}

        # Sort chains
        try:
            sorted_chains = sorted(
                chains,
                key=lambda c: (
                    -SEVERITY_ORDER.get(_safe_get_attr(c, 'overall_severity', 'LOW'), 0),
                    -float(_safe_get_attr(c, 'start_time', 0))
                )
            )
        except (TypeError, ValueError, AttributeError):
            sorted_chains = chains

        # Create items
        for chain in sorted_chains[:50]:  # Limit to 50 for performance
            try:
                chain_id = _safe_get_attr(chain, 'chain_id', '')
                storyline = storyline_map.get(chain_id)
                item = ChainListItem(chain, storyline)
                item.clicked.connect(self._on_item_clicked)
                self.scroll_layout.addWidget(item)
                self._items.append(item)
            except Exception as e:
                print(f"Warning: Failed to create chain item: {e}")
                continue

    def _on_item_clicked(self, chain: AttackChain):
        chain_id = _safe_get_attr(chain, 'chain_id', '')
        for item in self._items:
            item_chain_id = _safe_get_attr(item.chain, 'chain_id', '')
            item.set_selected(item_chain_id == chain_id)
        self._current_chain = chain
        self.chain_selected.emit(chain)

    def select_first(self):
        if self._items:
            first_chain = self._items[0].chain
            self._items[0].set_selected(True)
            self._current_chain = first_chain
            self.chain_selected.emit(first_chain)


# =============================================================================
# MODERN TIMELINE PANEL - WITH VISUAL STEPPER
# =============================================================================

class TimelinePanel(QGroupBox):
    """Modern timeline panel with Node-Link flowchart design - Dark Theme."""

    def __init__(self, parent=None):
        super().__init__("📊 Attack Timeline", parent)
        self.setStyleSheet(GROUPBOX_STYLE)

        self.setMinimumHeight(420)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 24, 16, 16)
        layout.setSpacing(16)

        # Escalation badge
        self.escalation_badge = EscalationBadge()
        layout.addWidget(self.escalation_badge, alignment=Qt.AlignLeft)

        # Timeline content with dark theme
        self.timeline_text = QTextEdit()
        self.timeline_text.setReadOnly(True)
        self.timeline_text.setStyleSheet(f"""
            QTextEdit {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {DARK_THEME['bg_secondary']}, stop:1 {DARK_THEME['bg_primary']});
                border: 1px solid {DARK_THEME['border']};
                border-radius: 8px;
                padding: 16px;
                font-size: 14px;
                color: {DARK_THEME['text_primary']};
            }}
            QScrollBar:vertical {{
                background-color: {DARK_THEME['bg_tertiary']};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {DARK_THEME['border_light']};
                border-radius: 4px;
                min-height: 32px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {DARK_THEME['accent_blue']};
            }}
        """)
        layout.addWidget(self.timeline_text)

    def display_chain(self, chain: AttackChain, storyline: Optional[AttackStoryline] = None):
        try:
            html_content = self._build_timeline_html(chain, storyline)
            self.timeline_text.setHtml(html_content)

            ot_escalation_score = _safe_get_attr(chain, 'ot_escalation_score', 0.0)
            has_ot_impact = _safe_get_attr(chain, 'has_ot_impact', False)
            self.escalation_badge.update_level(ot_escalation_score, has_ot_impact)
        except Exception as e:
            error_html = f"""
            <div style='color:{DARK_THEME['accent_red']}; padding:20px;'>
                <b>❌ Error displaying timeline:</b><br/>
                {_escape_html(str(e))}
            </div>
            """
            self.timeline_text.setHtml(error_html)

    def display_empty(self):
        self.escalation_badge.update_level(0.0, False)
        self.timeline_text.setHtml(f"""
            <div style='text-align:center; color:{DARK_THEME['text_muted']}; padding:60px 20px; font-size:14px;'>
                <div style='font-size: 48px; margin-bottom: 16px;'>🔗</div>
                <b style='font-size: 16px; color: {DARK_THEME['text_secondary']};'>No attack chains yet</b>
                <br/><br/>
                <span style='font-size: 12px;'>
                    To use this feature, enable <code style='background:{DARK_THEME['bg_tertiary']};
                    padding:2px 6px; border-radius:4px; color:{DARK_THEME['text_primary']};'>enable_correlation</code>
                    and <code style='background:{DARK_THEME['bg_tertiary']}; padding:2px 6px;
                    border-radius:4px; color:{DARK_THEME['text_primary']};'>enable_storyline</code> in AnalyzerConfig.
                </span>
            </div>
        """)

    def _build_timeline_html(self, chain: AttackChain,
                            storyline: Optional[AttackStoryline] = None) -> str:
        """Build Node-Link flowchart timeline HTML with dark theme."""
        parts = []

        # Dark theme CSS with Node-Link flowchart design
        parts.append(f"""
        <style>
            body {{
                font-family: 'Inter','Segoe UI',system-ui,sans-serif;
                color: {DARK_THEME['text_primary']};
                margin: 0;
                font-size: 14px;
                line-height: 1.6;
                background: transparent;
            }}
            .header {{
                background: linear-gradient(135deg, {DARK_THEME['bg_tertiary']} 0%, {DARK_THEME['bg_secondary']} 100%);
                padding: 16px 24px;
                border-radius: 8px;
                margin-bottom: 24px;
                border: 1px solid {DARK_THEME['border']};
            }}
            .header-title {{
                font-size: 20px;
                font-weight: 700;
                color: {DARK_THEME['text_primary']};
                margin-bottom: 8px;
            }}
            .header-meta {{
                font-size: 14px;
                color: {DARK_THEME['text_secondary']};
                line-height: 1.8;
            }}
            .badge {{
                display: inline-block;
                padding: 4px 16px;
                border-radius: 4px;
                font-size: 13px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .flow-arrow {{
                color: {DARK_THEME['accent_cyan']};
                font-size: 18px;
                margin: 0 8px;
            }}

            /* Node-Link Flowchart Design */
            .flowchart {{
                margin-top: 16px;
            }}
            .node {{
                display: flex;
                margin-bottom: 0;
            }}
            .node-indicator {{
                display: flex;
                flex-direction: column;
                align-items: center;
                width: 48px;
                flex-shrink: 0;
            }}
            .node-icon {{
                width: 40px;
                height: 40px;
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 18px;
                font-weight: 700;
                color: white;
                box-shadow: 0 4px 8px rgba(0,0,0,0.3);
            }}
            .node-connector {{
                width: 3px;
                flex-grow: 1;
                min-height: 24px;
                margin: 8px 0;
                border-radius: 2px;
            }}
            .node-content {{
                flex: 1;
                padding: 8px 0 20px 16px;
            }}
            .node-header {{
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 8px;
            }}
            .node-title {{
                font-weight: 700;
                font-size: 16px;
            }}
            .node-desc {{
                font-size: 14px;
                color: {DARK_THEME['text_secondary']};
                margin-bottom: 8px;
                line-height: 1.5;
            }}
            .node-meta {{
                font-size: 13px;
                color: {DARK_THEME['text_muted']};
            }}
            .technique-tag {{
                display: inline-block;
                background: {DARK_THEME['bg_tertiary']};
                color: {DARK_THEME['text_secondary']};
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                margin-right: 8px;
                border: 1px solid {DARK_THEME['border']};
            }}

            .alert-box {{
                background: linear-gradient(135deg, #4a2020 0%, #3a1818 100%);
                border: 1px solid {DARK_THEME['accent_red']}50;
                border-radius: 8px;
                padding: 16px;
                margin-top: 16px;
            }}
            .alert-title {{
                color: {DARK_THEME['accent_red']};
                font-weight: 700;
                font-size: 15px;
                margin-bottom: 8px;
            }}
        </style>
        """)

        # Header with chain info
        source_ips = _safe_get_attr(chain, 'source_ips', set())
        target_ips = _safe_get_attr(chain, 'target_ips', set())

        src = ", ".join(list(source_ips)[:2]) if source_ips else "N/A"
        if len(source_ips) > 2:
            src += f" +{len(source_ips)-2}"

        tgt = ", ".join(list(target_ips)[:2]) if target_ips else "N/A"
        if len(target_ips) > 2:
            tgt += f" +{len(target_ips)-2}"

        title_text = ""
        if storyline:
            title_text = _safe_get_attr(storyline, 'title', '')

        chain_id = _safe_get_attr(chain, 'chain_id', 'Unknown')
        overall_severity = _safe_get_attr(chain, 'overall_severity', 'MEDIUM')
        confidence = _safe_get_attr(chain, 'confidence', 0.0)
        start_time = _safe_get_attr(chain, 'start_time', 0.0)
        end_time = _safe_get_attr(chain, 'end_time', 0.0)
        duration = _safe_get_attr(chain, 'duration', 0.0)

        # Dark theme severity colors
        sev_colors_dark = {
            "CRITICAL": (DARK_THEME['accent_red'], "#4a2020"),
            "HIGH": (DARK_THEME['accent_amber'], "#4a3515"),
            "MEDIUM": (DARK_THEME['accent_blue'], "#152a3b"),
            "LOW": (DARK_THEME['accent_green'], "#153b1f"),
        }
        sev_text, sev_bg = sev_colors_dark.get(overall_severity, (DARK_THEME['text_secondary'], DARK_THEME['bg_tertiary']))
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        sev_icon = sev_icons.get(overall_severity, "⚪")

        parts.append(f"""
        <div class='header'>
            <div class='header-title'>
                ⚡ {_escape_html(title_text or 'Attack chain ' + chain_id[:15])}
            </div>
            <div class='header-meta'>
                <span class='badge' style='background:{sev_bg}; color:{sev_text};'>
                    {sev_icon} {_escape_html(overall_severity)}
                </span>
                &nbsp;&nbsp;|&nbsp;&nbsp;
                📊 Confidence: <b>{confidence:.0%}</b>
                <br/><br/>
                📍 <b>{_escape_html(src)}</b>
                <span class='flow-arrow'>➔</span>
                🎯 <b>{_escape_html(tgt)}</b>
                <br/>
                🕐 {_fmt_ts(start_time)} → {_fmt_ts(end_time)}
                <span style='color:{DARK_THEME["text_muted"]};'>({duration:.0f} seconds)</span>
            </div>
        </div>
        """)

        # Phase Node-Link flowchart
        phases = _safe_get_attr(chain, 'phases', [])

        if not phases:
            parts.append(f"""
                <div style='color:{DARK_THEME["text_muted"]}; text-align:center; padding:30px;'>
                    <div style='font-size: 32px; margin-bottom: 8px;'>📭</div>
                    No phases detected
                </div>
            """)
            return "".join(parts)

        parts.append("<div class='flowchart'>")

        for i, phase in enumerate(phases):
            try:
                phase_index = _safe_get_attr(phase, 'phase_index', 0)
                phase_name = _safe_get_attr(phase, 'phase_name', 'Unknown')
                description_text = _safe_get_attr(phase, 'description', '')
                severity = _safe_get_attr(phase, 'severity', 'MEDIUM')
                phase_timestamp = _safe_get_attr(phase, 'timestamp', 0.0)
                mitre_techniques = _safe_get_attr(phase, 'mitre_techniques', [])

                color = PHASE_COLORS.get(phase_index, "#6b7280")
                phase_info = ATTACK_PHASES.get(phase_name, {})
                phase_display_name = (phase_info.get("name") or
                                      str(phase_name).replace("_", " ").title())

                if not description_text:
                    description_text = phase_info.get("description", "")

                # Truncate long descriptions
                if len(description_text) > 120:
                    description_text = description_text[:117] + "..."

                sev_text_p, sev_bg_p = sev_colors_dark.get(severity, (DARK_THEME['text_secondary'], DARK_THEME['bg_tertiary']))
                is_last = (i == len(phases) - 1)

                # Get phase icon
                phase_icon = PHASE_ICONS.get(phase_index, "📌")

                # Connector style with gradient
                connector_html = "" if is_last else f"""
                    <div class='node-connector' style='background: linear-gradient(180deg, {color} 0%, {DARK_THEME["bg_tertiary"]} 100%);'></div>
                """

                parts.append(f"""
                <div class='node'>
                    <div class='node-indicator'>
                        <div class='node-icon' style='background: linear-gradient(135deg, {color} 0%, {color}cc 100%);'>
                            {phase_icon if len(phase_icon) < 3 else phase_index}
                        </div>
                        {connector_html}
                    </div>
                    <div class='node-content'>
                        <div class='node-header'>
                            <span class='node-title' style='color: {color};'>
                                {_escape_html(phase_display_name)}
                            </span>
                            <span class='badge' style='background:{sev_bg_p}; color:{sev_text_p};'>
                                {_escape_html(severity)}
                            </span>
                        </div>
                        <div class='node-desc'>{_escape_html(description_text)}</div>
                        <div class='node-meta'>
                            🕐 {_fmt_ts_short(phase_timestamp)}
                            {self._render_techniques(mitre_techniques)}
                        </div>
                    </div>
                </div>
                """)
            except Exception as e:
                print(f"Warning: Error rendering phase {i}: {e}")
                continue

        parts.append("</div>")

        # OT assets at risk alert box
        ot_assets_at_risk = _safe_get_attr(chain, 'ot_assets_at_risk', [])
        if ot_assets_at_risk:
            assets_text = ', '.join(ot_assets_at_risk[:3])
            if len(ot_assets_at_risk) > 3:
                assets_text += f' +{len(ot_assets_at_risk)-3}'
            parts.append(f"""
            <div class='alert-box'>
                <div class='alert-title'>🏭 OT assets at risk</div>
                <span style='font-size:11px; color:{DARK_THEME["accent_red"]};'>{_escape_html(assets_text)}</span>
            </div>
            """)

        return "".join(parts)

    def _render_techniques(self, techniques: list) -> str:
        """Render MITRE techniques as tags."""
        if not techniques:
            return ""
        html = "&nbsp;&nbsp;|&nbsp;&nbsp;"
        for tech in techniques[:3]:
            html += f"<span class='technique-tag'>{_escape_html(tech)}</span>"
        if len(techniques) > 3:
            html += f"<span class='technique-tag'>+{len(techniques)-3}</span>"
        return html


# =============================================================================
# MODERN DETAIL PANEL - WITH ICONS & SECTIONS
# =============================================================================

class DetailPanel(QGroupBox):
    """Modern detail panel with collapsible sections and interactive checklists - Dark Theme."""

    def __init__(self, parent=None):
        super().__init__("📋 Incident Details", parent)
        self.setStyleSheet(GROUPBOX_STYLE)

        self.setMinimumHeight(420)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 24, 16, 16)
        layout.setSpacing(8)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet(f"""
            QTextEdit {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {DARK_THEME['bg_secondary']}, stop:1 {DARK_THEME['bg_primary']});
                border: 1px solid {DARK_THEME['border']};
                border-radius: 8px;
                padding: 16px;
                font-size: 14px;
                color: {DARK_THEME['text_primary']};
            }}
            QScrollBar:vertical {{
                background-color: {DARK_THEME['bg_tertiary']};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {DARK_THEME['border_light']};
                border-radius: 4px;
                min-height: 32px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {DARK_THEME['accent_blue']};
            }}
        """)
        layout.addWidget(self.detail_text)

    def display_storyline(self, chain: AttackChain,
                         storyline: Optional[AttackStoryline] = None):
        try:
            html_content = self._build_detail_html(chain, storyline)
            self.detail_text.setHtml(html_content)
        except Exception as e:
            error_html = f"""
            <div style='color:{DARK_THEME['accent_red']}; padding:20px;'>
                <b>❌ Error displaying details:</b><br/>
                {_escape_html(str(e))}
            </div>
            """
            self.detail_text.setHtml(error_html)

    def display_empty(self):
        self.detail_text.setHtml(f"""
            <div style='text-align:center; color:{DARK_THEME['text_muted']}; padding:60px 20px; font-size:14px;'>
                <div style='font-size: 48px; margin-bottom: 16px;'>👆</div>
                <b style='font-size: 14px; color: {DARK_THEME['text_secondary']};'>Select an attack chain</b>
                <br/><br/>
                <span style='font-size: 12px;'>to view details and response recommendations</span>
            </div>
        """)

    def _build_detail_html(self, chain: AttackChain,
                          storyline: Optional[AttackStoryline] = None) -> str:
        """Build dark theme detail HTML with collapsible sections design."""

        # Dark theme CSS with accordion-style sections
        html = [f"""
        <style>
            body {{
                font-family:'Inter','Segoe UI',system-ui,sans-serif;
                color:{DARK_THEME['text_primary']};
                margin:0;
                font-size:14px;
                line-height: 1.6;
                background: transparent;
            }}

            .section {{
                background: linear-gradient(135deg, {DARK_THEME['bg_tertiary']} 0%, {DARK_THEME['bg_secondary']} 100%);
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 16px;
                border: 1px solid {DARK_THEME['border']};
            }}
            .section-warn {{
                background: linear-gradient(135deg, #4a2020 0%, #3a1818 100%);
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 16px;
                border: 1px solid {DARK_THEME['accent_red']}40;
            }}
            .section-success {{
                background: linear-gradient(135deg, #153b1f 0%, #102a15 100%);
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 16px;
                border: 1px solid {DARK_THEME['accent_green']}40;
            }}
            .section-amber {{
                background: linear-gradient(135deg, #4a3515 0%, #2a1f10 100%);
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 16px;
                border: 1px solid {DARK_THEME['accent_amber']}40;
            }}

            .section-header {{
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 8px;
            }}
            .section-icon {{
                font-size: 20px;
            }}
            .section-title {{
                font-size: 13px;
                font-weight: 700;
                color: {DARK_THEME['accent_blue']};
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .section-title-red {{
                color: {DARK_THEME['accent_red']};
            }}
            .section-title-amber {{
                color: {DARK_THEME['accent_amber']};
            }}
            .section-title-green {{
                color: {DARK_THEME['accent_green']};
            }}

            .badge {{
                display: inline-block;
                padding: 4px 16px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 700;
            }}

            .action-item {{
                display: flex;
                align-items: flex-start;
                gap: 12px;
                padding: 10px 12px;
                margin: 5px 0;
                background: {DARK_THEME['bg_tertiary']};
                border-radius: 8px;
                border-left: 3px solid {DARK_THEME['accent_blue']};
            }}
            .action-item-urgent {{
                border-left: 3px solid {DARK_THEME['accent_red']};
                background: linear-gradient(90deg, #4a202020 0%, {DARK_THEME['bg_tertiary']} 100%);
            }}
            .action-checkbox {{
                width: 20px;
                height: 20px;
                border: 2px solid {DARK_THEME['text_muted']};
                border-radius: 5px;
                flex-shrink: 0;
                margin-top: 2px;
            }}
            .action-text {{
                font-size: 13px;
                color: {DARK_THEME['text_primary']};
                line-height: 1.5;
            }}

            .event-row {{
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 8px 10px;
                margin: 3px 0;
                font-size: 12px;
                background: {DARK_THEME['bg_tertiary']};
                border-radius: 6px;
            }}
            .event-time {{
                color: {DARK_THEME['text_muted']};
                min-width: 60px;
            }}
            .event-sev {{
                font-weight: 600;
                min-width: 60px;
            }}

            .score-bar {{
                height: 10px;
                background: {DARK_THEME['bg_tertiary']};
                border-radius: 5px;
                margin: 8px 0;
                overflow: hidden;
            }}
            .score-fill {{
                height: 100%;
                border-radius: 5px;
                transition: width 0.3s ease;
            }}
        </style>
        """]

        # OT Escalation Section with progress bar
        ot_esc = _safe_get_attr(chain, 'ot_escalation_score', 0.0)
        has_ot_impact = _safe_get_attr(chain, 'has_ot_impact', False)
        ot_assets_at_risk = _safe_get_attr(chain, 'ot_assets_at_risk', [])

        # Dark theme escalation colors
        dark_esc_colors = [
            (0.8, "DANGER", DARK_THEME['accent_red'], "#4a2020"),
            (0.5, "WARNING", DARK_THEME['accent_amber'], "#4a3515"),
            (0.2, "MONITOR", DARK_THEME['accent_blue'], "#152a3b"),
            (0.0, "SAFE", DARK_THEME['accent_green'], "#153b1f"),
        ]

        ot_badge = ""
        bar_color = DARK_THEME['accent_green']
        for threshold, label, text_color, bg in dark_esc_colors:
            if ot_esc >= threshold:
                ot_badge = f"<span class='badge' style='background:{bg}; color:{text_color};'>{_escape_html(label)}</span>"
                bar_color = text_color
                break

        section_class = "section-warn" if ot_esc >= 0.5 else ("section-amber" if ot_esc >= 0.2 else "section")
        ot_impact_icon = "✅" if has_ot_impact else "❌"
        ot_impact_text = "Direct OT impact" if has_ot_impact else "No direct OT impact yet"
        ot_assets_text = ", ".join(ot_assets_at_risk[:2]) if ot_assets_at_risk else "None"
        if len(ot_assets_at_risk) > 2:
            ot_assets_text += f" +{len(ot_assets_at_risk)-2}"

        html.append(f"""
        <div class='{section_class}'>
            <div class='section-header'>
                <span class='section-icon'>🏭</span>
                <span class='section-title'>OT Impact / IT→OT Escalation</span>
            </div>
            <div style='display:flex; align-items:center; gap:14px; margin-bottom:8px;'>
                <span style='font-size:28px; font-weight:800; color:{DARK_THEME["text_primary"]};'>{ot_esc:.2f}</span>
                {ot_badge}
            </div>
            <div class='score-bar'>
                <div class='score-fill' style='width:{ot_esc*100:.0f}%; background:{bar_color};'></div>
            </div>
            <div style='font-size:11px; margin-top:10px; color:{DARK_THEME["text_secondary"]};'>
                {ot_impact_icon} {_escape_html(ot_impact_text)}<br/>
                🎯 OT assets: <b style='color:{DARK_THEME["text_primary"]};'>{_escape_html(ot_assets_text)}</b>
            </div>
        </div>
        """)

        if not storyline:
            html.append(f"""
            <div class='section'>
                <div class='section-header'>
                    <span class='section-icon'>📝</span>
                    <span class='section-title'>Incident Description</span>
                </div>
                <div style='color:{DARK_THEME["text_muted"]}; font-size:11px; text-align:center; padding:20px;'>
                    <div style='font-size:24px; margin-bottom:8px;'>📭</div>
                    No storyline available.<br/>
                    Enable <code style='background:{DARK_THEME["bg_tertiary"]}; padding:2px 6px; border-radius:4px; color:{DARK_THEME["text_primary"]};'>enable_storyline</code> to generate a narrative.
                </div>
            </div>
            """)
            return "".join(html)

        # Narrative Section
        narrative = _safe_get_attr(storyline, 'narrative', '') or ""

        narrative_clean = "<br/>".join(
            _escape_html(line.strip())
            for line in narrative.strip().split("\n")
            if line.strip()
        )[:600]

        if len(narrative) > 600:
            narrative_clean += "..."

        html.append(f"""
        <div class='section'>
            <div class='section-header'>
                <span class='section-icon'>📖</span>
                <span class='section-title'>Incident Description</span>
            </div>
            <div style='font-size:11px; color:{DARK_THEME["text_secondary"]};'>{narrative_clean}</div>
        </div>
        """)

        # Key Events Section
        key_events = _safe_get_attr(storyline, 'key_events', [])
        if key_events:
            html.append(f"""
            <div class='section'>
                <div class='section-header'>
                    <span class='section-icon'>📊</span>
                    <span class='section-title'>Key Events</span>
                </div>
            """)
            # Dark theme severity colors
            sev_colors_dark = {
                "CRITICAL": (DARK_THEME['accent_red'], "#4a2020"),
                "HIGH": (DARK_THEME['accent_amber'], "#4a3515"),
                "MEDIUM": (DARK_THEME['accent_blue'], "#152a3b"),
                "LOW": (DARK_THEME['accent_green'], "#153b1f"),
            }
            for evt in key_events[:5]:
                sev = evt.get("severity", "")
                sev_text, sev_bg = sev_colors_dark.get(sev, (DARK_THEME['text_secondary'], DARK_THEME['bg_tertiary']))
                time_str = evt.get("time", "")
                time_short = time_str.split(' ')[-1] if ' ' in time_str else time_str
                desc = evt.get("description", "")
                if len(desc) > 70:
                    desc = desc[:67] + "..."
                html.append(f"""
                <div class='event-row'>
                    <span class='event-time'>🕐 {_escape_html(time_short)}</span>
                    <span class='badge' style='background:{sev_bg}; color:{sev_text};'>{_escape_html(sev)}</span>
                    <span style='flex:1; color:{DARK_THEME["text_primary"]};'>{_escape_html(desc)}</span>
                </div>
                """)
            if len(key_events) > 5:
                html.append(f"<div style='color:{DARK_THEME['text_muted']}; font-size:10px; text-align:center; padding-top:8px;'>... +{len(key_events)-5} more events</div>")
            html.append("</div>")

        # Immediate Actions Section (RED/URGENT)
        immediate_actions = (_safe_get_attr(storyline, 'immediate_actions', []))
        if immediate_actions:
            html.append(f"""
            <div class='section-warn'>
                <div class='section-header'>
                    <span class='section-icon'>🚨</span>
                    <span class='section-title section-title-red'>IMMEDIATE ACTIONS</span>
                </div>
            """)
            for i, action in enumerate(immediate_actions[:4], 1):
                html.append(f"""
                <div class='action-item action-item-urgent'>
                    <div class='action-checkbox'></div>
                    <span class='action-text'><b style='color:{DARK_THEME["accent_red"]};'>{i}.</b> {_escape_html(action[:100])}</span>
                </div>
                """)
            if len(immediate_actions) > 4:
                html.append(f"<div style='color:{DARK_THEME['text_muted']}; font-size:10px; text-align:center; padding-top:6px;'>... +{len(immediate_actions)-4} more</div>")
            html.append("</div>")

        # Short-term Actions Section
        short_term_actions = (_safe_get_attr(storyline, 'short_term_actions', []))
        if short_term_actions:
            html.append(f"""
            <div class='section-amber'>
                <div class='section-header'>
                    <span class='section-icon'>⏰</span>
                    <span class='section-title section-title-amber'>SHORT TERM (24h)</span>
                </div>
            """)
            for i, action in enumerate(short_term_actions[:3], 1):
                html.append(f"""
                <div class='action-item'>
                    <div class='action-checkbox'></div>
                    <span class='action-text'><b style='color:{DARK_THEME["accent_amber"]};'>{i}.</b> {_escape_html(action[:100])}</span>
                </div>
                """)
            if len(short_term_actions) > 3:
                html.append(f"<div style='color:{DARK_THEME['text_muted']}; font-size:10px; text-align:center; padding-top:6px;'>... +{len(short_term_actions)-3} more</div>")
            html.append("</div>")

        # Long-term Actions Section
        long_term_actions = (_safe_get_attr(storyline, 'long_term_actions', []))
        if long_term_actions:
            html.append(f"""
            <div class='section'>
                <div class='section-header'>
                    <span class='section-icon'>📋</span>
                    <span class='section-title'>LONG TERM (1 week)</span>
                </div>
            """)
            for i, action in enumerate(long_term_actions[:3], 1):
                html.append(f"""
                <div class='action-item'>
                    <div class='action-checkbox'></div>
                    <span class='action-text'><b style='color:{DARK_THEME["accent_blue"]};'>{i}.</b> {_escape_html(action[:100])}</span>
                </div>
                """)
            if len(long_term_actions) > 3:
                html.append(f"<div style='color:{DARK_THEME['text_muted']}; font-size:10px; text-align:center; padding-top:6px;'>... +{len(long_term_actions)-3} more</div>")
            html.append("</div>")

        # Production Risk Section
        prod_risk = _safe_get_attr(storyline, 'production_risk', 'NONE')
        risk_colors_dark = {
            "CRITICAL": (DARK_THEME['accent_red'], "#4a2020"),
            "HIGH": (DARK_THEME['accent_amber'], "#4a3515"),
            "MEDIUM": (DARK_THEME['accent_blue'], "#152a3b"),
            "LOW": (DARK_THEME['accent_green'], "#153b1f"),
            "NONE": (DARK_THEME['accent_green'], "#153b1f"),
        }
        risk_text, risk_bg = risk_colors_dark.get(prod_risk, (DARK_THEME['accent_green'], "#153b1f"))
        risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "✅"}
        risk_icon = risk_icons.get(prod_risk, "⚪")

        section_class = "section-success" if prod_risk in ["NONE", "LOW"] else "section"

        html.append(f"""
        <div class='{section_class}'>
            <div class='section-header'>
                <span class='section-icon'>⚠️</span>
                <span class='section-title section-title-green'>Production Risk</span>
            </div>
            <span class='badge' style='background:{risk_bg}; color:{risk_text}; font-size:12px; padding:6px 14px;'>
                {risk_icon} {_escape_html(prod_risk)}
            </span>
        </div>
        """)

        return "".join(html)


# =============================================================================
# MODERN INCIDENT STORY WIDGET - DARK THEME MAIN VIEW
# =============================================================================

class IncidentStoryWidget(QWidget):
    """
    Modern incident story widget with Navy/Slate dark theme SOC dashboard.

    DARK MODE FEATURES:
    - Sparkline stat cards with trend visualization
    - Node-Link flowchart timeline
    - Collapsible accordion sections
    - Interactive action checklists
    - Professional detail panel with dark theme
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._chains: List[AttackChain] = []
        self._storylines: List[AttackStoryline] = []
        self._storyline_map: Dict[str, AttackStoryline] = {}
        self._init_ui()

    def _init_ui(self):
        """Initialize dark theme UI."""
        # Set dark background for main widget
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {DARK_THEME['bg_primary']};
                color: {DARK_THEME['text_primary']};
            }}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 20)
        main_layout.setSpacing(18)

        # Modern header with icon
        header_container = QFrame()
        header_container.setStyleSheet("background: transparent;")
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(14)

        # Title with icon
        title_icon = QLabel("⚔️")
        title_icon.setStyleSheet("font-size: 24px; background: transparent;")
        header_layout.addWidget(title_icon)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)

        title = QLabel("Incident View / Attack Chains")
        title.setStyleSheet(f"""
            font-size: 22px;
            font-weight: 800;
            color: {DARK_THEME['text_primary']};
            background: transparent;
        """)
        title_layout.addWidget(title)

        subtitle = QLabel("Attack Chain Visualization & Incident Analysis")
        subtitle.setStyleSheet(f"""
            font-size: 11px;
            color: {DARK_THEME['text_muted']};
            background: transparent;
        """)
        title_layout.addWidget(subtitle)

        header_layout.addLayout(title_layout)
        header_layout.addStretch()

        header_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        main_layout.addWidget(header_container)

        # Dark theme stat cards container
        cards_container = QFrame()
        cards_container.setStyleSheet("background: transparent;")
        cards_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        cards_container.setMaximumHeight(135)

        cards_layout = QHBoxLayout(cards_container)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(14)

        # Create stat cards with icons and sparklines
        self.card_chains = StatCard("ATTACK CHAINS", "0", "#ef4444", "⚡")
        self.card_ot_impact = StatCard("OT IMPACTED", "0", "#f59e0b", "🏭")
        self.card_critical = StatCard("CRITICAL", "0", "#ef4444", "🔴")
        self.card_storylines = StatCard("STORYLINES", "0", "#8b5cf6", "📖")
        self.card_max_esc = StatCard("OT ESCALATION", "0.00", "#3b82f6", "📈")

        for card in [self.card_chains, self.card_ot_impact, self.card_critical,
                     self.card_storylines, self.card_max_esc]:
            cards_layout.addWidget(card)

        cards_layout.addStretch()
        main_layout.addWidget(cards_container)

        # Dark theme 3-panel splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {DARK_THEME['bg_tertiary']}, stop:0.5 {DARK_THEME['border_light']}, stop:1 {DARK_THEME['bg_tertiary']});
                border-radius: 4px;
                margin: 6px 0;
            }}
            QSplitter::handle:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {DARK_THEME['accent_blue']}80, stop:0.5 {DARK_THEME['accent_blue']}, stop:1 {DARK_THEME['accent_blue']}80);
            }}
        """)
        splitter.setChildrenCollapsible(False)

        # Left: chain list
        self.chain_list = ChainListPanel()
        splitter.addWidget(self.chain_list)

        # Center: timeline
        self.timeline_panel = TimelinePanel()
        splitter.addWidget(self.timeline_panel)

        # Right: detail
        self.detail_panel = DetailPanel()
        splitter.addWidget(self.detail_panel)

        # Set sizes and stretch factors
        splitter.setSizes([320, 560, 560])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 2)
        splitter.setStretchFactor(2, 2)

        main_layout.addWidget(splitter, stretch=1)

        # Connect signals
        self.chain_list.chain_selected.connect(self._on_chain_selected)

        # Initial empty state
        self.timeline_panel.display_empty()
        self.detail_panel.display_empty()

    def _on_chain_selected(self, chain: AttackChain):
        """Handle chain selection."""
        try:
            chain_id = _safe_get_attr(chain, 'chain_id', '')
            storyline = self._storyline_map.get(chain_id)
            self.timeline_panel.display_chain(chain, storyline)
            self.detail_panel.display_storyline(chain, storyline)
        except Exception as e:
            print(f"Error displaying chain: {e}")

    def update_incident_view(self, analyzer):
        """Update tab with analysis results."""
        if not analyzer:
            return

        try:
            self._chains = (getattr(analyzer, 'attack_chains', []) or
                          getattr(analyzer, 'chains', []))

            self._storylines = (getattr(analyzer, 'attack_storylines', []) or
                              getattr(analyzer, 'storylines', []))

            self._storyline_map = {
                _safe_get_attr(s, 'chain_id', ''): s
                for s in self._storylines
                if hasattr(s, 'chain_id')
            }

            # Update stat cards
            self.card_chains.set_value(str(len(self._chains)))

            ot_impact_count = sum(
                1 for c in self._chains
                if _safe_get_attr(c, 'has_ot_impact', False)
            )
            self.card_ot_impact.set_value(str(ot_impact_count))

            critical_count = sum(
                1 for c in self._chains
                if _safe_get_attr(c, 'overall_severity', '') == "CRITICAL"
            )
            self.card_critical.set_value(str(critical_count))

            self.card_storylines.set_value(str(len(self._storylines)))

            max_esc = max(
                (_safe_get_attr(c, 'ot_escalation_score', 0.0) for c in self._chains),
                default=0.0
            )
            self.card_max_esc.set_value(f"{max_esc:.2f}")

            # Populate chain list
            self.chain_list.populate(self._chains, self._storylines)

            # Auto-select first chain if available
            if self._chains:
                self.chain_list.select_first()
            else:
                self.timeline_panel.display_empty()
                self.detail_panel.display_empty()

        except Exception as e:
            print(f"Error updating incident view: {e}")
            import traceback
            traceback.print_exc()

    def update_theme(self):
        """Update theme when toggle is clicked.

        Note: This widget uses a custom DARK_THEME which is optimized for dark mode.
        The theme is independent of the global theme toggle to maintain visual consistency.
        Re-apply the dark theme styling when this method is called.
        """
        # Re-apply dark theme styling to main widget
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {DARK_THEME['bg_primary']};
                color: {DARK_THEME['text_primary']};
            }}
        """)

        # Refresh the currently selected chain display if one exists
        if self._chains and hasattr(self, 'chain_list') and self.chain_list._current_chain:
            self._on_chain_selected(self.chain_list._current_chain)