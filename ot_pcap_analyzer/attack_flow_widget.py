"""
OT PCAP Analyzer - Attack Flow Visualization Widget (Enhanced)
===============================================================
Enhanced widget for visualizing attack flow, network topology and attack paths.

Features:
- Interactive canvas with zoom/pan (QGraphicsView)
- Control toolbar with actions
- Summary statistics panel
- Node click for details
- Severity filtering
- Export to PNG/SVG
- Modern dark theme styling
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QGroupBox, QFrame, QScrollArea, QSplitter, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QToolBar, QAction, QComboBox,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem,
    QGraphicsTextItem, QGraphicsRectItem, QGraphicsDropShadowEffect,
    QGraphicsPathItem, QToolButton, QMenu, QMessageBox, QFileDialog,
    QGraphicsProxyWidget, QSpacerItem, QSizePolicy, QToolTip,
    QGraphicsPolygonItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QRectF, QPointF, QLineF, QTimer
from PyQt5.QtGui import (
    QFont, QColor, QPen, QBrush, QPainter, QPainterPath,
    QLinearGradient, QRadialGradient, QPixmap, QCursor, QPolygonF
)

from .gui_style import themed

from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict
import math

from .models import AttackChain, AttackPhase, AttackStoryline, SecurityAnomaly
from .utils import normalize_timestamp


# =============================================================================
# CONSTANTS - High Contrast Dark Theme
# =============================================================================

PHASE_COLORS = {
    "RECONNAISSANCE": "#74c0fc",
    "INITIAL_ACCESS": "#bc8cff",
    "EXECUTION": "#ff6b6b",
    "PERSISTENCE": "#ffa94d",
    "PRIVILEGE_ESCALATION": "#ff6b6b",
    "LATERAL_MOVEMENT": "#ffa94d",
    "COLLECTION": "#bc8cff",
    "EXFILTRATION": "#ff6b6b",
    "IMPACT": "#ff4444",
}

PHASE_ICONS = {
    "RECONNAISSANCE": "RECON",
    "INITIAL_ACCESS": "ENTRY",
    "EXECUTION": "EXEC",
    "PERSISTENCE": "PERSIST",
    "PRIVILEGE_ESCALATION": "PRIV ESC",
    "LATERAL_MOVEMENT": "LATERAL",
    "COLLECTION": "COLLECT",
    "EXFILTRATION": "EXFIL",
    "IMPACT": "IMPACT",
}

# Node colors for network topology
NODE_COLORS = {
    "attacker": {"fill": "#5c1f1f", "stroke": "#ff4444", "text": "#ff6b6b"},
    "compromised": {"fill": "#5c3a1f", "stroke": "#ff9933", "text": "#ffa94d"},
    "ot_device": {"fill": "#3d1f5c", "stroke": "#bc8cff", "text": "#d4a5ff"},
    "it_device": {"fill": "#1f3d5c", "stroke": "#58a6ff", "text": "#74c0fc"},
    "normal": {"fill": "#2d333b", "stroke": "#3d444d", "text": "#8b949e"},
}

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff9933",
    "MEDIUM": "#ffcc00",
    "LOW": "#66cc66",
}


# =============================================================================
# CUSTOM GRAPHICS ITEMS
# =============================================================================

class NetworkNode(QGraphicsEllipseItem):
    """Interactive network node with hover effects and click handling"""

    def __init__(self, ip: str, node_type: str, x: float, y: float, radius: float = 40):
        super().__init__(-radius, -radius, radius * 2, radius * 2)
        self.ip = ip
        self.node_type = node_type
        self.radius = radius
        self.info = {}  # Additional info dict

        # Position
        self.setPos(x, y)

        # Colors based on type
        colors = NODE_COLORS.get(node_type, NODE_COLORS["normal"])
        self.base_fill = themed(colors["fill"], "bg")
        self.stroke_color = themed(colors["stroke"], "fg")
        self.text_color = themed(colors["text"], "fg")

        # Styling
        self.setPen(QPen(self.stroke_color, 3))
        self.setBrush(QBrush(self.base_fill))

        # Enable interactions
        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsEllipseItem.ItemIsSelectable, True)
        self.setCursor(QCursor(Qt.PointingHandCursor))

        # Add label
        self._add_label()

        # Drop shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 120))
        shadow.setOffset(3, 3)
        self.setGraphicsEffect(shadow)

    def _add_label(self):
        """Add IP label below the node"""
        # IP text (truncated if too long)
        display_ip = self.ip if len(self.ip) <= 15 else self.ip[:12] + "..."

        # Main label
        self.label = QGraphicsTextItem(display_ip, self)
        self.label.setDefaultTextColor(self.text_color)
        font = QFont("JetBrains Mono", 9, QFont.Bold)
        self.label.setFont(font)

        # Center the label below node
        text_width = self.label.boundingRect().width()
        self.label.setPos(-text_width / 2, self.radius + 5)

        # Type badge
        type_labels = {
            "attacker": "Attacker",
            "compromised": "Target",
            "ot_device": "OT/ICS",
            "it_device": "IT",
            "normal": "Host",
        }
        type_text = type_labels.get(self.node_type, "Node")
        self.type_label = QGraphicsTextItem(type_text, self)
        self.type_label.setDefaultTextColor(themed("#8b949e", "fg"))
        font2 = QFont("Inter", 8)
        self.type_label.setFont(font2)

        type_width = self.type_label.boundingRect().width()
        self.type_label.setPos(-type_width / 2, self.radius + 22)

    def hoverEnterEvent(self, event):
        """Highlight on hover"""
        self.setPen(QPen(self.stroke_color, 4))
        # Lighten fill
        lighter = self.base_fill.lighter(120)
        self.setBrush(QBrush(lighter))

        # Show tooltip with details
        tooltip = f"<b>{self.ip}</b><br/>"
        tooltip += f"Type: {self.node_type.replace('_', ' ').title()}<br/>"
        if self.info:
            if 'event_count' in self.info:
                tooltip += f"Events: {self.info['event_count']}<br/>"
            if 'severity' in self.info:
                tooltip += f"Severity: {self.info['severity']}"

        QToolTip.showText(event.screenPos(), tooltip)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        """Reset on hover leave"""
        self.setPen(QPen(self.stroke_color, 3))
        self.setBrush(QBrush(self.base_fill))
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):
        """Handle click"""
        if event.button() == Qt.LeftButton:
            # Emit signal or show detail (handled by parent)
            scene = self.scene()
            if hasattr(scene, 'node_clicked'):
                scene.node_clicked.emit(self.ip, self.node_type, self.info)
        super().mousePressEvent(event)


class AttackArrow(QGraphicsPathItem):
    """Curved arrow showing attack direction"""

    def __init__(self, start: QPointF, end: QPointF, severity: str = "MEDIUM", label: str = ""):
        super().__init__()

        self.severity = severity
        self.arrow_label = label

        # Color based on severity
        color = themed(SEVERITY_COLORS.get(severity, "#ffd43b"), "fg")
        self.setPen(QPen(color, 3, Qt.DashLine))

        # Build curved path
        path = QPainterPath()
        path.moveTo(start)

        # Calculate control point for curve
        mid_x = (start.x() + end.x()) / 2
        mid_y = (start.y() + end.y()) / 2

        # Offset control point perpendicular to line
        dx = end.x() - start.x()
        dy = end.y() - start.y()
        length = math.sqrt(dx * dx + dy * dy)

        if length > 0:
            # Perpendicular offset
            offset = min(50, length * 0.2)
            ctrl_x = mid_x - (dy / length) * offset
            ctrl_y = mid_y + (dx / length) * offset
        else:
            ctrl_x, ctrl_y = mid_x, mid_y

        path.quadTo(QPointF(ctrl_x, ctrl_y), end)
        self.setPath(path)

        # Add arrowhead
        self._add_arrowhead(QPointF(ctrl_x, ctrl_y), end, color)

        # Add label if provided
        if label:
            self._add_label(QPointF(ctrl_x, ctrl_y), label, color)

    def _add_arrowhead(self, control: QPointF, end: QPointF, color: QColor):
        """Add arrowhead at the end"""
        # Calculate direction from control to end
        dx = end.x() - control.x()
        dy = end.y() - control.y()
        length = math.sqrt(dx * dx + dy * dy)

        if length > 0:
            # Normalize
            dx /= length
            dy /= length

            # Arrowhead size
            size = 12

            # Points for arrowhead
            p1 = end
            p2 = QPointF(end.x() - size * dx + size * 0.5 * dy,
                         end.y() - size * dy - size * 0.5 * dx)
            p3 = QPointF(end.x() - size * dx - size * 0.5 * dy,
                         end.y() - size * dy + size * 0.5 * dx)

            # Create arrowhead
            arrow = QGraphicsPolygonItem(QPolygonF([p1, p2, p3]), self)
            arrow.setBrush(QBrush(color))
            arrow.setPen(QPen(Qt.NoPen))

    def _add_label(self, pos: QPointF, label: str, color: QColor):
        """Add label near the arrow"""
        text = QGraphicsTextItem(label, self)
        text.setDefaultTextColor(color)
        font = QFont("Inter", 8, QFont.Bold)
        text.setFont(font)
        text.setPos(pos.x() - text.boundingRect().width() / 2,
                    pos.y() - text.boundingRect().height() / 2)


class ZoneRect(QGraphicsRectItem):
    """Network zone rectangle with label"""

    def __init__(self, x: float, y: float, width: float, height: float,
                 zone_type: str, label: str):
        super().__init__(x, y, width, height)

        self.zone_type = zone_type

        # Colors based on zone
        zone_colors = {
            "internet": ("#2d1b1b", "#ff4444"),
            "dmz": ("#2d2d1b", "#ffd43b"),
            "it": ("#1b2d3d", "#58a6ff"),
            "ot": ("#2d1b3d", "#bc8cff"),
        }

        fill_color, stroke_color = zone_colors.get(zone_type, ("#1c2128", "#3d444d"))

        # Styling
        self.setPen(QPen(themed(stroke_color, "fg"), 2, Qt.DashLine))
        self.setBrush(QBrush(themed(fill_color, "bg")))
        self.setOpacity(0.85)

        # Z-value to put zones behind nodes
        self.setZValue(-10)

        # Add label
        self._add_label(label, themed(stroke_color, "fg"))

    def _add_label(self, label: str, color: QColor):
        """Add zone label"""
        text = QGraphicsTextItem(label, self)
        text.setDefaultTextColor(color)
        font = QFont("Inter", 12, QFont.Bold)
        text.setFont(font)

        # Position at top-left of zone
        rect = self.rect()
        text.setPos(rect.x() + 10, rect.y() + 5)


# =============================================================================
# INTERACTIVE NETWORK SCENE
# =============================================================================

class NetworkGraphicsScene(QGraphicsScene):
    """Custom scene with signals for node interaction"""

    node_clicked = pyqtSignal(str, str, dict)  # ip, type, info

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setBackgroundBrush(QBrush(themed("#0d1117", "bg")))

        self.nodes = {}  # ip -> NetworkNode
        self.arrows = []  # List of AttackArrow
        self.zones = []  # List of ZoneRect

    def clear_all(self):
        """Clear all items (and pick up the current theme's background)"""
        self.clear()
        self.setBackgroundBrush(QBrush(themed("#0d1117", "bg")))
        self.nodes = {}
        self.arrows = []
        self.zones = []

    def add_network_node(self, ip: str, node_type: str, x: float, y: float,
                         radius: float = 40, info: dict = None) -> NetworkNode:
        """Add a network node"""
        node = NetworkNode(ip, node_type, x, y, radius)
        if info:
            node.info = info
        self.addItem(node)
        self.nodes[ip] = node
        return node

    def add_attack_arrow(self, src_ip: str, dst_ip: str, severity: str = "MEDIUM",
                         label: str = "") -> Optional[AttackArrow]:
        """Add attack arrow between nodes"""
        if src_ip not in self.nodes or dst_ip not in self.nodes:
            return None

        src_node = self.nodes[src_ip]
        dst_node = self.nodes[dst_ip]

        # Calculate start/end at node edges
        src_pos = src_node.pos()
        dst_pos = dst_node.pos()

        dx = dst_pos.x() - src_pos.x()
        dy = dst_pos.y() - src_pos.y()
        length = math.sqrt(dx * dx + dy * dy)

        if length > 0:
            # Offset by radius
            src_radius = src_node.radius
            dst_radius = dst_node.radius

            start = QPointF(src_pos.x() + (dx / length) * src_radius,
                           src_pos.y() + (dy / length) * src_radius)
            end = QPointF(dst_pos.x() - (dx / length) * dst_radius,
                         dst_pos.y() - (dy / length) * dst_radius)
        else:
            start = src_pos
            end = dst_pos

        arrow = AttackArrow(start, end, severity, label)
        self.addItem(arrow)
        self.arrows.append(arrow)
        return arrow

    def add_zone(self, x: float, y: float, width: float, height: float,
                 zone_type: str, label: str) -> ZoneRect:
        """Add a network zone"""
        zone = ZoneRect(x, y, width, height, zone_type, label)
        self.addItem(zone)
        self.zones.append(zone)
        return zone


# =============================================================================
# INTERACTIVE NETWORK VIEW
# =============================================================================

class NetworkGraphicsView(QGraphicsView):
    """Zoomable, pannable view for network visualization"""

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform |
                           QPainter.TextAntialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # Zoom level
        self._zoom = 1.0
        self._min_zoom = 0.3
        self._max_zoom = 3.0

        # Styling
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)

    def wheelEvent(self, event):
        """Handle zoom with mouse wheel"""
        factor = 1.15

        if event.angleDelta().y() > 0:
            # Zoom in
            if self._zoom < self._max_zoom:
                self._zoom *= factor
                self.scale(factor, factor)
        else:
            # Zoom out
            if self._zoom > self._min_zoom:
                self._zoom /= factor
                self.scale(1 / factor, 1 / factor)

    def zoom_in(self):
        """Zoom in programmatically"""
        if self._zoom < self._max_zoom:
            self._zoom *= 1.2
            self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out programmatically"""
        if self._zoom > self._min_zoom:
            self._zoom /= 1.2
            self.scale(1 / 1.2, 1 / 1.2)

    def zoom_fit(self):
        """Fit all content in view"""
        self.fitInView(self.scene().sceneRect(), Qt.KeepAspectRatio)
        self._zoom = 1.0

    def zoom_reset(self):
        """Reset to 100% zoom"""
        self.resetTransform()
        self._zoom = 1.0


# =============================================================================
# SUMMARY STATISTICS PANEL
# =============================================================================

class StatisticsPanel(QFrame):
    """Panel showing attack statistics"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
            }
        """)
        self.setMinimumHeight(100)
        self.setMaximumHeight(120)

        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(20)

        # Create stat boxes
        self.stat_boxes = {}

        stats = [
            ("total_events", "TOTAL EVENTS", "0", "#58a6ff"),
            ("critical", "CRITICAL", "0", "#ff4444"),
            ("high", "HIGH", "0", "#ff9933"),
            ("sources", "ATTACK SOURCES", "0", "#bc8cff"),
            ("targets", "TARGETS", "0", "#ffa94d"),
            ("ot_impact", "OT IMPACT", "N/A", "#ff6b6b"),
        ]

        for key, label, value, color in stats:
            box = self._create_stat_box(label, value, color)
            self.stat_boxes[key] = box
            layout.addWidget(box)

        layout.addStretch()

    def _create_stat_box(self, label: str, value: str, color: str) -> QFrame:
        """Create a statistics box"""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
            }}
        """)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        # Label
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: #8b949e; font-size: 10px; font-weight: 600;")
        lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl)

        # Value
        val = QLabel(value)
        val.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: 700;")
        val.setAlignment(Qt.AlignCenter)
        val.setObjectName("value")
        layout.addWidget(val)

        return frame

    def update_stats(self, stats: dict):
        """Update statistics values"""
        for key, value in stats.items():
            if key in self.stat_boxes:
                box = self.stat_boxes[key]
                val_label = box.findChild(QLabel, "value")
                if val_label:
                    val_label.setText(str(value))


# =============================================================================
# ATTACK FLOW PANEL (Left side - Phase visualization)
# =============================================================================

class AttackFlowPanel(QGroupBox):
    """Panel showing attack phases in timeline format"""

    def __init__(self, parent=None):
        super().__init__("Attack Flow Timeline", parent)
        self.setStyleSheet("""
            QGroupBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 0px;
                padding: 16px;
                padding-top: 32px;
                font-weight: 600;
                font-size: 14px;
                color: #f0f6fc;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 4px 16px;
                background-color: #21262d;
                border-radius: 4px;
                color: #58a6ff;
            }
        """)

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Scroll area for phases
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background-color: #21262d;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background-color: #484f58;
                border-radius: 4px;
            }
        """)

        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(8, 8, 8, 8)
        self.content_layout.setSpacing(12)
        self.content_layout.addStretch()

        scroll.setWidget(self.content)
        layout.addWidget(scroll)

    def clear_phases(self):
        """Clear all phase widgets"""
        while self.content_layout.count() > 1:
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def add_phase(self, phase_name: str, description: str, severity: str,
                  timestamp: str, event_count: int, mitre: list = None):
        """Add a phase card"""
        card = self._create_phase_card(phase_name, description, severity,
                                       timestamp, event_count, mitre)
        self.content_layout.insertWidget(self.content_layout.count() - 1, card)

    def _create_phase_card(self, phase_name: str, description: str, severity: str,
                          timestamp: str, event_count: int, mitre: list = None) -> QFrame:
        """Create a phase card widget"""
        color = PHASE_COLORS.get(phase_name, "#6b7280")
        icon = PHASE_ICONS.get(phase_name, "PHASE")

        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #21262d;
                border-left: 4px solid {color};
                border-radius: 6px;
                padding: 12px;
            }}
            QFrame:hover {{
                background-color: #30363d;
            }}
        """)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)

        # Header row
        header = QHBoxLayout()

        # Phase name with icon
        name_lbl = QLabel(f"[{icon}] {phase_name.replace('_', ' ')}")
        name_lbl.setStyleSheet(f"color: {color}; font-weight: 700; font-size: 13px;")
        header.addWidget(name_lbl)

        # Severity badge
        sev_color = SEVERITY_COLORS.get(severity, "#6b7280")
        sev_lbl = QLabel(severity)
        sev_lbl.setStyleSheet(f"""
            background-color: {sev_color}30;
            color: {sev_color};
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
        """)
        header.addWidget(sev_lbl)
        header.addStretch()

        layout.addLayout(header)

        # Timestamp
        time_lbl = QLabel(f"Time: {timestamp}")
        time_lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
        layout.addWidget(time_lbl)

        # Description
        desc_lbl = QLabel(description[:100] + "..." if len(description) > 100 else description)
        desc_lbl.setStyleSheet("color: #c9d1d9; font-size: 12px;")
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)

        # Footer with event count and MITRE
        footer = QHBoxLayout()

        event_lbl = QLabel(f"{event_count} events")
        event_lbl.setStyleSheet("color: #8b949e; font-size: 10px;")
        footer.addWidget(event_lbl)

        if mitre:
            mitre_str = ", ".join(mitre[:2])
            if len(mitre) > 2:
                mitre_str += f" +{len(mitre)-2}"
            mitre_lbl = QLabel(f"MITRE: {mitre_str}")
            mitre_lbl.setStyleSheet("color: #bc8cff; font-size: 10px;")
            footer.addWidget(mitre_lbl)

        footer.addStretch()
        layout.addLayout(footer)

        return card

    def display_no_chain(self):
        """Display when no attack chain detected"""
        self.clear_phases()

        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #1a3d2e;
                border: 1px solid #3fb950;
                border-radius: 8px;
                padding: 24px;
            }
        """)

        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignCenter)

        icon = QLabel("✓")
        icon.setStyleSheet("font-size: 36px; color: #3fb950;")
        icon.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon)

        msg = QLabel("No organized attack chain detected")
        msg.setStyleSheet("color: #3fb950; font-size: 14px; font-weight: 600;")
        msg.setAlignment(Qt.AlignCenter)
        layout.addWidget(msg)

        hint = QLabel("Network traffic appears normal, or the events are not correlated")
        hint.setStyleSheet("color: #7ee787; font-size: 12px;")
        hint.setAlignment(Qt.AlignCenter)
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.content_layout.insertWidget(0, card)

    def display_anomaly_summary(self, anomalies: list):
        """Display anomaly summary when no formal chain exists"""
        self.clear_phases()

        # Header card
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: #5c3a1f;
                border: 1px solid #ff9933;
                border-radius: 8px;
                padding: 16px;
            }
        """)

        h_layout = QVBoxLayout(header)

        title = QLabel(f"Detected {len(anomalies)} anomalous events")
        title.setStyleSheet("color: #ffd43b; font-size: 16px; font-weight: 700;")
        h_layout.addWidget(title)

        subtitle = QLabel("Not enough evidence to identify an attack chain, but some events need review")
        subtitle.setStyleSheet("color: #ffe066; font-size: 12px;")
        subtitle.setWordWrap(True)
        h_layout.addWidget(subtitle)

        self.content_layout.insertWidget(0, header)

        # Group by type
        by_type = defaultdict(list)
        for a in anomalies:
            by_type[a.anomaly_type].append(a)

        # Show top types as cards
        sorted_types = sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True)

        for atype, items in sorted_types[:8]:
            critical = sum(1 for i in items if i.severity == "CRITICAL")
            high = sum(1 for i in items if i.severity == "HIGH")

            max_sev = "CRITICAL" if critical > 0 else ("HIGH" if high > 0 else "MEDIUM")

            self.add_phase(
                phase_name=atype,
                description=f"Detected {len(items)} events of this type. Critical: {critical}, High: {high}",
                severity=max_sev,
                timestamp="Multiple",
                event_count=len(items),
                mitre=None
            )


# =============================================================================
# MAIN ATTACK FLOW WIDGET
# =============================================================================

class AttackFlowWidget(QWidget):
    """Main widget combining attack flow, topology, and controls"""

    def __init__(self, parent=None):
        super().__init__(parent)

        self.current_anomalies = []
        self.current_chain = None
        self.current_assets = {}

        self._init_ui()
        self._connect_signals()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # ===== HEADER =====
        header = QHBoxLayout()

        title = QLabel("Attack Flow & Network Visualization")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #f0f6fc;")
        header.addWidget(title)

        header.addStretch()

        # ===== TOOLBAR =====
        self.toolbar = self._create_toolbar()
        header.addWidget(self.toolbar)

        main_layout.addLayout(header)

        # ===== STATISTICS PANEL =====
        self.stats_panel = StatisticsPanel()
        main_layout.addWidget(self.stats_panel)

        # ===== MAIN CONTENT SPLITTER =====
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(4)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #30363d;
            }
            QSplitter::handle:hover {
                background-color: #58a6ff;
            }
        """)

        # Left panel: Attack Flow Timeline
        self.flow_panel = AttackFlowPanel()
        splitter.addWidget(self.flow_panel)

        # Right panel: Network Topology (Interactive)
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        # Network label
        net_label = QLabel("Network Topology")
        net_label.setStyleSheet("""
            color: #58a6ff;
            font-size: 14px;
            font-weight: 600;
            background-color: #21262d;
            padding: 8px 16px;
            border-radius: 4px;
        """)
        right_layout.addWidget(net_label)

        # Graphics view
        self.scene = NetworkGraphicsScene()
        self.view = NetworkGraphicsView()
        self.view.setScene(self.scene)
        right_layout.addWidget(self.view)

        # Zoom controls
        zoom_layout = QHBoxLayout()
        zoom_layout.addStretch()

        self.btn_zoom_out = QPushButton("-")
        self.btn_zoom_out.setFixedSize(32, 32)
        self.btn_zoom_out.setStyleSheet(self._get_zoom_button_style())
        zoom_layout.addWidget(self.btn_zoom_out)

        self.btn_zoom_fit = QPushButton("Fit")
        self.btn_zoom_fit.setFixedSize(48, 32)
        self.btn_zoom_fit.setStyleSheet(self._get_zoom_button_style())
        zoom_layout.addWidget(self.btn_zoom_fit)

        self.btn_zoom_in = QPushButton("+")
        self.btn_zoom_in.setFixedSize(32, 32)
        self.btn_zoom_in.setStyleSheet(self._get_zoom_button_style())
        zoom_layout.addWidget(self.btn_zoom_in)

        right_layout.addLayout(zoom_layout)

        splitter.addWidget(right_container)

        # Set splitter sizes (40% flow, 60% topology)
        splitter.setSizes([400, 600])

        main_layout.addWidget(splitter, 1)

        # ===== DETAIL PANEL (collapsible) =====
        self.detail_panel = QFrame()
        self.detail_panel.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        self.detail_panel.setMaximumHeight(150)
        self.detail_panel.setVisible(False)

        detail_layout = QVBoxLayout(self.detail_panel)
        self.detail_label = QLabel("Click a node to view details")
        self.detail_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        self.detail_label.setWordWrap(True)
        detail_layout.addWidget(self.detail_label)

        main_layout.addWidget(self.detail_panel)

    def _create_toolbar(self) -> QFrame:
        """Create toolbar with action buttons"""
        toolbar = QFrame()
        toolbar.setStyleSheet("""
            QFrame {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
        """)

        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(8)

        # Severity filter
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #30363d;
                color: #f0f6fc;
                border: 1px solid #484f58;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 120px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 6px solid #8b949e;
                margin-right: 8px;
            }
            QComboBox QAbstractItemView {
                background-color: #30363d;
                color: #f0f6fc;
                selection-background-color: #484f58;
            }
        """)
        layout.addWidget(self.filter_combo)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet("background-color: #484f58;")
        layout.addWidget(sep)

        # Refresh button
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setStyleSheet(self._get_toolbar_button_style())
        layout.addWidget(self.btn_refresh)

        # Export button
        self.btn_export = QPushButton("Export")
        self.btn_export.setStyleSheet(self._get_toolbar_button_style())
        layout.addWidget(self.btn_export)

        return toolbar

    def _get_toolbar_button_style(self) -> str:
        return """
            QPushButton {
                background-color: #30363d;
                color: #f0f6fc;
                border: 1px solid #484f58;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #484f58;
            }
            QPushButton:pressed {
                background-color: #21262d;
            }
        """

    def _get_zoom_button_style(self) -> str:
        return """
            QPushButton {
                background-color: #30363d;
                color: #f0f6fc;
                border: 1px solid #484f58;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 700;
                padding: 0;
                min-height: 0;
            }
            QPushButton:hover {
                background-color: #484f58;
            }
        """

    def _connect_signals(self):
        """Connect widget signals"""
        self.btn_zoom_in.clicked.connect(self.view.zoom_in)
        self.btn_zoom_out.clicked.connect(self.view.zoom_out)
        self.btn_zoom_fit.clicked.connect(self.view.zoom_fit)

        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)
        self.btn_export.clicked.connect(self._export_topology)
        self.btn_refresh.clicked.connect(self._refresh_display)

        self.scene.node_clicked.connect(self._on_node_clicked)

    def _on_filter_changed(self, text: str):
        """Handle severity filter change"""
        self._refresh_display()

    def _on_node_clicked(self, ip: str, node_type: str, info: dict):
        """Handle node click - show details"""
        self.detail_panel.setVisible(True)

        details = f"<b>IP:</b> {ip}<br/>"
        details += f"<b>Type:</b> {node_type.replace('_', ' ').title()}<br/>"

        if info:
            for key, value in info.items():
                details += f"<b>{key.replace('_', ' ').title()}:</b> {value}<br/>"

        self.detail_label.setText(details)

    def _export_topology(self):
        """Export topology as image"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Topology",
            "attack_topology.png",
            "PNG Files (*.png);;All Files (*)"
        )

        if file_path:
            # Render scene to pixmap
            rect = self.scene.sceneRect()
            pixmap = QPixmap(int(rect.width()), int(rect.height()))
            pixmap.fill(themed("#0d1117", "bg"))

            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            self.scene.render(painter)
            painter.end()

            pixmap.save(file_path)
            QMessageBox.information(self, "Export", f"Topology saved to:\n{file_path}")

    def _refresh_display(self):
        """Refresh the display with current data"""
        if self.current_chain:
            self._build_chain_visualization(self.current_chain, self.current_assets)
        elif self.current_anomalies:
            self._build_anomaly_visualization(self.current_anomalies, self.current_assets)

    def update_from_analyzer(self, analyzer):
        """Update visualization from analyzer data"""
        self.current_anomalies = analyzer.anomalies if hasattr(analyzer, 'anomalies') else []
        self.current_chain = analyzer.attack_chains[0] if analyzer.attack_chains else None
        self.current_assets = analyzer.assets if hasattr(analyzer, 'assets') else {}

        if self.current_chain:
            self._build_chain_visualization(self.current_chain, self.current_assets)
            storyline = analyzer.storylines[0] if analyzer.storylines else None
            self._update_flow_panel(self.current_chain, storyline)
        elif self.current_anomalies:
            self._build_anomaly_visualization(self.current_anomalies, self.current_assets)
            self.flow_panel.display_anomaly_summary(self.current_anomalies)
        else:
            self.scene.clear_all()
            self.flow_panel.display_no_chain()
            self._update_stats_empty()

    def update_attack_flow(self, chain: AttackChain = None, storyline: AttackStoryline = None,
                          all_assets: Dict = None):
        """Update from attack chain directly"""
        self.current_chain = chain
        self.current_assets = all_assets or {}

        if chain:
            self._build_chain_visualization(chain, all_assets)
            self._update_flow_panel(chain, storyline)
        else:
            self.scene.clear_all()
            self.flow_panel.display_no_chain()
            self._update_stats_empty()

    def _update_stats_empty(self):
        """Update stats for empty state"""
        self.stats_panel.update_stats({
            "total_events": "0",
            "critical": "0",
            "high": "0",
            "sources": "0",
            "targets": "0",
            "ot_impact": "N/A"
        })

    def _update_flow_panel(self, chain: AttackChain, storyline: AttackStoryline = None):
        """Update the flow panel with chain phases"""
        self.flow_panel.clear_phases()

        for phase in chain.phases:
            try:
                ts = datetime.fromtimestamp(normalize_timestamp(phase.timestamp) or 0).strftime("%H:%M:%S")
            except:
                ts = "N/A"

            self.flow_panel.add_phase(
                phase_name=phase.phase_name,
                description=phase.description or "No description",
                severity=phase.severity,
                timestamp=ts,
                event_count=phase.event_count,
                mitre=phase.mitre_techniques
            )

    def _build_chain_visualization(self, chain: AttackChain, all_assets: dict):
        """Build network visualization from attack chain"""
        self.scene.clear_all()

        # Get severity filter
        filter_text = self.filter_combo.currentText()

        # Calculate layout
        width = 800
        height = 600

        # Zones
        zone_height = 150
        zone_margin = 20

        # Add zones
        self.scene.add_zone(zone_margin, zone_margin, width - 2*zone_margin, zone_height,
                          "internet", "INTERNET / EXTERNAL")

        self.scene.add_zone(zone_margin, zone_margin + zone_height + 30,
                          width - 2*zone_margin, zone_height,
                          "it", "IT NETWORK")

        self.scene.add_zone(zone_margin, zone_margin + 2*(zone_height + 30),
                          width - 2*zone_margin, zone_height,
                          "ot", "OT / ICS NETWORK")

        # Add nodes
        src_ips = [ip for ip in (chain.source_ips or []) if ip and ip.strip()]
        tgt_ips = [ip for ip in (chain.target_ips or []) if ip and ip.strip()]
        ot_ips = set([ip for ip in (chain.ot_assets_at_risk or []) if ip and ip.strip()])

        # Source IPs (attackers) in internet zone
        src_y = zone_margin + zone_height / 2
        src_x_start = 150
        src_spacing = 150

        for i, ip in enumerate(src_ips[:4]):
            x = src_x_start + i * src_spacing
            self.scene.add_network_node(ip, "attacker", x, src_y, 35,
                                       {"role": "Attacker", "event_count": "N/A"})

        # Target IPs in IT zone
        it_y = zone_margin + zone_height + 30 + zone_height / 2
        it_targets = [ip for ip in tgt_ips if ip not in ot_ips]

        for i, ip in enumerate(it_targets[:4]):
            x = src_x_start + i * src_spacing
            node_type = "compromised"
            self.scene.add_network_node(ip, node_type, x, it_y, 35,
                                       {"role": "Target", "status": "Compromised"})

        # OT IPs in OT zone
        ot_y = zone_margin + 2*(zone_height + 30) + zone_height / 2

        for i, ip in enumerate(list(ot_ips)[:4]):
            x = src_x_start + i * src_spacing
            self.scene.add_network_node(ip, "ot_device", x, ot_y, 35,
                                       {"role": "OT Device", "status": "At Risk"})

        # Add attack arrows
        for src in src_ips[:3]:
            for tgt in it_targets[:3]:
                self.scene.add_attack_arrow(src, tgt, "HIGH", "Attack")

        if chain.has_ot_impact:
            for tgt in it_targets[:2]:
                for ot in list(ot_ips)[:2]:
                    self.scene.add_attack_arrow(tgt, ot, "CRITICAL", "Lateral")

        # Update stats
        self.stats_panel.update_stats({
            "total_events": sum(p.event_count for p in chain.phases),
            "critical": sum(1 for p in chain.phases if p.severity == "CRITICAL"),
            "high": sum(1 for p in chain.phases if p.severity == "HIGH"),
            "sources": len(src_ips),
            "targets": len(tgt_ips),
            "ot_impact": "YES" if chain.has_ot_impact else "NO"
        })

        # Fit view
        self.view.zoom_fit()

    def _build_anomaly_visualization(self, anomalies: list, all_assets: dict):
        """Build visualization from anomalies when no chain exists"""
        self.scene.clear_all()

        # Get severity filter
        filter_text = self.filter_combo.currentText()
        if filter_text != "All Severities":
            anomalies = [a for a in anomalies if a.severity == filter_text]

        # Collect IPs
        attack_sources = defaultdict(lambda: {"count": 0, "critical": 0, "high": 0, "targets": set()})
        attack_targets = defaultdict(lambda: {"count": 0, "sources": set()})

        for a in anomalies:
            if a.src_ip:
                attack_sources[a.src_ip]["count"] += 1
                if a.severity == "CRITICAL":
                    attack_sources[a.src_ip]["critical"] += 1
                elif a.severity == "HIGH":
                    attack_sources[a.src_ip]["high"] += 1
                if a.dst_ip:
                    attack_sources[a.src_ip]["targets"].add(a.dst_ip)
                    attack_targets[a.dst_ip]["count"] += 1
                    attack_targets[a.dst_ip]["sources"].add(a.src_ip)

        # Sort by threat level
        sorted_sources = sorted(attack_sources.items(),
                               key=lambda x: (x[1]["critical"], x[1]["high"], x[1]["count"]),
                               reverse=True)[:6]
        sorted_targets = sorted(attack_targets.items(),
                               key=lambda x: x[1]["count"],
                               reverse=True)[:6]

        # Layout
        width = 700
        src_x = 150
        tgt_x = 550
        y_start = 100
        y_spacing = 100

        # Add source nodes
        for i, (ip, data) in enumerate(sorted_sources):
            y = y_start + i * y_spacing
            severity = "CRITICAL" if data["critical"] > 0 else ("HIGH" if data["high"] > 0 else "MEDIUM")
            self.scene.add_network_node(ip, "attacker", src_x, y, 40,
                                       {"event_count": data["count"], "severity": severity})

        # Add target nodes
        for i, (ip, data) in enumerate(sorted_targets):
            y = y_start + i * y_spacing
            # Check if OT
            is_ot = False
            if all_assets and ip in all_assets:
                asset = all_assets[ip]
                protocols = getattr(asset, 'protocols_seen', set()) if hasattr(asset, 'protocols_seen') else set()
                OT_PROTOCOLS = {'MODBUS', 'S7COMM', 'DNP3', 'ENIP', 'BACNET', 'OPCUA', 'IEC104', 'MMS'}
                is_ot = any(p.upper() in OT_PROTOCOLS for p in protocols)

            node_type = "ot_device" if is_ot else "compromised"
            self.scene.add_network_node(ip, node_type, tgt_x, y, 40,
                                       {"event_count": data["count"]})

        # Add arrows
        for src_ip, src_data in sorted_sources[:5]:
            for tgt_ip in list(src_data["targets"])[:3]:
                if tgt_ip in [t[0] for t in sorted_targets]:
                    severity = "CRITICAL" if src_data["critical"] > 0 else "HIGH"
                    self.scene.add_attack_arrow(src_ip, tgt_ip, severity)

        # Update stats
        critical = sum(1 for a in anomalies if a.severity == "CRITICAL")
        high = sum(1 for a in anomalies if a.severity == "HIGH")

        self.stats_panel.update_stats({
            "total_events": len(anomalies),
            "critical": critical,
            "high": high,
            "sources": len(attack_sources),
            "targets": len(attack_targets),
            "ot_impact": "Check OT tab"
        })

        # Fit view
        self.view.zoom_fit()

    def clear_display(self):
        """Clear all displays"""
        self.scene.clear_all()
        self.flow_panel.clear_phases()
        self._update_stats_empty()
        self.detail_panel.setVisible(False)
