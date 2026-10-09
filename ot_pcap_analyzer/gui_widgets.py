"""
OT PCAP Analyzer - GUI building blocks
(metric cards, risk summary, sidebar, top bar, search bar, analysis worker)
"""
try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
        QProgressBar, QTableWidget, QFrame, QListWidget, QListWidgetItem,
        QScrollArea, QLineEdit
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QColor
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False


if HAS_PYQT5:
    from .version import VERSION

    # =========================================================================
    # COMPACT METRIC WIDGET - Enhanced Risk-first design with icons
    # =========================================================================

    class CompactMetric(QFrame):
        """Compact clickable metric with icon and improved visual design"""
        clicked = pyqtSignal(str)

        # Metric icons mapping
        METRIC_ICONS = {
            "total_assets": "◫",
            "ot_devices": "⚙",
            "it_devices": "◻",
            "unknown": "◇",
            "critical": "◉",
            "high": "◈",
            "medium": "◬",
            "low": "◇",
            "anomalies": "△",
            "alerts": "⚡",
            "packets": "▦",
            "default": "●"
        }

        # Tooltip descriptions for each metric type
        METRIC_TOOLTIPS = {
            "total": "Total devices detected in the PCAP\nClick to view all",
            "total_assets": "Total devices detected in the PCAP\nClick to view all",
            "ot": "OT/ICS devices (PLC, RTU, HMI)\nClick to show only OT devices",
            "ot_devices": "OT/ICS devices (PLC, RTU, HMI)\nClick to show only OT devices",
            "it": "IT devices (Server, Workstation)\nClick to show only IT devices",
            "it_devices": "IT devices (Server, Workstation)\nClick to show only IT devices",
            "unknown": "Devices of unidentified type\nClick to view and classify",
            "high_risk": "Devices at high/critical risk\nClick to view the list",
            "critical": "Number of CRITICAL alerts\nHighest severity level",
            "high": "Number of HIGH alerts\nShould be handled soon",
            "medium": "Number of MEDIUM alerts\nShould be monitored",
            "low": "Number of LOW alerts\nFor reference",
            "anomalies": "Total anomalies detected\nClick to view details",
            "packets": "Total packets analyzed",
        }

        def __init__(self, label: str, value: str = "0", color_key: str = "text_primary",
                     metric_id: str = "", theme_manager=None, icon: str = None, parent=None):
            super().__init__(parent)
            self.label_text = label
            self.metric_id = metric_id
            self.color_key = color_key
            self.theme_manager = theme_manager
            self.icon = icon or self.METRIC_ICONS.get(metric_id, self.METRIC_ICONS["default"])
            self.setObjectName("MetricCard")
            self.setCursor(Qt.PointingHandCursor)
            self.setMinimumHeight(80)
            self.setMinimumWidth(110)

            # Set tooltip based on metric type
            tooltip = self.METRIC_TOOLTIPS.get(metric_id, f"Click to filter by {label}")
            self.setToolTip(tooltip)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(14, 12, 14, 12)
            layout.setSpacing(6)

            # Top row: Icon and value
            top_row = QHBoxLayout()
            top_row.setSpacing(8)

            self.icon_label = QLabel(self.icon)
            self.icon_label.setStyleSheet("font-size: 16px;")
            top_row.addWidget(self.icon_label)

            top_row.addStretch()

            # Trend indicator (optional)
            self.trend_label = QLabel("")
            self.trend_label.setStyleSheet("font-size: 12px;")
            top_row.addWidget(self.trend_label)

            layout.addLayout(top_row)

            # Value (large number)
            self.value_label = QLabel(value)
            self.value_label.setObjectName("ValueLarge")
            self.value_label.setAlignment(Qt.AlignLeft)
            layout.addWidget(self.value_label)

            # Label (small text)
            self.label_label = QLabel(label)
            self.label_label.setObjectName("SectionTitle")
            layout.addWidget(self.label_label)

            self.update_theme()

        def mousePressEvent(self, event):
            if event.button() == Qt.LeftButton:
                self.clicked.emit(self.metric_id)
            super().mousePressEvent(event)

        def set_value(self, value: str):
            self.value_label.setText(value)

        def set_trend(self, trend: str, is_positive: bool = True):
            """Set trend indicator (e.g., '↑ 12%' or '↓ 5%')"""
            color = "#69db7c" if is_positive else "#ff6b6b"
            self.trend_label.setText(trend)
            self.trend_label.setStyleSheet(f"font-size: 11px; color: {color}; font-weight: 600;")

        def update_theme(self):
            if not self.theme_manager:
                return
            t = self.theme_manager.THEMES[self.theme_manager.current_theme]
            color = t.get(self.color_key, t['text_primary'])
            fs = self.theme_manager.scale_font(28)
            label_fs = self.theme_manager.scale_font(11)
            icon_fs = self.theme_manager.scale_font(16)
            self.value_label.setStyleSheet(f"color: {color}; font-size: {fs}px; font-weight: 700;")
            self.label_label.setStyleSheet(f"color: {t['text_secondary']}; font-size: {label_fs}px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;")
            self.icon_label.setStyleSheet(f"color: {color}; font-size: {icon_fs}px;")


    # =========================================================================
    # RISK SUMMARY WIDGET
    # =========================================================================

    class RiskSummaryWidget(QFrame):
        """Risk distribution summary with visual bars"""

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.setObjectName("MetricCard")

            layout = QVBoxLayout(self)
            layout.setContentsMargins(16, 12, 16, 12)
            layout.setSpacing(8)

            # Title with icon
            title_row = QHBoxLayout()
            title_icon = QLabel("◉")
            title_icon.setStyleSheet("font-size: 14px; color: #ff6b6b;")
            title_row.addWidget(title_icon)
            title = QLabel("RISK DISTRIBUTION")
            title.setObjectName("SectionTitle")
            title_row.addWidget(title)
            title_row.addStretch()
            layout.addLayout(title_row)

            # Risk bars container
            self.bars_layout = QVBoxLayout()
            self.bars_layout.setSpacing(8)
            layout.addLayout(self.bars_layout)

            self.risk_data = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            self._create_bars()

        def _create_bars(self):
            # Clear existing
            while self.bars_layout.count():
                item = self.bars_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            self.bar_widgets = {}
            risk_levels = [
                ("critical", "◉ CRITICAL", "#ff6b6b"),
                ("high", "◈ HIGH", "#ffa94d"),
                ("medium", "◬ MEDIUM", "#ffd43b"),
                ("low", "◇ LOW", "#69db7c"),
            ]

            for key, label, color in risk_levels:
                row = QHBoxLayout()
                row.setSpacing(10)

                # Label with icon
                lbl = QLabel(label)
                lbl.setFixedWidth(90)
                lbl.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {color};")
                row.addWidget(lbl)

                # Bar container with rounded corners
                bar_bg = QFrame()
                bar_bg.setFixedHeight(10)
                bar_bg.setStyleSheet("background-color: #3d444d; border-radius: 5px;")

                bar_fill = QFrame(bar_bg)
                bar_fill.setFixedHeight(10)
                bar_fill.setGeometry(0, 0, 0, 10)
                self.bar_widgets[key] = (bar_bg, bar_fill, lbl)

                row.addWidget(bar_bg, 1)

                # Count with badge style
                count_lbl = QLabel("0")
                count_lbl.setFixedWidth(45)
                count_lbl.setAlignment(Qt.AlignCenter)
                count_lbl.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {color}; background-color: {color}20; border-radius: 4px; padding: 2px 6px;")
                self.bar_widgets[key] = (bar_bg, bar_fill, count_lbl)
                row.addWidget(count_lbl)

                self.bars_layout.addLayout(row)

        def update_risk(self, critical: int, high: int, medium: int, low: int):
            """Update risk distribution"""
            self.risk_data = {"critical": critical, "high": high, "medium": medium, "low": low}
            total = max(critical + high + medium + low, 1)

            colors = {
                "critical": "#ff6b6b",
                "high": "#ffa94d",
                "medium": "#ffd43b",
                "low": "#69db7c"
            }

            for key, (bar_bg, bar_fill, count_lbl) in self.bar_widgets.items():
                count = self.risk_data[key]
                pct = (count / total) * 100
                width = int((count / total) * bar_bg.width()) if bar_bg.width() > 0 else 0
                color = colors[key]

                bar_fill.setStyleSheet(f"background-color: {color}; border-radius: 5px;")
                bar_fill.setFixedWidth(max(width, 0))
                count_lbl.setText(str(count))
                count_lbl.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {color}; background-color: {color}20; border-radius: 4px; padding: 2px 6px;")

        def resizeEvent(self, event):
            super().resizeEvent(event)
            # Recalculate bar widths on resize
            if hasattr(self, 'risk_data'):
                self.update_risk(**self.risk_data)


    # =========================================================================
    # SIDEBAR NAVIGATION - Enhanced with modern icons
    # =========================================================================

    class SidebarNavigation(QWidget):
        """
        Vertical sidebar navigation for SOC-style layout with GROUPED WORKFLOW.

        Navigation is organized into workflow sections:
        - TRIAGE: Quick overview and alerts
        - ANALYZE: Deep dive into data
        - THREAT: Threat modeling and intelligence
        - REPORT: Incidents and history
        """
        navigation_changed = pyqtSignal(int)
        theme_changed = pyqtSignal()  # Signal to notify MainWindow to refresh theme

        # Grouped navigation with workflow sections
        # Format: (section_name, section_icon, [(key, icon, label, tooltip), ...])
        NAV_SECTIONS = [
            ("TRIAGE", "▶", [
                ("dashboard", "◉", "Dashboard", "Security Overview"),
                ("anomalies", "△", "Alerts", "Alerts & Anomalies"),
            ]),
            ("ANALYZE", "▶", [
                ("assets", "◫", "Assets", "Network Assets"),
                ("ot_events", "⚙", "OT Events", "OT/ICS Protocol Events"),
                ("attack_flow", "◈", "Attack Flow", "Attack Chain"),
            ]),
            ("THREAT", "▶", [
                ("threat_model", "◎", "MITRE ATT&CK", "MITRE Matrix - Threat Mapping"),
                ("ioc", "◐", "IOC Analysis", "Indicators of Compromise"),
                ("threat_intel", "◆", "Threat Intel", "Threat Intelligence"),
            ]),
            ("REPORT", "▶", [
                ("incidents", "⚡", "Incidents", "Incident Reports & Stories"),
                ("history", "◷", "History", "Analysis History"),
            ]),
        ]

        # Flat list for backward compatibility (maps view index to content stack index)
        NAV_ITEMS = [
            ("dashboard", "◉", "Dashboard", "System overview"),
            ("assets", "◫", "Assets", "Asset management"),
            ("attack_flow", "◈", "Attack Flow", "Attack flow"),
            ("threat_model", "◎", "Threat Model", "Threat model"),
            ("anomalies", "△", "Anomalies", "Detected anomalies"),
            ("ot_events", "⚙", "OT Events", "OT/ICS events"),
            ("ioc", "◐", "IOC Analysis", "Indicator analysis"),
            ("incidents", "⚡", "Incidents", "Security incidents"),
            ("threat_intel", "◆", "Threat Intel", "Threat Intelligence"),
            ("history", "◷", "History", "Analysis history"),
        ]

        # Mapping from nav key to content stack index (original order)
        KEY_TO_INDEX = {
            "dashboard": 0,
            "assets": 1,
            "attack_flow": 2,
            "threat_model": 3,
            "anomalies": 4,
            "ot_events": 5,
            "ioc": 6,
            "incidents": 7,
            "threat_intel": 8,
            "history": 9,
        }

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.setObjectName("Sidebar")
            self.setFixedWidth(240)  # Wider for grouped layout

            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            # Logo / App title with tagline - store references for theme updates
            header = QWidget()
            header_layout = QVBoxLayout(header)
            header_layout.setContentsMargins(16, 16, 16, 12)
            header_layout.setSpacing(4)

            self.logo_label = QLabel("OT PCAP Analyzer")
            header_layout.addWidget(self.logo_label)

            self.tagline_label = QLabel("Advanced Threat Detection")
            header_layout.addWidget(self.tagline_label)

            self.version_label = QLabel(f"Version {VERSION}")
            header_layout.addWidget(self.version_label)

            layout.addWidget(header)

            # Store section headers for theme updates
            self.section_headers = []

            # Separator
            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet("background-color: #3d444d;")
            sep.setFixedHeight(1)
            layout.addWidget(sep)

            # Custom icons mapping with colors for active state
            self.icon_colors = {
                "dashboard": "#74c0fc",
                "assets": "#bc8cff",
                "attack_flow": "#ff6b6b",
                "threat_model": "#ffa94d",
                "anomalies": "#ffd43b",
                "ot_events": "#63e6be",
                "ioc": "#69db7c",
                "incidents": "#ff6b6b",
                "threat_intel": "#74c0fc",
                "history": "#adb5bd",
            }

            # Section colors for workflow guidance
            self.section_colors = {
                "TRIAGE": "#ff6b6b",    # Red - urgent attention
                "ANALYZE": "#74c0fc",   # Blue - deep dive
                "THREAT": "#ffd43b",    # Yellow - threat intel
                "REPORT": "#69db7c",    # Green - documentation
            }

            # Create scroll area for navigation
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setStyleSheet("""
                QScrollArea {
                    border: none;
                    background-color: transparent;
                }
                QScrollBar:vertical {
                    background-color: transparent;
                    width: 6px;
                    margin: 0;
                }
                QScrollBar::handle:vertical {
                    background-color: #3d444d;
                    border-radius: 3px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #545d68;
                }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                    height: 0;
                }
            """)

            nav_container = QWidget()
            nav_layout = QVBoxLayout(nav_container)
            nav_layout.setContentsMargins(8, 8, 8, 8)
            nav_layout.setSpacing(4)

            # Build grouped navigation with collapsible sections
            self.nav_buttons = {}  # Store button references
            self.item_to_index = {}  # Map button to content index
            self.section_containers = {}  # Store section containers for collapse
            self.section_expanded = {}  # Track section expand state

            for section_name, section_icon, items in self.NAV_SECTIONS:
                # Clickable section header
                section_header = QPushButton(f"  ▼ {section_name}")
                section_header.setObjectName(f"section_{section_name}")
                section_header.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        border: none;
                        text-align: left;
                        font-weight: bold;
                        padding: 8px 4px;
                    }
                    QPushButton:hover {
                        background-color: #3d444d;
                        border-radius: 4px;
                    }
                """)
                section_header.setCursor(Qt.PointingHandCursor)
                section_header.clicked.connect(
                    lambda checked, s=section_name: self._toggle_section(s)
                )
                self.section_headers.append((section_header, section_name))
                self.section_expanded[section_name] = True
                nav_layout.addWidget(section_header)

                # Section items container (collapsible)
                section_container = QWidget()
                section_container.setObjectName(f"container_{section_name}")
                section_layout = QVBoxLayout(section_container)
                section_layout.setContentsMargins(0, 0, 0, 0)
                section_layout.setSpacing(2)
                self.section_containers[section_name] = section_container

                # Section items
                for key, icon, label, tooltip in items:
                    btn = QPushButton(f"  {icon}  {label}")
                    btn.setObjectName(f"nav_{key}")
                    btn.setToolTip(tooltip)
                    btn.setCheckable(True)
                    btn.setMinimumHeight(40)

                    # Store mapping
                    content_index = self.KEY_TO_INDEX.get(key, 0)
                    self.nav_buttons[key] = btn
                    self.item_to_index[key] = content_index

                    # Connect click
                    btn.clicked.connect(lambda checked, k=key: self._on_nav_click(k))
                    section_layout.addWidget(btn)

                nav_layout.addWidget(section_container)

            nav_layout.addStretch()
            scroll.setWidget(nav_container)
            layout.addWidget(scroll, 1)

            # Select first item by default
            if "dashboard" in self.nav_buttons:
                self.nav_buttons["dashboard"].setChecked(True)

            # Keep nav_list for backward compatibility (hidden)
            self.nav_list = QListWidget()
            self.nav_list.setVisible(False)
            for idx, (key, icon, label, tooltip) in enumerate(self.NAV_ITEMS):
                item = QListWidgetItem(f"  {icon}  {label}")
                item.setData(Qt.UserRole, idx)
                item.setData(Qt.UserRole + 1, key)
                self.nav_list.addItem(item)

            layout.addWidget(self.nav_list)
            layout.addStretch()

            # Font zoom controls
            zoom_container = QWidget()
            zoom_layout = QHBoxLayout(zoom_container)
            zoom_layout.setContentsMargins(12, 8, 12, 8)
            zoom_layout.setSpacing(4)

            zoom_label = QLabel("🔍")
            zoom_label.setStyleSheet("font-size: 14px; color: #e6edf3;")
            zoom_layout.addWidget(zoom_label)

            self.zoom_out_btn = QPushButton("−")
            self.zoom_out_btn.setFixedSize(28, 28)
            self.zoom_out_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3d444d;
                    border: 1px solid #3d444d;
                    border-radius: 4px;
                    color: #f0f6fc;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #3d444d;
                }
            """)
            self.zoom_out_btn.clicked.connect(self._on_zoom_out)
            zoom_layout.addWidget(self.zoom_out_btn)

            self.zoom_value_label = QLabel("100%")
            self.zoom_value_label.setFixedWidth(42)
            self.zoom_value_label.setAlignment(Qt.AlignCenter)
            self.zoom_value_label.setStyleSheet("color: #e6edf3; font-size: 11px;")
            zoom_layout.addWidget(self.zoom_value_label)

            self.zoom_in_btn = QPushButton("+")
            self.zoom_in_btn.setFixedSize(28, 28)
            self.zoom_in_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3d444d;
                    border: 1px solid #3d444d;
                    border-radius: 4px;
                    color: #f0f6fc;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #3d444d;
                }
            """)
            self.zoom_in_btn.clicked.connect(self._on_zoom_in)
            zoom_layout.addWidget(self.zoom_in_btn)

            layout.addWidget(zoom_container)

            # Theme toggle at bottom - Dark ↔ Slate
            self.theme_btn = QPushButton("🎨 Dark ↔ Slate")
            self.theme_btn.setToolTip("Toggle between Dark and Navy/Slate themes")
            self.theme_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: none;
                    color: #e6edf3;
                    padding: 14px 18px;
                    text-align: left;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #3d444d;
                    color: #f0f6fc;
                    border-radius: 8px;
                }
            """)
            self.theme_btn.clicked.connect(self._on_theme_toggle)
            layout.addWidget(self.theme_btn)

        def _on_theme_toggle(self):
            if self.theme_manager:
                self.theme_manager.toggle_theme()
                self.theme_changed.emit()

        def _on_zoom_in(self):
            if self.theme_manager:
                new_scale = min(1.5, self.theme_manager.font_scale + 0.1)
                self.theme_manager.set_font_scale(new_scale)
                self.zoom_value_label.setText(f"{int(new_scale * 100)}%")
                self.theme_changed.emit()

        def _on_zoom_out(self):
            if self.theme_manager:
                new_scale = max(0.8, self.theme_manager.font_scale - 0.1)
                self.theme_manager.set_font_scale(new_scale)
                self.zoom_value_label.setText(f"{int(new_scale * 100)}%")
                self.theme_changed.emit()

        def _toggle_section(self, section_name: str):
            """Toggle section expand/collapse"""
            if section_name not in self.section_containers:
                return

            container = self.section_containers[section_name]
            is_expanded = self.section_expanded.get(section_name, True)

            # Toggle state
            new_state = not is_expanded
            self.section_expanded[section_name] = new_state

            # Update visibility
            container.setVisible(new_state)

            # Update header icon
            for header, name in self.section_headers:
                if name == section_name:
                    icon = "▼" if new_state else "▶"
                    header.setText(f"  {icon} {section_name}")
                    break

        def collapse_all_sections(self):
            """Collapse all sections"""
            for section_name in self.section_containers:
                self.section_expanded[section_name] = False
                self.section_containers[section_name].setVisible(False)
                for header, name in self.section_headers:
                    if name == section_name:
                        header.setText(f"  ▶ {section_name}")
                        break

        def expand_all_sections(self):
            """Expand all sections"""
            for section_name in self.section_containers:
                self.section_expanded[section_name] = True
                self.section_containers[section_name].setVisible(True)
                for header, name in self.section_headers:
                    if name == section_name:
                        header.setText(f"  ▼ {section_name}")
                        break

        def update_zoom_label(self):
            """Update zoom label to current scale"""
            if self.theme_manager:
                self.zoom_value_label.setText(f"{int(self.theme_manager.font_scale * 100)}%")

        def _on_nav_click(self, key: str):
            """Handle navigation button click - grouped workflow navigation"""
            # Uncheck all other buttons
            for btn_key, btn in self.nav_buttons.items():
                if btn_key != key:
                    btn.setChecked(False)

            # Check clicked button
            if key in self.nav_buttons:
                self.nav_buttons[key].setChecked(True)

            # Emit navigation signal with correct content index
            content_index = self.item_to_index.get(key, 0)
            self.navigation_changed.emit(content_index)

        def set_active_button(self, index: int):
            """Highlight the button for a content index without emitting a signal.

            Used by keyboard shortcuts (Ctrl+1..9); MainWindow already switched
            the page. This method was missing, so the shortcuts raised
            AttributeError.
            """
            for btn_key, btn in self.nav_buttons.items():
                btn.setChecked(self.item_to_index.get(btn_key) == index)

        def set_active_nav(self, key: str):
            """Programmatically set active navigation item"""
            if key in self.nav_buttons:
                self._on_nav_click(key)

        def highlight_section(self, section_name: str, highlight: bool = True):
            """Highlight a workflow section (e.g., when alerts are critical)"""
            # This can be used to draw attention to specific sections

        def update_theme(self):
            """Update all sidebar elements with current theme colors and font scale"""
            if not self.theme_manager:
                return

            t = self.theme_manager.THEMES[self.theme_manager.current_theme]
            fs = self.theme_manager.scale_font

            # Update logo, tagline, version labels with theme colors and font scale
            self.logo_label.setStyleSheet(f"""
                font-size: {fs(16)}px;
                font-weight: bold;
                color: {t['text_primary']};
            """)
            self.tagline_label.setStyleSheet(f"""
                font-size: {fs(10)}px;
                color: {t['text_tertiary']};
            """)
            self.version_label.setStyleSheet(f"""
                font-size: {fs(9)}px;
                color: {t['text_muted']};
            """)

            # Update section headers with workflow colors and font scale
            for section_header, section_name in self.section_headers:
                section_color = self.section_colors.get(section_name, t['text_tertiary'])
                section_header.setStyleSheet(f"""
                    font-size: {fs(10)}px;
                    font-weight: 700;
                    letter-spacing: 1px;
                    padding: 16px 12px 6px 12px;
                    color: {section_color};
                """)

            # Update nav buttons with font scale
            for key, btn in self.nav_buttons.items():
                icon_color = self.icon_colors.get(key, t['text_secondary'])
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: transparent;
                        border: none;
                        border-left: 3px solid transparent;
                        border-radius: 0;
                        color: {t['text_secondary']};
                        font-size: {fs(13)}px;
                        font-weight: 500;
                        text-align: left;
                        padding: 10px 16px;
                        margin: 2px 8px;
                    }}
                    QPushButton:hover {{
                        background-color: {t['sidebar_hover']};
                        color: {t['text_primary']};
                    }}
                    QPushButton:checked {{
                        background-color: {t['sidebar_active']};
                        color: {icon_color};
                        font-weight: 600;
                        border-left: 3px solid {icon_color};
                    }}
                """)

            # Update zoom controls with theme colors and font scale
            zoom_btn_style = f"""
                QPushButton {{
                    background-color: {t['bg_tertiary']};
                    border: 1px solid {t['border_light']};
                    border-radius: 4px;
                    color: {t['text_primary']};
                    font-size: {fs(16)}px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: {t['bg_hover']};
                    border-color: {t['accent_blue']};
                }}
            """
            self.zoom_out_btn.setStyleSheet(zoom_btn_style)
            self.zoom_in_btn.setStyleSheet(zoom_btn_style)
            self.zoom_value_label.setStyleSheet(f"""
                color: {t['text_secondary']};
                font-size: {fs(11)}px;
            """)
            self.zoom_value_label.setText(f"{int(self.theme_manager.font_scale * 100)}%")

            # Update theme toggle button
            self.theme_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    border: none;
                    color: {t['text_secondary']};
                    padding: 14px 18px;
                    text-align: left;
                    font-size: {fs(13)}px;
                }}
                QPushButton:hover {{
                    background-color: {t['sidebar_hover']};
                    color: {t['text_primary']};
                    border-radius: 8px;
                }}
            """)


    # =========================================================================
    # TOP BAR - PCAP Info & Controls (Enhanced with better icons)
    # =========================================================================

    class TopBar(QWidget):
        """Top bar with PCAP info, analysis status, and professional action buttons"""
        import_clicked = pyqtSignal()
        export_clicked = pyqtSignal()
        cancel_clicked = pyqtSignal()

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.setObjectName("TopBar")
            self.setMinimumHeight(60)

            layout = QHBoxLayout(self)
            layout.setContentsMargins(24, 0, 24, 0)
            layout.setSpacing(20)

            # Left: Status indicator with pulsing effect
            status_container = QWidget()
            status_layout = QHBoxLayout(status_container)
            status_layout.setContentsMargins(0, 0, 0, 0)
            status_layout.setSpacing(10)

            self.status_dot = QLabel("●")
            self.status_dot.setStyleSheet("color: #69db7c; font-size: 14px;")
            status_layout.addWidget(self.status_dot)

            self.status_label = QLabel("Ready — Select PCAP file to analyze")
            self.status_label.setStyleSheet("color: #e6edf3; font-size: 13px; font-weight: 500;")
            status_layout.addWidget(self.status_label)
            layout.addWidget(status_container)

            # PCAP info (hidden initially) - with better icons
            self.pcap_info = QLabel("")
            self.pcap_info.setStyleSheet("color: #74c0fc; font-size: 12px; font-weight: 500;")
            self.pcap_info.setVisible(False)
            layout.addWidget(self.pcap_info)

            layout.addStretch()

            # Progress section: label + bar with ETA
            progress_container = QWidget()
            progress_layout = QVBoxLayout(progress_container)
            progress_layout.setContentsMargins(0, 2, 0, 2)
            progress_layout.setSpacing(4)

            # Progress info row: status + ETA
            progress_info = QHBoxLayout()
            progress_info.setSpacing(8)

            self.progress_label = QLabel("")
            self.progress_label.setStyleSheet("color: #bc8cff; font-size: 11px; font-weight: 500;")
            self.progress_label.setVisible(False)
            progress_info.addWidget(self.progress_label)

            progress_info.addStretch()

            self.eta_label = QLabel("")
            self.eta_label.setStyleSheet("color: #8b949e; font-size: 11px;")
            self.eta_label.setVisible(False)
            progress_info.addWidget(self.eta_label)

            progress_layout.addLayout(progress_info)

            self.progress_bar = QProgressBar()
            self.progress_bar.setMinimumWidth(280)
            self.progress_bar.setFixedHeight(14)  # Slightly taller for visibility
            self.progress_bar.setVisible(False)
            self.progress_bar.setTextVisible(True)  # Show percentage
            self.progress_bar.setFormat("%p%")
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #3d444d;
                    border-radius: 7px;
                    background-color: #3d444d;
                    text-align: center;
                    color: #f0f6fc;
                    font-size: 10px;
                    font-weight: 600;
                }
                QProgressBar::chunk {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #388bfd, stop:1 #58a6ff);
                    border-radius: 6px;
                }
            """)
            progress_layout.addWidget(self.progress_bar)

            layout.addWidget(progress_container)

            # Track timing for ETA calculation
            self._progress_start_time = None
            self._last_progress_value = 0

            # Action buttons with modern styling
            self.btn_cancel = QPushButton("  ✕  Cancel")
            self.btn_cancel.setObjectName("BtnDanger")
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setMinimumWidth(100)
            self.btn_cancel.setMinimumHeight(36)
            self.btn_cancel.clicked.connect(self.cancel_clicked.emit)
            layout.addWidget(self.btn_cancel)

            self.btn_export = QPushButton("  ↓  Export")
            self.btn_export.setEnabled(False)
            self.btn_export.setMinimumWidth(100)
            self.btn_export.setMinimumHeight(36)
            self.btn_export.clicked.connect(self.export_clicked.emit)
            layout.addWidget(self.btn_export)

            self.btn_import = QPushButton("  ◈  Import PCAP")
            self.btn_import.setObjectName("BtnPrimary")
            self.btn_import.setMinimumWidth(140)
            self.btn_import.setMinimumHeight(36)
            self.btn_import.clicked.connect(self.import_clicked.emit)
            layout.addWidget(self.btn_import)

        def set_status(self, message: str, status_type: str = "info"):
            """Update status with appropriate color and icon"""
            status_configs = {
                "ready": ("●", "#3fb950"),
                "info": ("●", "#58a6ff"),
                "warning": ("◬", "#d29922"),
                "error": ("◉", "#f85149"),
                "processing": ("◌", "#a371f7"),
            }
            icon, color = status_configs.get(status_type, ("●", "#8b949e"))
            self.status_dot.setText(icon)
            self.status_dot.setStyleSheet(f"color: {color}; font-size: 14px;")
            self.status_label.setText(message)

        def set_pcap_info(self, filename: str, packets: int, duration: str):
            """Display PCAP file information with clean icons"""
            self.pcap_info.setText(f"◎ {filename}   ·   ▦ {packets:,} packets   ·   ⏱ {duration}")
            self.pcap_info.setVisible(True)

        def set_progress(self, current: int, total: int, message: str = ""):
            import time
            if total > 0:
                # Initialize timing on first call
                if self._progress_start_time is None or current < self._last_progress_value:
                    self._progress_start_time = time.time()
                    self._last_progress_value = 0

                self.progress_bar.setMaximum(total)
                self.progress_bar.setValue(current)
                self.progress_bar.setVisible(True)
                self.progress_label.setVisible(True)
                self.eta_label.setVisible(True)

                # Update status message
                if message:
                    self.progress_label.setText(message)
                elif current > 0:
                    self.progress_label.setText(f"▶ {current:,} / ~{total:,} packets")

                # Calculate and show ETA
                elapsed = time.time() - self._progress_start_time
                if current > 0 and elapsed > 1:
                    rate = current / elapsed  # packets per second
                    remaining = total - current
                    eta_seconds = remaining / rate if rate > 0 else 0

                    if eta_seconds > 60:
                        eta_str = f"~{int(eta_seconds / 60)}m {int(eta_seconds % 60)}s remaining"
                    elif eta_seconds > 0:
                        eta_str = f"~{int(eta_seconds)}s remaining"
                    else:
                        eta_str = "Almost done..."

                    self.eta_label.setText(f"⏱ {eta_str} ({rate:,.0f} pkt/s)")
                else:
                    self.eta_label.setText("Calculating...")

                self._last_progress_value = current
            else:
                self.progress_bar.setVisible(False)
                self.progress_label.setVisible(False)
                self.eta_label.setVisible(False)
                self.progress_label.setText("")
                self.eta_label.setText("")
                self._progress_start_time = None


    # =========================================================================
    # ANALYSIS WORKER THREAD
    # =========================================================================

    class AnalysisWorker(QThread):
        """Background worker for PCAP analysis

        THREAD SAFETY:
        - All signals use Qt's queued connection mechanism
        - No direct UI updates from this thread
        - progress_callback emits signals which are queued to main thread
        """
        progress = pyqtSignal(int, int, str)
        finished = pyqtSignal()
        error = pyqtSignal(str)

        def __init__(self, analyzer, pcap_path, max_packets=None):
            super().__init__()
            self.analyzer = analyzer
            self.pcap_path = pcap_path
            self.max_packets = max_packets
            self._running = True

        def run(self):
            try:
                # Use a thread-safe callback that only emits signals
                def safe_progress_callback(c, t, m):
                    if self._running:
                        self.progress.emit(c, t, m)

                self.analyzer.progress_callback = safe_progress_callback
                self.analyzer.analyze_capture(self.pcap_path, self.max_packets)

                if self._running:
                    self.finished.emit()
            except Exception as e:
                import traceback
                if self._running:
                    self.error.emit(f"{str(e)}\n\n{traceback.format_exc()}")
            finally:
                self._running = False


    # =========================================================================
    # GLOBAL SEARCH BAR
    # =========================================================================

    class GlobalSearchBar(QWidget):
        """
        A collapsible search bar for searching across table data in views.
        Appears at the top of the content area when Ctrl+F is pressed.
        """
        closed = pyqtSignal()

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.current_table = None
            self.matches = []
            self.current_match = -1

            self.setFixedHeight(48)
            self.setAutoFillBackground(True)

            layout = QHBoxLayout(self)
            layout.setContentsMargins(16, 8, 16, 8)
            layout.setSpacing(8)

            # Search icon
            search_icon = QLabel("🔍")
            search_icon.setStyleSheet("font-size: 16px;")
            layout.addWidget(search_icon)

            # Search input
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("Search in current table... (Esc to close)")
            self.search_input.setMinimumWidth(300)
            self.search_input.setStyleSheet("""
                QLineEdit {
                    background-color: #3d444d;
                    border: 1px solid #3d444d;
                    border-radius: 6px;
                    color: #f0f6fc;
                    padding: 6px 12px;
                    font-size: 14px;
                }
                QLineEdit:focus {
                    border-color: #58a6ff;
                }
            """)
            self.search_input.textChanged.connect(self._on_search_changed)
            self.search_input.returnPressed.connect(self._next_match)
            layout.addWidget(self.search_input, 1)

            # Match info
            self.match_info = QLabel("0 matches")
            self.match_info.setStyleSheet("color: #8b949e; font-size: 12px; min-width: 80px;")
            layout.addWidget(self.match_info)

            # Navigation buttons
            self.btn_prev = QPushButton("▲")
            self.btn_prev.setFixedSize(28, 28)
            self.btn_prev.setToolTip("Previous match (Shift+Enter)")
            self.btn_prev.clicked.connect(self._prev_match)
            layout.addWidget(self.btn_prev)

            self.btn_next = QPushButton("▼")
            self.btn_next.setFixedSize(28, 28)
            self.btn_next.setToolTip("Next match (Enter)")
            self.btn_next.clicked.connect(self._next_match)
            layout.addWidget(self.btn_next)

            # Case sensitivity toggle
            self.btn_case = QPushButton("Aa")
            self.btn_case.setFixedSize(28, 28)
            self.btn_case.setCheckable(True)
            self.btn_case.setToolTip("Case sensitive")
            self.btn_case.clicked.connect(self._on_search_changed)
            layout.addWidget(self.btn_case)

            # Close button
            btn_close = QPushButton("✕")
            btn_close.setFixedSize(28, 28)
            btn_close.setToolTip("Close (Esc)")
            btn_close.clicked.connect(self._close)
            layout.addWidget(btn_close)

            # Style
            self.setStyleSheet("""
                GlobalSearchBar {
                    background-color: #252b33;
                    border-bottom: 1px solid #3d444d;
                }
                QPushButton {
                    background-color: #3d444d;
                    border: 1px solid #3d444d;
                    border-radius: 4px;
                    color: #e6edf3;
                }
                QPushButton:hover {
                    background-color: #3d444d;
                }
                QPushButton:checked {
                    background-color: #388bfd;
                    border-color: #388bfd;
                }
            """)

            # Hide by default
            self.hide()

        def set_table(self, table: QTableWidget):
            """Set the table to search in"""
            self.current_table = table
            self._clear_highlights()
            self.matches = []
            self.current_match = -1
            self.match_info.setText("0 matches")

        def show_and_focus(self, table: QTableWidget = None):
            """Show the search bar and focus the input"""
            if table:
                self.set_table(table)
            self.show()
            self.search_input.setFocus()
            self.search_input.selectAll()

        def _close(self):
            """Close the search bar"""
            self._clear_highlights()
            self.hide()
            self.closed.emit()

        def keyPressEvent(self, event):
            """Handle key events"""
            if event.key() == Qt.Key_Escape:
                self._close()
            elif event.key() == Qt.Key_Return and event.modifiers() & Qt.ShiftModifier:
                self._prev_match()
            else:
                super().keyPressEvent(event)

        def _on_search_changed(self):
            """Perform search when text changes"""
            self._clear_highlights()
            self.matches = []
            self.current_match = -1

            if not self.current_table:
                return

            query = self.search_input.text()
            if not query:
                self.match_info.setText("0 matches")
                self._update_nav_buttons()
                return

            case_sensitive = self.btn_case.isChecked()
            if not case_sensitive:
                query = query.lower()

            # Search all cells
            for row in range(self.current_table.rowCount()):
                for col in range(self.current_table.columnCount()):
                    item = self.current_table.item(row, col)
                    if item:
                        text = item.text()
                        if not case_sensitive:
                            text = text.lower()
                        if query in text:
                            self.matches.append((row, col))
                            # Highlight matching cell
                            item.setBackground(QColor("#3d4752"))
                            break  # Only count each row once

            # Update match info
            count = len(self.matches)
            self.match_info.setText(f"{count} match{'es' if count != 1 else ''}")
            self._update_nav_buttons()

            # Go to first match
            if self.matches:
                self.current_match = 0
                self._highlight_current()

        def _next_match(self):
            """Go to next match"""
            if not self.matches:
                return
            self.current_match = (self.current_match + 1) % len(self.matches)
            self._highlight_current()

        def _prev_match(self):
            """Go to previous match"""
            if not self.matches:
                return
            self.current_match = (self.current_match - 1) % len(self.matches)
            self._highlight_current()

        def _highlight_current(self):
            """Highlight and scroll to current match"""
            if not self.matches or self.current_match < 0:
                return

            row, col = self.matches[self.current_match]

            # Update match info with position
            self.match_info.setText(f"{self.current_match + 1}/{len(self.matches)}")

            # Scroll to and select the row
            self.current_table.selectRow(row)
            self.current_table.scrollToItem(
                self.current_table.item(row, 0),
                QTableWidget.PositionAtCenter
            )

        def _clear_highlights(self):
            """Clear all highlights from the table"""
            if not self.current_table:
                return

            default_bg = QColor("#1c2128")
            alt_bg = QColor("#252b33")

            for row in range(self.current_table.rowCount()):
                bg = alt_bg if row % 2 else default_bg
                for col in range(self.current_table.columnCount()):
                    item = self.current_table.item(row, col)
                    if item:
                        item.setBackground(bg)

        def _update_nav_buttons(self):
            """Update navigation button states"""
            has_matches = len(self.matches) > 0
            self.btn_prev.setEnabled(has_matches)
            self.btn_next.setEnabled(has_matches)
