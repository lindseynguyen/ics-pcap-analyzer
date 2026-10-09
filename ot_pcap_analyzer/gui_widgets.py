"""
OT PCAP Analyzer - GUI building blocks
(metric cards, risk summary, sidebar, top bar, search bar, analysis worker)
"""
try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
        QProgressBar, QTableWidget, QFrame,
        QScrollArea, QLineEdit
    )
    from PyQt5.QtCore import Qt, QThread, QSize, pyqtSignal
    from PyQt5.QtGui import QColor
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False


if HAS_PYQT5:
    from .version import VERSION
    from .gui_theme import SOCIcons

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
    # SIDEBAR NAVIGATION
    # =========================================================================

    class SidebarNavigation(QWidget):
        """Left navigation: app header, grouped pages, theme switch and zoom."""
        navigation_changed = pyqtSignal(int)
        theme_changed = pyqtSignal()

        # (section, [(key, label, tooltip), ...]) in workflow order
        NAV_SECTIONS = [
            ("TRIAGE", [
                ("dashboard", "Dashboard", "Security overview"),
                ("anomalies", "Alerts", "Alerts and anomalies"),
            ]),
            ("ANALYZE", [
                ("assets", "Assets", "Network assets"),
                ("ot_events", "OT Events", "OT/ICS protocol events"),
                ("attack_flow", "Attack Flow", "Attack chain graph"),
            ]),
            ("THREAT", [
                ("threat_model", "MITRE ATT&&CK", "MITRE ATT&CK matrix"),
                ("ioc", "IOCs", "Indicators of compromise"),
                ("threat_intel", "Threat Intel", "Threat intelligence lookups"),
            ]),
            ("REPORT", [
                ("incidents", "Incidents", "Incident stories"),
                ("history", "Scan History", "Previous analyses stored on this computer"),
            ]),
        ]

        # nav key -> content stack index (order the pages are added in MainWindow)
        KEY_TO_INDEX = {
            "dashboard": 0, "assets": 1, "attack_flow": 2, "threat_model": 3,
            "anomalies": 4, "ot_events": 5, "ioc": 6, "incidents": 7,
            "threat_intel": 8, "history": 9,
        }

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.setObjectName("Sidebar")
            self.setAttribute(Qt.WA_StyledBackground, True)
            self.setFixedWidth(232)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            # header: logo mark + name
            header = QWidget()
            hl = QHBoxLayout(header)
            hl.setContentsMargins(16, 18, 16, 14)
            hl.setSpacing(10)
            logo = QLabel("OT")
            logo.setObjectName("AppLogo")
            logo.setFixedSize(34, 34)
            logo.setAlignment(Qt.AlignCenter)
            hl.addWidget(logo)
            titles = QVBoxLayout()
            titles.setSpacing(0)
            self.logo_label = QLabel("ICS PCAP Analyzer")
            self.logo_label.setObjectName("AppTitle")
            titles.addWidget(self.logo_label)
            self.version_label = QLabel(f"v{VERSION} · offline")
            self.version_label.setObjectName("AppSubtitle")
            titles.addWidget(self.version_label)
            hl.addLayout(titles, 1)
            layout.addWidget(header)

            # navigation
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setFrameShape(QFrame.NoFrame)
            nav = QWidget()
            nav.setAttribute(Qt.WA_TranslucentBackground, True)
            nav_layout = QVBoxLayout(nav)
            nav_layout.setContentsMargins(0, 0, 0, 8)
            nav_layout.setSpacing(0)

            self.nav_buttons = {}
            self.item_to_index = {}
            for section, items in self.NAV_SECTIONS:
                title = QLabel(section)
                title.setObjectName("NavSection")
                nav_layout.addWidget(title)
                for key, label, tooltip in items:
                    btn = QPushButton(f"  {label}")
                    btn.setObjectName("NavItem")
                    btn.setToolTip(tooltip)
                    btn.setCheckable(True)
                    btn.setCursor(Qt.PointingHandCursor)
                    btn.setIconSize(QSize(18, 18))
                    btn.clicked.connect(lambda checked, k=key: self._on_nav_click(k))
                    self.nav_buttons[key] = btn
                    self.item_to_index[key] = self.KEY_TO_INDEX[key]
                    nav_layout.addWidget(btn)
            nav_layout.addStretch()
            scroll.setWidget(nav)
            layout.addWidget(scroll, 1)

            # footer: theme switch + zoom
            footer = QWidget()
            fl = QVBoxLayout(footer)
            fl.setContentsMargins(14, 10, 14, 14)
            fl.setSpacing(10)

            switch = QFrame()
            switch.setObjectName("ThemeSwitch")
            sl = QHBoxLayout(switch)
            sl.setContentsMargins(3, 3, 3, 3)
            sl.setSpacing(2)
            self.theme_buttons = {}
            for name, label in (("light", "☀  Light"), ("dark", "☾  Dark")):
                b = QPushButton(label)
                b.setObjectName("ThemeSeg")
                b.setCheckable(True)
                b.setCursor(Qt.PointingHandCursor)
                b.clicked.connect(lambda checked, n=name: self.set_theme(n))
                self.theme_buttons[name] = b
                sl.addWidget(b)
            fl.addWidget(switch)
            # backwards-compatible handle used by older code/tests
            self.theme_btn = self.theme_buttons["dark"]

            zoom = QHBoxLayout()
            zoom.setSpacing(6)
            zl = QLabel("Text size")
            zl.setObjectName("AppSubtitle")
            zoom.addWidget(zl)
            zoom.addStretch()
            self.zoom_out_btn = QPushButton("−")
            self.zoom_in_btn = QPushButton("+")
            self.zoom_value_label = QLabel("100%")
            self.zoom_value_label.setObjectName("AppSubtitle")
            self.zoom_value_label.setAlignment(Qt.AlignCenter)
            self.zoom_value_label.setFixedWidth(40)
            for b in (self.zoom_out_btn, self.zoom_in_btn):
                b.setObjectName("SidebarTool")
                b.setFixedSize(30, 28)
                b.setCursor(Qt.PointingHandCursor)
            self.zoom_out_btn.setToolTip("Smaller text  (Ctrl+-)")
            self.zoom_in_btn.setToolTip("Larger text  (Ctrl+=)")
            self.zoom_out_btn.clicked.connect(self._on_zoom_out)
            self.zoom_in_btn.clicked.connect(self._on_zoom_in)
            zoom.addWidget(self.zoom_out_btn)
            zoom.addWidget(self.zoom_value_label)
            zoom.addWidget(self.zoom_in_btn)
            fl.addLayout(zoom)
            layout.addWidget(footer)

            self.nav_buttons["dashboard"].setChecked(True)
            self.update_theme()

        # ---- theme / zoom ---------------------------------------------------
        def set_theme(self, name: str):
            if self.theme_manager and name != self.theme_manager.current_theme:
                self.theme_manager.set_theme(name)
                self.theme_changed.emit()
            self._sync_theme_buttons()

        def toggle_theme(self):
            if self.theme_manager:
                self.set_theme("light" if self.theme_manager.current_theme == "dark" else "dark")

        _on_theme_toggle = toggle_theme

        def _sync_theme_buttons(self):
            current = self.theme_manager.current_theme if self.theme_manager else "dark"
            for name, b in self.theme_buttons.items():
                b.setChecked(name == current)

        def _on_zoom_in(self):
            if self.theme_manager:
                self.theme_manager.set_font_scale(round(self.theme_manager.font_scale + 0.1, 1))
                self.update_zoom_label()
                self.theme_changed.emit()

        def _on_zoom_out(self):
            if self.theme_manager:
                self.theme_manager.set_font_scale(round(self.theme_manager.font_scale - 0.1, 1))
                self.update_zoom_label()
                self.theme_changed.emit()

        def update_zoom_label(self):
            if self.theme_manager:
                self.zoom_value_label.setText(f"{int(round(self.theme_manager.font_scale * 100))}%")

        # ---- navigation -------------------------------------------------------
        def _on_nav_click(self, key: str):
            for k, b in self.nav_buttons.items():
                b.setChecked(k == key)
            self._refresh_icons()
            self.navigation_changed.emit(self.item_to_index.get(key, 0))

        def set_active_button(self, index: int):
            """Highlight the item for a content index without emitting a signal."""
            for k, b in self.nav_buttons.items():
                b.setChecked(self.item_to_index.get(k) == index)
            self._refresh_icons()

        def set_active_nav(self, key: str):
            if key in self.nav_buttons:
                self._on_nav_click(key)

        def _refresh_icons(self):
            if not self.theme_manager:
                return
            t = self.theme_manager.THEMES[self.theme_manager.current_theme]
            for key, btn in self.nav_buttons.items():
                svg = SOCIcons.NAV_ICONS.get(key)
                if svg:
                    color = t["accent"] if btn.isChecked() else t["text_3"]
                    btn.setIcon(SOCIcons.icon(svg, color, 18))

        def update_theme(self):
            """Icons and toggles follow the theme; colours come from the app style sheet."""
            self._sync_theme_buttons()
            self.update_zoom_label()
            self._refresh_icons()

    # =========================================================================
    # TOP BAR
    # =========================================================================

    class TopBar(QWidget):
        """Status, capture info, progress and the main actions."""
        import_clicked = pyqtSignal()
        export_clicked = pyqtSignal()
        cancel_clicked = pyqtSignal()

        STATUS_TOKENS = {
            "ready": "low", "info": "accent", "warning": "medium",
            "error": "critical", "processing": "purple",
        }

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.setObjectName("TopBar")
            self.setAttribute(Qt.WA_StyledBackground, True)
            self.setFixedHeight(60)
            self._status_type = "ready"

            layout = QHBoxLayout(self)
            layout.setContentsMargins(20, 0, 20, 0)
            layout.setSpacing(14)

            self.status_dot = QLabel("●")
            layout.addWidget(self.status_dot)
            self.status_label = QLabel("Ready — open a PCAP file to start")
            self.status_label.setStyleSheet("font-weight: 600;")
            layout.addWidget(self.status_label)

            self.pcap_info = QLabel("")
            self.pcap_info.setObjectName("FileChip")
            self.pcap_info.setFixedHeight(26)
            self.pcap_info.setVisible(False)
            layout.addWidget(self.pcap_info)

            layout.addStretch()

            progress = QWidget()
            pl = QVBoxLayout(progress)
            pl.setContentsMargins(0, 0, 0, 0)
            pl.setSpacing(4)
            info = QHBoxLayout()
            self.progress_label = QLabel("")
            self.progress_label.setObjectName("AppSubtitle")
            self.progress_label.setVisible(False)
            info.addWidget(self.progress_label)
            info.addStretch()
            self.eta_label = QLabel("")
            self.eta_label.setObjectName("AppSubtitle")
            self.eta_label.setVisible(False)
            info.addWidget(self.eta_label)
            pl.addLayout(info)
            self.progress_bar = QProgressBar()
            self.progress_bar.setMinimumWidth(260)
            self.progress_bar.setTextVisible(False)
            self.progress_bar.setVisible(False)
            pl.addWidget(self.progress_bar)
            layout.addWidget(progress)

            self.btn_cancel = QPushButton("Cancel")
            self.btn_cancel.setObjectName("BtnDanger")
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setVisible(False)
            self.btn_cancel.clicked.connect(self.cancel_clicked.emit)
            layout.addWidget(self.btn_cancel)

            self.btn_export = QPushButton("Export report")
            self.btn_export.setEnabled(False)
            self.btn_export.setToolTip("Save the analysis as an Excel report  (Ctrl+E)")
            self.btn_export.clicked.connect(self.export_clicked.emit)
            layout.addWidget(self.btn_export)

            self.btn_import = QPushButton("Open PCAP")
            self.btn_import.setObjectName("BtnPrimary")
            self.btn_import.setToolTip("Analyze a .pcap / .pcapng file  (Ctrl+O)")
            self.btn_import.clicked.connect(self.import_clicked.emit)
            layout.addWidget(self.btn_import)

            self.btn_cancel.installEventFilter(self)
            self.update_theme()

        def eventFilter(self, obj, event):
            # Cancel is only shown while an analysis can actually be cancelled
            from PyQt5.QtCore import QEvent
            if obj is self.btn_cancel and event.type() == QEvent.EnabledChange:
                self.btn_cancel.setVisible(self.btn_cancel.isEnabled())
            return super().eventFilter(obj, event)

        def update_theme(self):
            if not self.theme_manager:
                return
            t = self.theme_manager.THEMES[self.theme_manager.current_theme]
            color = t[self.STATUS_TOKENS.get(self._status_type, "text_3")]
            self.status_dot.setStyleSheet(f"color: {color}; font-size: 12px;")
            for btn, svg in ((self.btn_import, SOCIcons.IMPORT), (self.btn_export, SOCIcons.EXPORT),
                             (self.btn_cancel, SOCIcons.CANCEL)):
                col = t["on_accent"] if btn is self.btn_import else (
                    t["critical"] if btn is self.btn_cancel else t["text_2"])
                btn.setIcon(SOCIcons.icon(svg, col, 16))

        def set_status(self, message: str, status_type: str = "info"):
            self._status_type = status_type
            self.status_label.setText(message)
            self.update_theme()

        def set_pcap_info(self, filename: str, packets: int, duration: str):
            self.pcap_info.setText(f"{filename}   ·   {packets:,} packets   ·   {duration}")
            self.pcap_info.setVisible(True)

        def set_progress(self, current: int, total: int, message: str = ""):
            import time
            if total > 0:
                if self._progress_start_time is None or current < self._last_progress_value:
                    self._progress_start_time = time.time()
                    self._last_progress_value = 0
                self.progress_bar.setMaximum(total)
                self.progress_bar.setValue(current)
                for w in (self.progress_bar, self.progress_label, self.eta_label):
                    w.setVisible(True)
                if message:
                    self.progress_label.setText(message)
                elif current > 0:
                    self.progress_label.setText(f"{current:,} / ~{total:,} packets")
                elapsed = time.time() - self._progress_start_time
                if current > 0 and elapsed > 1:
                    rate = current / elapsed
                    eta = (total - current) / rate if rate > 0 else 0
                    if eta > 60:
                        eta_str = f"~{int(eta // 60)}m {int(eta % 60)}s left"
                    elif eta > 0:
                        eta_str = f"~{int(eta)}s left"
                    else:
                        eta_str = "almost done"
                    self.eta_label.setText(f"{eta_str} · {rate:,.0f} pkt/s")
                else:
                    self.eta_label.setText("estimating…")
                self._last_progress_value = current
            else:
                for w in (self.progress_bar, self.progress_label, self.eta_label):
                    w.setVisible(False)
                self.progress_label.setText("")
                self.eta_label.setText("")
                self._progress_start_time = None

        _progress_start_time = None
        _last_progress_value = 0


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
