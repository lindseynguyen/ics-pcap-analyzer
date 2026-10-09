"""
OT PCAP Analyzer - GUI views
(asset, dashboard, anomaly, OT event and MITRE views)
"""
try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
        QMessageBox, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
        QFrame, QGroupBox, QComboBox, QSplitter, QScrollArea,
        QSizePolicy, QLineEdit
    )
    from PyQt5.QtCore import Qt, pyqtSignal
    from PyQt5.QtGui import QColor
    from PyQt5.QtWidgets import QMenu, QApplication as QApp
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False


if HAS_PYQT5:
    from .utils import utc_str
    from .gui_widgets import CompactMetric, RiskSummaryWidget

    # =========================================================================
    # ASSET DETAIL PANEL - Enhanced Right-side drawer with icons
    # =========================================================================

    class AssetDetailPanel(QWidget):
        """Right-side panel showing detailed asset information with professional styling"""
        closed = pyqtSignal()

        # Section icons mapping
        SECTION_ICONS = {
            "IDENTITY": "◫",
            "RISK ASSESSMENT": "◉",
            "ACTIVITY": "◷",
            "PROTOCOLS": "⚙",
            "CONNECTIONS": "◈",
            "ANOMALIES": "△",
        }

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.setObjectName("DetailPanel")
            # Resizable with min/max constraints
            self.setMinimumWidth(300)
            self.setMaximumWidth(600)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            # Header with gradient effect
            header = QWidget()
            header.setStyleSheet("""
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #388bfd25, stop:1 #252b33);
                border-bottom: 1px solid #3d444d;
            """)
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(20, 14, 16, 14)

            # Icon and title
            header_icon = QLabel("◫")
            header_icon.setStyleSheet("font-size: 18px; color: #74c0fc;")
            header_layout.addWidget(header_icon)

            self.title_label = QLabel("Asset Details")
            self.title_label.setStyleSheet("font-size: 15px; font-weight: 600; color: #f0f6fc; margin-left: 8px;")
            header_layout.addWidget(self.title_label)

            header_layout.addStretch()

            close_btn = QPushButton("✕")
            close_btn.setFixedSize(32, 32)
            close_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: 1px solid transparent;
                    border-radius: 6px;
                    color: #e6edf3;
                    font-size: 16px;
                }
                QPushButton:hover {
                    background-color: #f8514920;
                    border-color: #f85149;
                    color: #f85149;
                }
            """)
            close_btn.clicked.connect(self.closed.emit)
            header_layout.addWidget(close_btn)

            layout.addWidget(header)

            # Scrollable content
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")

            self.content = QWidget()
            self.content_layout = QVBoxLayout(self.content)
            self.content_layout.setContentsMargins(20, 20, 20, 20)
            self.content_layout.setSpacing(24)

            # Identity section
            self._add_section("IDENTITY", "◫", "#58a6ff")
            self.ip_label = self._add_field("◎ IP Address", "-")
            self.mac_label = self._add_field("◉ MAC Address", "-")
            self.device_type = self._add_field("◆ Device Type", "-")
            self.classification = self._add_field("◇ Classification", "-")

            # Risk section
            self._add_section("RISK ASSESSMENT", "◉", "#f85149")
            self.risk_badge = QLabel("◇ LOW")
            self.risk_badge.setObjectName("RiskLow")
            self.risk_badge.setAlignment(Qt.AlignCenter)
            self.risk_badge.setFixedWidth(100)
            self.risk_badge.setStyleSheet("""
                font-size: 12px; font-weight: 700;
                padding: 6px 12px;
                border-radius: 6px;
            """)
            self.content_layout.addWidget(self.risk_badge)

            # Risk reasons with special orange color
            risk_row = QHBoxLayout()
            risk_row.setSpacing(12)
            risk_lbl = QLabel("△ Risk Reasons")
            risk_lbl.setStyleSheet("color: #e6edf3; font-size: 13px; font-weight: 500;")
            risk_lbl.setFixedWidth(130)
            risk_row.addWidget(risk_lbl)
            self.risk_reasons = QLabel("-")
            self.risk_reasons.setStyleSheet("color: #ffa94d; font-size: 13px; font-weight: 500;")
            self.risk_reasons.setWordWrap(True)
            risk_row.addWidget(self.risk_reasons, 1)
            self.content_layout.addLayout(risk_row)

            # Activity section
            self._add_section("ACTIVITY", "◷", "#bc8cff")
            self.first_seen = self._add_field("▷ First Seen", "-")
            self.last_seen = self._add_field("◁ Last Seen", "-")
            self.packets = self._add_field("▦ Packets", "-")
            self.bytes = self._add_field("▣ Bytes", "-")

            # Protocols section
            self._add_section("PROTOCOLS", "⚙", "#63e6be")
            self.protocols_label = QLabel("-")
            self.protocols_label.setWordWrap(True)
            self.protocols_label.setStyleSheet("color: #63e6be; font-size: 13px; font-weight: 500; line-height: 1.5;")
            self.content_layout.addWidget(self.protocols_label)

            # Related threats section
            self._add_section("RELATED THREATS", "⚡", "#ff6b6b")
            self.threats_table = QTableWidget()
            self.threats_table.setColumnCount(2)
            self.threats_table.setHorizontalHeaderLabels(["Type", "Details"])
            self.threats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.threats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
            self.threats_table.setMaximumHeight(150)
            self.threats_table.setStyleSheet("""
                QTableWidget {
                    background-color: #252b33;
                    border: 1px solid #3d444d;
                    border-radius: 6px;
                    color: #f0f6fc;
                    gridline-color: #3d444d;
                }
                QTableWidget::item {
                    padding: 6px;
                    color: #f0f6fc;
                }
                QHeaderView::section {
                    background-color: #3d444d;
                    color: #e6edf3;
                    font-weight: 600;
                    padding: 8px;
                    border: none;
                    border-bottom: 1px solid #3d444d;
                }
            """)
            self.content_layout.addWidget(self.threats_table)

            self.content_layout.addStretch()
            scroll.setWidget(self.content)
            layout.addWidget(scroll)

        def _add_section(self, title: str, icon: str = "●", color: str = "#8b949e"):
            """Add a section header with icon"""
            section_container = QWidget()
            section_layout = QHBoxLayout(section_container)
            section_layout.setContentsMargins(0, 8, 0, 4)
            section_layout.setSpacing(8)

            icon_label = QLabel(icon)
            icon_label.setStyleSheet(f"font-size: 14px; color: {color};")
            section_layout.addWidget(icon_label)

            label = QLabel(title)
            label.setObjectName("SectionTitle")
            label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 700; letter-spacing: 1px;")
            section_layout.addWidget(label)

            # Separator line
            line = QFrame()
            line.setFrameShape(QFrame.HLine)
            line.setStyleSheet(f"background-color: {color}40;")
            line.setFixedHeight(1)
            section_layout.addWidget(line, 1)

            self.content_layout.addWidget(section_container)

        def _add_field(self, label: str, value: str) -> QLabel:
            """Add a field row with label and value"""
            row = QHBoxLayout()
            row.setSpacing(12)

            lbl = QLabel(label)
            lbl.setStyleSheet("color: #e6edf3; font-size: 13px; font-weight: 500;")
            lbl.setFixedWidth(130)
            row.addWidget(lbl)

            val = QLabel(value)
            val.setObjectName("FieldValue")
            val.setStyleSheet("""
                QLabel#FieldValue {
                    color: #74c0fc;
                    font-size: 14px;
                    font-weight: 600;
                    background-color: transparent;
                }
            """)
            val.setWordWrap(True)
            row.addWidget(val, 1)

            self.content_layout.addLayout(row)
            return val

        def update_asset(self, asset_data: dict):
            """Update panel with asset data"""
            self.ip_label.setText(asset_data.get("ip", "-"))
            self.mac_label.setText(asset_data.get("mac", "-"))
            self.device_type.setText(asset_data.get("device_type", "-"))
            self.classification.setText(asset_data.get("classification", "-"))

            # Risk badge with icon
            risk = asset_data.get("risk_level", "LOW")
            risk_configs = {
                "CRITICAL": ("◉ CRITICAL", "#f85149", "#f8514920"),
                "HIGH": ("◈ HIGH", "#db6d28", "#db6d2820"),
                "MEDIUM": ("◬ MEDIUM", "#d29922", "#d2992220"),
                "LOW": ("◇ LOW", "#3fb950", "#3fb95020")
            }
            text, color, bg = risk_configs.get(risk, risk_configs["LOW"])
            self.risk_badge.setText(text)
            self.risk_badge.setStyleSheet(f"""
                font-size: 12px; font-weight: 700;
                padding: 6px 12px;
                border-radius: 6px;
                color: {color};
                background-color: {bg};
                border: 1px solid {color}40;
            """)

            self.risk_reasons.setText(asset_data.get("risk_reasons", "-"))
            self.first_seen.setText(asset_data.get("first_seen", "-"))
            self.last_seen.setText(asset_data.get("last_seen", "-"))
            self.packets.setText(f"{asset_data.get('packets', 0):,}")
            self.bytes.setText(asset_data.get("bytes_str", "-"))

            # Protocols with badges
            protocols = asset_data.get("protocols", [])
            if protocols:
                proto_text = " · ".join([f"⚙ {p}" for p in protocols])
                self.protocols_label.setText(proto_text)
            else:
                self.protocols_label.setText("-")

            # Threats
            threats = asset_data.get("threats", [])
            self.threats_table.setRowCount(len(threats))
            for i, threat in enumerate(threats):
                self.threats_table.setItem(i, 0, QTableWidgetItem(threat.get("type", "")))
                self.threats_table.setItem(i, 1, QTableWidgetItem(threat.get("details", "")))


    # =========================================================================
    # ASSET CLASSIFICATION VIEW - Risk-first redesign
    # =========================================================================

    class AssetClassificationView(QWidget):
        """Redesigned asset classification with risk-first approach"""

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.asset_detail_visible = False

            # Main layout with splitter
            main_layout = QHBoxLayout(self)
            main_layout.setContentsMargins(0, 0, 0, 0)
            main_layout.setSpacing(0)

            # Left content area
            content = QWidget()
            content_layout = QVBoxLayout(content)
            content_layout.setContentsMargins(24, 20, 24, 20)
            content_layout.setSpacing(20)

            # Header with title and filter
            header = QHBoxLayout()

            title = QLabel("Asset Classification")
            title.setStyleSheet("font-size: 20px; font-weight: 700;")
            header.addWidget(title)

            header.addStretch()

            # Filter controls
            self.filter_type = QComboBox()
            self.filter_type.addItems(["All Types", "OT Devices", "IT Devices", "Unknown"])
            self.filter_type.setFixedWidth(140)
            self.filter_type.currentIndexChanged.connect(self._apply_filters)
            header.addWidget(self.filter_type)

            self.filter_risk = QComboBox()
            self.filter_risk.addItems(["All Risk", "Critical", "High", "Medium", "Low"])
            self.filter_risk.setFixedWidth(120)
            self.filter_risk.currentIndexChanged.connect(self._apply_filters)
            header.addWidget(self.filter_risk)

            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("🔍 Search IP or MAC...")
            self.search_input.setFixedWidth(200)
            self.search_input.textChanged.connect(self._apply_filters)
            header.addWidget(self.search_input)

            content_layout.addLayout(header)

            # Metrics row
            metrics_row = QHBoxLayout()
            metrics_row.setSpacing(12)

            self.metric_total = CompactMetric("Total Assets", "0", "text_primary", "total", theme_manager)
            self.metric_ot = CompactMetric("OT Devices", "0", "ot_device", "ot", theme_manager)
            self.metric_it = CompactMetric("IT Devices", "0", "it_device", "it", theme_manager)
            self.metric_unknown = CompactMetric("Unknown", "0", "unknown_device", "unknown", theme_manager)
            self.metric_high_risk = CompactMetric("High Risk", "0", "risk_critical", "high_risk", theme_manager)

            for metric in [self.metric_total, self.metric_ot, self.metric_it,
                          self.metric_unknown, self.metric_high_risk]:
                metric.clicked.connect(self._on_metric_clicked)
                metrics_row.addWidget(metric)

            metrics_row.addStretch()

            # Risk summary
            self.risk_summary = RiskSummaryWidget(theme_manager)
            self.risk_summary.setFixedWidth(280)
            metrics_row.addWidget(self.risk_summary)

            content_layout.addLayout(metrics_row)

            # Asset table
            self.asset_table = QTableWidget()
            self.asset_table.setColumnCount(8)
            self.asset_table.setHorizontalHeaderLabels([
                "Risk", "IP Address", "MAC", "Type", "Classification",
                "Protocols", "Packets", "Last Seen"
            ])

            # Add tooltips to column headers
            header_tooltips = [
                "Overall risk level (CRITICAL/HIGH/MEDIUM/LOW)\nBased on anomaly count and attack types",
                "Device IPv4 address",
                "MAC address (if available). Helps identify the vendor",
                "Device type (OT Device / IT Device / Unknown)",
                "Detailed classification (PLC, HMI, Server, Workstation, etc.)",
                "Protocols used. Click to see all in the detail panel",
                "Total packets to/from this device",
                "Time traffic was last observed"
            ]
            for i, tooltip in enumerate(header_tooltips):
                self.asset_table.horizontalHeaderItem(i).setToolTip(tooltip)
            self.asset_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.asset_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)  # Protocols stretches
            self.asset_table.setAlternatingRowColors(True)
            self.asset_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.asset_table.setSelectionMode(QTableWidget.SingleSelection)
            self.asset_table.setSortingEnabled(True)
            self.asset_table.itemSelectionChanged.connect(self._on_asset_selected)

            # Enable context menu (right-click)
            self.asset_table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.asset_table.customContextMenuRequested.connect(self._show_context_menu)

            # Enable double-click to show detail panel
            self.asset_table.doubleClicked.connect(self._show_asset_detail_on_double_click)

            content_layout.addWidget(self.asset_table)

            # Use QSplitter for resizable detail panel
            self.splitter = QSplitter(Qt.Horizontal)
            self.splitter.setChildrenCollapsible(False)
            self.splitter.addWidget(content)

            # Right detail panel (initially hidden)
            self.detail_panel = AssetDetailPanel(theme_manager)
            self.detail_panel.closed.connect(self._hide_detail_panel)
            self.detail_panel.setVisible(False)
            self.splitter.addWidget(self.detail_panel)

            # Set initial sizes (content takes most space, panel 400px default)
            self.splitter.setSizes([800, 400])
            self.splitter.setStretchFactor(0, 1)
            self.splitter.setStretchFactor(1, 0)

            main_layout.addWidget(self.splitter)

            # Store assets data
            self.assets_data = {}
            self.filtered_assets = {}

        def _on_metric_clicked(self, metric_id: str):
            """Handle metric click for quick filtering"""
            filter_map = {
                "ot": 1,       # OT Devices
                "it": 2,       # IT Devices
                "unknown": 3,  # Unknown
                "high_risk": 0, # Will set risk filter
                "total": 0,    # All
            }

            if metric_id == "high_risk":
                self.filter_type.setCurrentIndex(0)  # All types
                self.filter_risk.setCurrentIndex(1)  # Critical
            elif metric_id in filter_map:
                self.filter_type.setCurrentIndex(filter_map[metric_id])
                self.filter_risk.setCurrentIndex(0)  # All risk

        def _apply_filters(self):
            """Apply current filters to asset table"""
            type_filter = self.filter_type.currentText()
            risk_filter = self.filter_risk.currentText()
            search_text = self.search_input.text().lower()

            self.filtered_assets = {}
            for ip, asset in self.assets_data.items():
                # Type filter
                if type_filter != "All Types":
                    classification = asset.get("classification", "Unknown")
                    if type_filter == "OT Devices" and classification != "OT":
                        continue
                    if type_filter == "IT Devices" and classification != "IT":
                        continue
                    if type_filter == "Unknown" and classification not in ["Unknown", ""]:
                        continue

                # Risk filter
                if risk_filter != "All Risk":
                    risk = asset.get("risk_level", "LOW")
                    if risk_filter.upper() != risk:
                        continue

                # Search filter
                if search_text:
                    ip_match = search_text in ip.lower()
                    mac_match = search_text in asset.get("mac", "").lower()
                    if not ip_match and not mac_match:
                        continue

                self.filtered_assets[ip] = asset

            self._refresh_table()

        def _refresh_table(self):
            """Refresh table with filtered data - optimized"""
            self.asset_table.setSortingEnabled(False)
            self.asset_table.setUpdatesEnabled(False)
            try:
                self.asset_table.setRowCount(len(self.filtered_assets))

                risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                sorted_assets = sorted(
                    self.filtered_assets.items(),
                    key=lambda x: risk_order.get(x[1].get("risk_level", "LOW"), 3)
                )

                # Pre-create QColor objects
                risk_colors = {
                    "CRITICAL": (QColor("#f85149"), QColor("#f8514920")),
                    "HIGH": (QColor("#db6d28"), QColor("#db6d2820")),
                    "MEDIUM": (QColor("#d29922"), QColor("#d2992220")),
                    "LOW": (QColor("#3fb950"), QColor("#3fb95020")),
                }
                default_risk = (QColor("#8b949e"), QColor("#3d444d"))
                class_colors = {
                    "OT": QColor("#a371f7"),
                    "IT": QColor("#58a6ff"),
                    "Unknown": QColor("#6e7681"),
                }

                for row, (ip, asset) in enumerate(sorted_assets):
                    risk = asset.get("risk_level", "LOW")
                    risk_item = QTableWidgetItem(risk)
                    fg, bg = risk_colors.get(risk, default_risk)
                    risk_item.setForeground(fg)
                    risk_item.setBackground(bg)
                    risk_item.setTextAlignment(Qt.AlignCenter)
                    self.asset_table.setItem(row, 0, risk_item)

                    self.asset_table.setItem(row, 1, QTableWidgetItem(ip))
                    self.asset_table.setItem(row, 2, QTableWidgetItem(asset.get("mac", "-")))
                    self.asset_table.setItem(row, 3, QTableWidgetItem(asset.get("device_type", "-")))

                    classification = asset.get("classification", "Unknown")
                    class_item = QTableWidgetItem(classification)
                    class_item.setForeground(class_colors.get(classification, QColor("#6e7681")))
                    self.asset_table.setItem(row, 4, class_item)

                    protocols = asset.get("protocols", [])
                    proto_str = ", ".join(protocols[:3])
                    if len(protocols) > 3:
                        proto_str += f" +{len(protocols)-3}"
                    self.asset_table.setItem(row, 5, QTableWidgetItem(proto_str))

                    packets = asset.get("packets", 0)
                    packets_item = QTableWidgetItem(f"{packets:,}")
                    packets_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                    self.asset_table.setItem(row, 6, packets_item)

                    self.asset_table.setItem(row, 7, QTableWidgetItem(asset.get("last_seen", "-")))
            finally:
                self.asset_table.setUpdatesEnabled(True)
                self.asset_table.setSortingEnabled(True)

        def _on_asset_selected(self):
            """Handle asset selection - show detail panel"""
            selected = self.asset_table.selectedItems()
            if not selected:
                return

            row = selected[0].row()
            ip = self.asset_table.item(row, 1).text()

            if ip in self.filtered_assets:
                self.detail_panel.update_asset(self.filtered_assets[ip])
                self.detail_panel.setVisible(True)

        def _hide_detail_panel(self):
            """Hide the detail panel"""
            self.detail_panel.setVisible(False)
            self.asset_table.clearSelection()

        def update_assets(self, analyzer):
            """Update assets from analyzer"""
            if not analyzer or not hasattr(analyzer, 'assets'):
                return

            self.assets_data = {}
            assets = analyzer.assets

            # Count by classification and risk
            counts = {"total": 0, "ot": 0, "it": 0, "unknown": 0}
            risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for ip, asset in assets.items():
                # Determine classification
                classification = self._classify_asset(asset, analyzer)

                # Calculate risk
                risk_level, risk_reasons = self._calculate_risk(ip, asset, analyzer)

                # Build asset data
                asset_data = {
                    "ip": ip,
                    "mac": getattr(asset, 'mac_address', '-'),
                    "device_type": getattr(asset, 'device_type', 'Unknown'),
                    "classification": classification,
                    "protocols": list(getattr(asset, 'protocols_seen', [])),
                    "packets": getattr(asset, 'packet_count', 0),
                    "bytes": getattr(asset, 'bytes_total', 0),
                    "bytes_str": self._format_bytes(getattr(asset, 'bytes_total', 0)),
                    "first_seen": utc_str(getattr(asset, 'first_seen', 0)),
                    "last_seen": utc_str(getattr(asset, 'last_seen', 0)),
                    "risk_level": risk_level,
                    "risk_reasons": risk_reasons,
                    "threats": self._get_related_threats(ip, analyzer),
                }

                self.assets_data[ip] = asset_data

                # Update counts
                counts["total"] += 1
                if classification == "OT":
                    counts["ot"] += 1
                elif classification == "IT":
                    counts["it"] += 1
                else:
                    counts["unknown"] += 1

                risk_key = risk_level.lower()
                if risk_key in risk_counts:
                    risk_counts[risk_key] += 1

            # Update metrics
            self.metric_total.set_value(str(counts["total"]))
            self.metric_ot.set_value(str(counts["ot"]))
            self.metric_it.set_value(str(counts["it"]))
            self.metric_unknown.set_value(str(counts["unknown"]))
            self.metric_high_risk.set_value(str(risk_counts["critical"] + risk_counts["high"]))

            # Update risk summary
            self.risk_summary.update_risk(
                risk_counts["critical"],
                risk_counts["high"],
                risk_counts["medium"],
                risk_counts["low"]
            )

            # Apply filters and refresh
            self.filtered_assets = self.assets_data.copy()
            self._apply_filters()

        def _classify_asset(self, asset, analyzer) -> str:
            """Classify asset as OT/IT/Unknown"""
            protocols = getattr(asset, 'protocols_seen', set())
            device_type = getattr(asset, 'device_type', 'Unknown')

            OT_PROTOCOLS = {'MODBUS', 'S7COMM', 'DNP3', 'ENIP', 'BACNET', 'OPCUA', 'IEC104', 'MMS'}
            OT_TYPES = {'PLC', 'HMI', 'RTU', 'DCS', 'SCADA', 'IED'}

            if any(p.upper() in OT_PROTOCOLS for p in protocols):
                return "OT"
            if device_type.upper() in OT_TYPES:
                return "OT"
            if protocols & {'HTTP', 'HTTPS', 'DNS', 'SMB', 'RDP', 'SSH'}:
                return "IT"
            return "Unknown"

        def _calculate_risk(self, ip: str, asset, analyzer) -> tuple:
            """Calculate risk level and reasons"""
            reasons = []
            risk_score = 0

            # Check for anomalies
            if hasattr(analyzer, 'anomalies'):
                anomalies = [a for a in analyzer.anomalies if a.src_ip == ip or a.dst_ip == ip]
                critical_count = sum(1 for a in anomalies if a.severity == "CRITICAL")
                high_count = sum(1 for a in anomalies if a.severity == "HIGH")

                if critical_count > 0:
                    risk_score += 40
                    reasons.append(f"{critical_count} critical anomalies")
                if high_count > 0:
                    risk_score += 20
                    reasons.append(f"{high_count} high severity anomalies")
                if len(anomalies) > 10:
                    risk_score += 10
                    reasons.append(f"{len(anomalies)} total anomalies")

            # Check threat detector
            if hasattr(analyzer, 'threat_detector'):
                td = analyzer.threat_detector
                if ip in td.ip_risk_scores:
                    score = td.ip_risk_scores[ip]
                    if score > 0.7:
                        risk_score += 30
                        reasons.append(f"Threat score: {score:.2f}")
                    elif score > 0.5:
                        risk_score += 15

            # Determine level
            if risk_score >= 50:
                level = "CRITICAL"
            elif risk_score >= 30:
                level = "HIGH"
            elif risk_score >= 10:
                level = "MEDIUM"
            else:
                level = "LOW"

            return level, "; ".join(reasons) if reasons else "No significant risks detected"

        def _get_related_threats(self, ip: str, analyzer) -> list:
            """Get threats related to this IP"""
            threats = []
            if hasattr(analyzer, 'anomalies'):
                for a in analyzer.anomalies[:5]:  # Limit to 5
                    if a.src_ip == ip or a.dst_ip == ip:
                        threats.append({
                            "type": a.anomaly_type,
                            "details": a.description[:50] if a.description else ""
                        })
            return threats

        def _format_bytes(self, bytes_count: int) -> str:
            for unit in ['B', 'KB', 'MB', 'GB']:
                if bytes_count < 1024:
                    return f"{bytes_count:.1f} {unit}"
                bytes_count /= 1024
            return f"{bytes_count:.1f} TB"

        def update_theme(self):
            """Update theme for all child widgets"""
            for metric in [self.metric_total, self.metric_ot, self.metric_it,
                          self.metric_unknown, self.metric_high_risk]:
                metric.update_theme()

        def _show_context_menu(self, position):
            """Show context menu for asset table row"""
            row = self.asset_table.rowAt(position.y())
            if row < 0:
                return

            menu = QMenu(self)
            menu.setStyleSheet("""
                QMenu {
                    background-color: #3d444d;
                    border: 1px solid #3d444d;
                    border-radius: 6px;
                    padding: 4px;
                }
                QMenu::item {
                    padding: 6px 20px;
                    color: #e6edf3;
                }
                QMenu::item:selected {
                    background-color: #388bfd;
                    color: white;
                }
            """)

            # Copy actions
            copy_row_action = menu.addAction("📋 Copy Row")
            copy_ip_action = menu.addAction("📋 Copy IP Address")
            copy_mac_action = menu.addAction("📋 Copy MAC Address")
            menu.addSeparator()
            details_action = menu.addAction("🔍 View Details")
            menu.addSeparator()
            filter_src_action = menu.addAction("🔎 Find as Source in Anomalies")
            filter_dst_action = menu.addAction("🔎 Find as Destination in Anomalies")

            action = menu.exec_(self.asset_table.viewport().mapToGlobal(position))

            if action == copy_row_action:
                self._copy_row_to_clipboard(row)
            elif action == copy_ip_action:
                self._copy_cell_to_clipboard(row, 1)
            elif action == copy_mac_action:
                self._copy_cell_to_clipboard(row, 2)
            elif action == details_action:
                self._show_asset_detail_on_double_click_row(row)
            elif action == filter_src_action:
                self._filter_anomalies_by_ip(row, "src")
            elif action == filter_dst_action:
                self._filter_anomalies_by_ip(row, "dst")

        def _copy_row_to_clipboard(self, row: int):
            """Copy entire row to clipboard as tab-separated values"""
            values = []
            for col in range(self.asset_table.columnCount()):
                item = self.asset_table.item(row, col)
                values.append(item.text() if item else "")
            clipboard = QApp.clipboard()
            clipboard.setText("\t".join(values))

        def _copy_cell_to_clipboard(self, row: int, col: int):
            """Copy single cell value to clipboard"""
            item = self.asset_table.item(row, col)
            if item:
                clipboard = QApp.clipboard()
                clipboard.setText(item.text())

        def _show_asset_detail_on_double_click(self, index):
            """Show asset detail panel on double-click"""
            self._show_asset_detail_on_double_click_row(index.row())

        def _show_asset_detail_on_double_click_row(self, row: int):
            """Show asset detail panel for specific row"""
            if row < 0:
                return
            ip_item = self.asset_table.item(row, 1)
            if ip_item:
                ip = ip_item.text()
                if ip in self.assets_data:
                    self.detail_panel.update_asset(self.assets_data[ip])
                    self.detail_panel.setVisible(True)

        def _filter_anomalies_by_ip(self, row: int, direction: str):
            """Navigate to anomalies view with IP filter (placeholder for integration)"""
            ip_item = self.asset_table.item(row, 1)
            if ip_item:
                ip = ip_item.text()
                # Store the filter request for parent window to handle
                self._pending_filter = {"ip": ip, "direction": direction}
                # Signal parent to switch to anomalies view (needs MainWindow integration)


    # =========================================================================
    # DASHBOARD VIEW - Overview with key metrics
    # =========================================================================

    class DashboardView(QWidget):
        """Main dashboard with key security metrics and enhanced styling"""

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager

            layout = QVBoxLayout(self)
            layout.setContentsMargins(24, 20, 24, 20)
            layout.setSpacing(24)

            # Title with icon
            title_row = QHBoxLayout()
            title_icon = QLabel("◉")
            title_icon.setStyleSheet("font-size: 26px; color: #74c0fc;")
            title_row.addWidget(title_icon)

            title = QLabel("Security Overview")
            title.setStyleSheet("font-size: 22px; font-weight: 700; margin-left: 10px; color: #f0f6fc;")
            title_row.addWidget(title)

            # Status badge
            self.status_badge = QLabel("◌ Awaiting Analysis")
            self.status_badge.setStyleSheet("""
                font-size: 12px; font-weight: 600;
                color: #e6edf3;
                padding: 4px 12px;
                background-color: #3d444d;
                border-radius: 12px;
                margin-left: 16px;
            """)
            title_row.addWidget(self.status_badge)

            title_row.addStretch()
            layout.addLayout(title_row)

            # Top metrics row with enhanced styling
            metrics_row = QHBoxLayout()
            metrics_row.setSpacing(16)

            self.metric_packets = CompactMetric("Total Packets", "0", "accent_blue", "packets", theme_manager, icon="▦")
            self.metric_events = CompactMetric("OT Events", "0", "accent_purple", "events", theme_manager, icon="⚙")
            self.metric_assets = CompactMetric("Assets", "0", "accent_green", "assets", theme_manager, icon="◫")
            self.metric_anomalies = CompactMetric("Anomalies", "0", "accent_yellow", "anomalies", theme_manager, icon="△")
            self.metric_critical = CompactMetric("Critical", "0", "risk_critical", "critical", theme_manager, icon="◉")

            for m in [self.metric_packets, self.metric_events, self.metric_assets,
                     self.metric_anomalies, self.metric_critical]:
                metrics_row.addWidget(m)

            metrics_row.addStretch()
            layout.addLayout(metrics_row)

            # Two column layout
            columns = QHBoxLayout()
            columns.setSpacing(20)

            # Left column - Analysis summary
            left_col = QVBoxLayout()
            left_col.setSpacing(16)

            summary_group = QGroupBox("◎ Analysis Summary")
            summary_layout = QVBoxLayout(summary_group)
            self.summary_text = QTextEdit()
            self.summary_text.setReadOnly(True)
            self.summary_text.setMinimumHeight(200)
            self.summary_text.setHtml("""
                <div style='color:#6e7681; padding:30px; text-align:center;'>
                    <div style='font-size: 32px; margin-bottom: 12px;'>◈</div>
                    <div style='font-size: 14px;'>No analysis data</div>
                    <div style='font-size: 12px; margin-top: 8px; color: #484f58;'>
                        Import a PCAP file to begin security analysis
                    </div>
                </div>
            """)
            summary_layout.addWidget(self.summary_text)
            left_col.addWidget(summary_group)

            # Protocol distribution
            proto_group = QGroupBox("⚙ Protocol Distribution")
            proto_layout = QVBoxLayout(proto_group)
            self.proto_table = QTableWidget()
            self.proto_table.setColumnCount(3)
            self.proto_table.setHorizontalHeaderLabels(["◎ Protocol", "▦ Count", "◇ %"])
            self.proto_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            proto_layout.addWidget(self.proto_table)
            left_col.addWidget(proto_group)

            columns.addLayout(left_col, 1)

            # Right column - Critical alerts
            right_col = QVBoxLayout()
            right_col.setSpacing(16)

            alerts_group = QGroupBox("⚡ Critical Alerts")
            alerts_layout = QVBoxLayout(alerts_group)
            self.alerts_table = QTableWidget()
            self.alerts_table.setColumnCount(4)
            self.alerts_table.setHorizontalHeaderLabels(["⏱ Time", "⚙ Type", "◈ Source", "◉ Severity"])
            self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.alerts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
            self.alerts_table.setAlternatingRowColors(True)
            alerts_layout.addWidget(self.alerts_table)
            right_col.addWidget(alerts_group)

            # MITRE techniques
            mitre_group = QGroupBox("◆ Top MITRE Techniques")
            mitre_layout = QVBoxLayout(mitre_group)
            self.mitre_table = QTableWidget()
            self.mitre_table.setColumnCount(3)
            self.mitre_table.setHorizontalHeaderLabels(["◎ Technique", "▦ Count", "◉ Severity"])
            self.mitre_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.mitre_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            mitre_layout.addWidget(self.mitre_table)
            right_col.addWidget(mitre_group)

            columns.addLayout(right_col, 1)

            layout.addLayout(columns)

        def update_dashboard(self, summary: dict):
            """Update dashboard with analysis summary"""
            self.metric_packets.set_value(f"{summary.get('PACKETS_PARSED', 0):,}")
            self.metric_events.set_value(f"{summary.get('OT_EVENTS_TOTAL', 0):,}")
            self.metric_assets.set_value(str(summary.get('OT_ASSETS', 0)))
            self.metric_anomalies.set_value(str(summary.get('ANOMALIES_DETECTED', 0)))
            self.metric_critical.set_value(str(summary.get('CRITICAL_EVENTS', 0)))

            # Update status badge
            if summary.get('PACKETS_PARSED', 0) > 0:
                critical = summary.get('CRITICAL_EVENTS', 0)
                if critical > 0:
                    self.status_badge.setText(f"◉ {critical} Critical Alerts")
                    self.status_badge.setStyleSheet("""
                        font-size: 12px; font-weight: 600;
                        color: #f85149;
                        padding: 4px 12px;
                        background-color: #f8514920;
                        border-radius: 12px;
                        margin-left: 16px;
                    """)
                else:
                    self.status_badge.setText("● Analysis Complete")
                    self.status_badge.setStyleSheet("""
                        font-size: 12px; font-weight: 600;
                        color: #3fb950;
                        padding: 4px 12px;
                        background-color: #3fb95020;
                        border-radius: 12px;
                        margin-left: 16px;
                    """)

            # Summary HTML
            html = f"""
            <style>
                body {{ font-family: 'JetBrains Mono', monospace; color: #f0f6fc; }}
                table {{ width: 100%; border-collapse: collapse; }}
                td {{ padding: 8px 0; border-bottom: 1px solid #3d444d; }}
                .label {{ color: #e6edf3; width: 40%; }}
                .value {{ color: #f0f6fc; font-weight: 500; }}
            </style>
            <table>
                <tr><td class='label'>◎ Capture File</td><td class='value'>{summary.get('CAPTURE_FILE', '-')}</td></tr>
                <tr><td class='label'>▦ File Size</td><td class='value'>{summary.get('CAPTURE_SIZE', '-')}</td></tr>
                <tr><td class='label'>⏱ Duration</td><td class='value'>{summary.get('DURATION_STR', '-')}</td></tr>
                <tr><td class='label'>◷ Time Range</td><td class='value'>{summary.get('TIME_START', '')} - {summary.get('TIME_END', '')}</td></tr>
                <tr><td class='label'>⚡ MITRE Techniques</td><td class='value'>{summary.get('MITRE_TECHNIQUES', '-')}</td></tr>
            </table>
            """
            self.summary_text.setHtml(html)

            # Protocol distribution
            proto_counts = summary.get('OT_PROTOCOLS', {})
            total = sum(proto_counts.values()) or 1
            self.proto_table.setRowCount(len(proto_counts))
            for i, (proto, count) in enumerate(sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)):
                pct = count / total * 100
                self.proto_table.setItem(i, 0, QTableWidgetItem(proto))
                self.proto_table.setItem(i, 1, QTableWidgetItem(f"{count:,}"))
                pct_item = QTableWidgetItem(f"{pct:.1f}%")
                if pct > 50:
                    pct_item.setForeground(QColor("#3fb950"))
                self.proto_table.setItem(i, 2, pct_item)

        def update_alerts(self, anomalies: list):
            """Update critical alerts table"""
            critical_anomalies = [a for a in anomalies if a.severity in ("CRITICAL", "HIGH")][:20]
            self.alerts_table.setRowCount(len(critical_anomalies))

            for i, a in enumerate(critical_anomalies):
                self.alerts_table.setItem(i, 0, QTableWidgetItem(utc_str(a.timestamp)))
                self.alerts_table.setItem(i, 1, QTableWidgetItem(a.anomaly_type))
                self.alerts_table.setItem(i, 2, QTableWidgetItem(a.src_ip))

                sev_item = QTableWidgetItem(a.severity)
                color = "#f85149" if a.severity == "CRITICAL" else "#db6d28"
                sev_item.setForeground(QColor(color))
                self.alerts_table.setItem(i, 3, sev_item)

        def update_theme(self):
            for m in [self.metric_packets, self.metric_events, self.metric_assets,
                     self.metric_anomalies, self.metric_critical]:
                m.update_theme()


    # =========================================================================
    # ANOMALIES VIEW
    # =========================================================================

    class AnomaliesView(QWidget):
        """View for displaying detected anomalies with enhanced styling"""

        # Severity icons mapping
        SEVERITY_ICONS = {
            "CRITICAL": ("◉", "#f85149"),
            "HIGH": ("◈", "#db6d28"),
            "MEDIUM": ("◬", "#d29922"),
            "LOW": ("◇", "#3fb950"),
            "INFO": ("○", "#58a6ff"),
        }

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager

            layout = QVBoxLayout(self)
            layout.setContentsMargins(24, 20, 24, 20)
            layout.setSpacing(16)

            # Header with icon
            header = QHBoxLayout()
            header_icon = QLabel("△")
            header_icon.setStyleSheet("font-size: 24px; color: #ffd43b;")
            header.addWidget(header_icon)

            title = QLabel("Detected Anomalies")
            title.setStyleSheet("font-size: 22px; font-weight: 700; margin-left: 8px; color: #f0f6fc;")
            header.addWidget(title)

            header.addStretch()

            # Severity filter with icon
            sev_label = QLabel("◉")
            sev_label.setStyleSheet("font-size: 14px; color: #e6edf3;")
            header.addWidget(sev_label)

            self.severity_filter = QComboBox()
            self.severity_filter.addItems(["All Severity", "Critical", "High", "Medium", "Low"])
            self.severity_filter.currentIndexChanged.connect(self._apply_filter)
            header.addWidget(self.severity_filter)

            # Type filter with icon
            type_label = QLabel("⚙")
            type_label.setStyleSheet("font-size: 14px; color: #e6edf3; margin-left: 12px;")
            header.addWidget(type_label)

            self.type_filter = QComboBox()
            self.type_filter.addItems(["All Types"])
            self.type_filter.setFixedWidth(180)
            self.type_filter.currentIndexChanged.connect(self._apply_filter)
            header.addWidget(self.type_filter)

            layout.addLayout(header)

            # Summary stats row
            self.stats_row = QHBoxLayout()
            self.stats_row.setSpacing(16)

            self.stat_labels = {}
            for level, (icon, color) in self.SEVERITY_ICONS.items():
                stat = QLabel(f"{icon} {level}: 0")
                stat.setStyleSheet(f"font-size: 13px; font-weight: 600; color: {color}; padding: 4px 10px; background-color: {color}15; border-radius: 4px;")
                self.stat_labels[level] = stat
                self.stats_row.addWidget(stat)
            self.stats_row.addStretch()

            layout.addLayout(self.stats_row)

            # Table with enhanced styling
            self.table = QTableWidget()
            self.table.setColumnCount(8)
            self.table.setHorizontalHeaderLabels([
                "⏱ Time", "◉ Severity", "⚙ Type", "◈ Source", "◇ Destination",
                "▦ Protocol", "◎ Description", "⚡ MITRE"
            ])

            # Add tooltips to column headers
            header_tooltips = [
                "Time the anomaly was detected (UTC)",
                "Severity: CRITICAL > HIGH > MEDIUM > LOW",
                "Anomaly type / attack technique",
                "Source IP address (attacker or infected host)",
                "Destination IP address (target or C2 server)",
                "Network protocol (TCP/UDP/HTTP/OT protocols)",
                "Detailed anomaly description. Double-click to view in full",
                "Related MITRE ATT&CK techniques"
            ]
            for i, tooltip in enumerate(header_tooltips):
                self.table.horizontalHeaderItem(i).setToolTip(tooltip)

            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)  # Description stretches
            self.table.setAlternatingRowColors(True)
            self.table.setSelectionBehavior(QTableWidget.SelectRows)

            # Enable context menu (right-click)
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._show_context_menu)

            # Enable double-click to show details
            self.table.doubleClicked.connect(self._show_anomaly_details)

            layout.addWidget(self.table)

            # Pagination controls
            pagination_layout = QHBoxLayout()
            pagination_layout.setSpacing(8)

            self.page_info_label = QLabel("Page 1 of 1")
            self.page_info_label.setStyleSheet("color: #8b949e; font-size: 12px;")
            pagination_layout.addWidget(self.page_info_label)

            pagination_layout.addStretch()

            # Rows per page selector
            rows_label = QLabel("Rows:")
            rows_label.setStyleSheet("color: #8b949e; font-size: 12px;")
            pagination_layout.addWidget(rows_label)

            self.rows_per_page_combo = QComboBox()
            self.rows_per_page_combo.addItems(["100", "250", "500", "1000", "All"])
            self.rows_per_page_combo.setCurrentIndex(1)  # Default 250
            self.rows_per_page_combo.setFixedWidth(70)
            self.rows_per_page_combo.currentIndexChanged.connect(self._on_page_size_changed)
            pagination_layout.addWidget(self.rows_per_page_combo)

            # Navigation buttons
            self.btn_first = QPushButton("⏮")
            self.btn_first.setFixedSize(32, 28)
            self.btn_first.setToolTip("First page")
            self.btn_first.clicked.connect(lambda: self._go_to_page(0))
            pagination_layout.addWidget(self.btn_first)

            self.btn_prev = QPushButton("◀")
            self.btn_prev.setFixedSize(32, 28)
            self.btn_prev.setToolTip("Previous page")
            self.btn_prev.clicked.connect(lambda: self._go_to_page(self.current_page - 1))
            pagination_layout.addWidget(self.btn_prev)

            self.page_input = QLineEdit("1")
            self.page_input.setFixedWidth(50)
            self.page_input.setAlignment(Qt.AlignCenter)
            self.page_input.setStyleSheet("background-color: #3d444d; border: 1px solid #3d444d; border-radius: 4px; color: #f0f6fc; padding: 4px;")
            self.page_input.returnPressed.connect(self._on_page_input)
            pagination_layout.addWidget(self.page_input)

            self.btn_next = QPushButton("▶")
            self.btn_next.setFixedSize(32, 28)
            self.btn_next.setToolTip("Next page")
            self.btn_next.clicked.connect(lambda: self._go_to_page(self.current_page + 1))
            pagination_layout.addWidget(self.btn_next)

            self.btn_last = QPushButton("⏭")
            self.btn_last.setFixedSize(32, 28)
            self.btn_last.setToolTip("Last page")
            self.btn_last.clicked.connect(lambda: self._go_to_page(self.total_pages - 1))
            pagination_layout.addWidget(self.btn_last)

            # Total records label
            self.total_label = QLabel("0 records")
            self.total_label.setStyleSheet("color: #58a6ff; font-size: 12px; font-weight: 600; margin-left: 12px;")
            pagination_layout.addWidget(self.total_label)

            layout.addLayout(pagination_layout)

            # Pagination state
            self.all_anomalies = []
            self.filtered_anomalies = []
            self.current_page = 0
            self.rows_per_page = 250
            self.total_pages = 1

        def update_anomalies(self, anomalies: list):
            """Update anomalies list"""
            self.all_anomalies = anomalies
            self.filtered_anomalies = anomalies

            # Update type filter
            types = set(a.anomaly_type for a in anomalies)
            self.type_filter.clear()
            self.type_filter.addItem("All Types")
            self.type_filter.addItems(sorted(types))

            # Update stats
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for a in anomalies:
                sev = a.severity.upper() if hasattr(a, 'severity') else "INFO"
                if sev in severity_counts:
                    severity_counts[sev] += 1

            for level, stat_label in self.stat_labels.items():
                icon, color = self.SEVERITY_ICONS.get(level, ("○", "#8b949e"))
                count = severity_counts.get(level, 0)
                stat_label.setText(f"{icon} {level}: {count}")

            # Reset to first page and refresh
            self.current_page = 0
            self._update_pagination()
            self._refresh_table()

        def _apply_filter(self):
            """Apply current filters"""
            filtered = self.all_anomalies

            severity = self.severity_filter.currentText()
            if severity != "All Severity":
                filtered = [a for a in filtered if a.severity.upper() == severity.upper()]

            atype = self.type_filter.currentText()
            if atype != "All Types":
                filtered = [a for a in filtered if a.anomaly_type == atype]

            self.filtered_anomalies = filtered
            self.current_page = 0
            self._update_pagination()
            self._refresh_table()

        def _on_page_size_changed(self):
            """Handle rows per page change"""
            text = self.rows_per_page_combo.currentText()
            if text == "All":
                self.rows_per_page = len(self.filtered_anomalies) or 1000
            else:
                self.rows_per_page = int(text)
            self.current_page = 0
            self._update_pagination()
            self._refresh_table()

        def _go_to_page(self, page: int):
            """Navigate to specific page"""
            if 0 <= page < self.total_pages:
                self.current_page = page
                self._update_pagination()
                self._refresh_table()

        def _on_page_input(self):
            """Handle manual page input"""
            try:
                page = int(self.page_input.text()) - 1  # Convert to 0-indexed
                self._go_to_page(page)
            except ValueError:
                self.page_input.setText(str(self.current_page + 1))

        def _update_pagination(self):
            """Update pagination controls"""
            total = len(self.filtered_anomalies)
            self.total_pages = max(1, (total + self.rows_per_page - 1) // self.rows_per_page)

            # Update labels
            self.page_info_label.setText(f"Page {self.current_page + 1} of {self.total_pages}")
            self.page_input.setText(str(self.current_page + 1))
            self.total_label.setText(f"{total:,} records")

            # Enable/disable navigation buttons
            self.btn_first.setEnabled(self.current_page > 0)
            self.btn_prev.setEnabled(self.current_page > 0)
            self.btn_next.setEnabled(self.current_page < self.total_pages - 1)
            self.btn_last.setEnabled(self.current_page < self.total_pages - 1)

        def _refresh_table(self):
            """Refresh table with current page data"""
            start_idx = self.current_page * self.rows_per_page
            end_idx = min(start_idx + self.rows_per_page, len(self.filtered_anomalies))
            display_list = self.filtered_anomalies[start_idx:end_idx]

            self.table.setSortingEnabled(False)
            self.table.setUpdatesEnabled(False)
            try:
                self.table.setRowCount(len(display_list))

                sev_colors = {
                    "CRITICAL": QColor("#f85149"),
                    "HIGH": QColor("#db6d28"),
                    "MEDIUM": QColor("#d29922"),
                    "LOW": QColor("#3fb950"),
                }
                default_color = QColor("#8b949e")

                for i, a in enumerate(display_list):
                    self.table.setItem(i, 0, QTableWidgetItem(utc_str(a.timestamp)))

                    sev_item = QTableWidgetItem(a.severity)
                    sev_item.setForeground(sev_colors.get(a.severity, default_color))
                    self.table.setItem(i, 1, sev_item)

                    self.table.setItem(i, 2, QTableWidgetItem(a.anomaly_type))
                    self.table.setItem(i, 3, QTableWidgetItem(a.src_ip))
                    self.table.setItem(i, 4, QTableWidgetItem(a.dst_ip))
                    self.table.setItem(i, 5, QTableWidgetItem(getattr(a, 'protocol', '-')))

                    desc = a.description
                    self.table.setItem(i, 6, QTableWidgetItem(desc[:120] if desc else ""))

                    mitre = ", ".join(a.mitre_techniques) if hasattr(a, 'mitre_techniques') and a.mitre_techniques else "-"
                    self.table.setItem(i, 7, QTableWidgetItem(mitre))
            finally:
                self.table.setUpdatesEnabled(True)
                self.table.setSortingEnabled(True)

        def _show_context_menu(self, position):
            """Show context menu for table row"""
            row = self.table.rowAt(position.y())
            if row < 0:
                return

            menu = QMenu(self)
            menu.setStyleSheet("""
                QMenu {
                    background-color: #3d444d;
                    border: 1px solid #3d444d;
                    border-radius: 6px;
                    padding: 4px;
                }
                QMenu::item {
                    padding: 6px 20px;
                    color: #e6edf3;
                }
                QMenu::item:selected {
                    background-color: #388bfd;
                    color: white;
                }
            """)

            # Copy actions
            copy_row_action = menu.addAction("📋 Copy Row")
            copy_src_action = menu.addAction("📋 Copy Source IP")
            copy_dst_action = menu.addAction("📋 Copy Destination IP")
            menu.addSeparator()
            copy_desc_action = menu.addAction("📋 Copy Description")
            copy_mitre_action = menu.addAction("📋 Copy MITRE Techniques")
            menu.addSeparator()
            details_action = menu.addAction("🔍 View Details")

            action = menu.exec_(self.table.viewport().mapToGlobal(position))

            if action == copy_row_action:
                self._copy_row_to_clipboard(row)
            elif action == copy_src_action:
                self._copy_cell_to_clipboard(row, 3)
            elif action == copy_dst_action:
                self._copy_cell_to_clipboard(row, 4)
            elif action == copy_desc_action:
                self._copy_cell_to_clipboard(row, 6)
            elif action == copy_mitre_action:
                self._copy_cell_to_clipboard(row, 7)
            elif action == details_action:
                self._show_anomaly_details_for_row(row)

        def _copy_row_to_clipboard(self, row: int):
            """Copy entire row to clipboard as tab-separated values"""
            values = []
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                values.append(item.text() if item else "")
            clipboard = QApp.clipboard()
            clipboard.setText("\t".join(values))

        def _copy_cell_to_clipboard(self, row: int, col: int):
            """Copy single cell value to clipboard"""
            item = self.table.item(row, col)
            if item:
                clipboard = QApp.clipboard()
                clipboard.setText(item.text())

        def _show_anomaly_details(self, index):
            """Show anomaly details on double-click"""
            row = index.row()
            self._show_anomaly_details_for_row(row)

        def _show_anomaly_details_for_row(self, row: int):
            """Show detailed anomaly information in a dialog"""
            # Calculate actual index in filtered list accounting for pagination
            actual_idx = self.current_page * self.rows_per_page + row
            if actual_idx < 0 or actual_idx >= len(self.filtered_anomalies):
                return

            anomaly = self.filtered_anomalies[actual_idx]

            # Create detail dialog
            msg = QMessageBox(self)
            msg.setWindowTitle(f"Anomaly Details - {anomaly.anomaly_type}")
            msg.setIcon(QMessageBox.Information)

            details = f"""
<b>Type:</b> {anomaly.anomaly_type}<br>
<b>Severity:</b> <span style="color: {self.SEVERITY_ICONS.get(anomaly.severity.upper(), ('', '#ffffff'))[1]}">{anomaly.severity}</span><br>
<b>Timestamp:</b> {getattr(anomaly, 'timestamp', 'N/A')}<br>
<b>Source:</b> {anomaly.src_ip}<br>
<b>Destination:</b> {anomaly.dst_ip}<br>
<b>Protocol:</b> {getattr(anomaly, 'protocol', 'N/A')}<br><br>
<b>Description:</b><br>{anomaly.description or 'N/A'}<br><br>
<b>MITRE Techniques:</b> {', '.join(getattr(anomaly, 'mitre_techniques', []))}<br>
<b>Confidence:</b> {getattr(anomaly, 'confidence', 'N/A')}<br><br>
<b>Recommendation:</b><br>{getattr(anomaly, 'recommendation', 'N/A')}
"""
            msg.setTextFormat(Qt.RichText)
            msg.setText(details)
            msg.setStyleSheet("""
                QMessageBox {
                    background-color: #252b33;
                }
                QMessageBox QLabel {
                    color: #e6edf3;
                    min-width: 500px;
                }
            """)
            msg.exec_()


    # =========================================================================
    # OT EVENTS VIEW
    # =========================================================================

    class OTEventsView(QWidget):
        """View for OT/ICS protocol events with enhanced styling"""

        # Protocol icons mapping
        PROTOCOL_ICONS = {
            "MODBUS": ("⚙", "#39c5cf"),
            "MODBUS_TCP": ("⚙", "#39c5cf"),
            "S7COMM": ("◈", "#a371f7"),
            "ETHERNET_IP": ("◎", "#58a6ff"),
            "ETHERNET/IP": ("◎", "#58a6ff"),
            "DNP3": ("◆", "#f85149"),
            "PROFINET": ("◇", "#3fb950"),
            "OPC_UA": ("◉", "#db6d28"),
            "BACNET": ("○", "#d29922"),
        }

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager

            layout = QVBoxLayout(self)
            layout.setContentsMargins(24, 20, 24, 20)
            layout.setSpacing(16)

            # Header with icon
            header = QHBoxLayout()
            header_icon = QLabel("⚙")
            header_icon.setStyleSheet("font-size: 24px; color: #63e6be;")
            header.addWidget(header_icon)

            title = QLabel("OT/ICS Events")
            title.setStyleSheet("font-size: 22px; font-weight: 700; margin-left: 8px; color: #f0f6fc;")
            header.addWidget(title)

            header.addStretch()

            # Protocol filter with icon
            proto_label = QLabel("▦")
            proto_label.setStyleSheet("font-size: 14px; color: #e6edf3;")
            header.addWidget(proto_label)

            self.proto_filter = QComboBox()
            self.proto_filter.addItems(["All Protocols"])
            self.proto_filter.setMinimumWidth(160)
            self.proto_filter.currentIndexChanged.connect(self._apply_filter)
            header.addWidget(self.proto_filter)

            layout.addLayout(header)

            # Protocol summary badges
            self.proto_summary = QHBoxLayout()
            self.proto_summary.setSpacing(12)
            self.proto_badges = {}
            layout.addLayout(self.proto_summary)

            # Table with enhanced headers
            self.table = QTableWidget()
            self.table.setColumnCount(8)
            self.table.setHorizontalHeaderLabels([
                "⏱ Time", "◈ Source", "◇ Destination", "⚙ Protocol",
                "◎ Function", "▷ Operation", "◉ Risk", "⚡ MITRE"
            ])

            # Add tooltips to column headers
            header_tooltips = [
                "Time the OT event was recorded (UTC)",
                "Source IP address (PLC, RTU, HMI, SCADA)",
                "Destination IP address (slave device or engineering station)",
                "OT/ICS protocol (Modbus, S7Comm, DNP3, EtherNet/IP, etc.)",
                "Protocol function code (Read/Write Coils, Registers, etc.)",
                "Description of the specific operation. Double-click to view details",
                "Risk level of this operation (HIGH/MEDIUM/LOW)",
                "Related MITRE ATT&CK for ICS techniques"
            ]
            for i, tooltip in enumerate(header_tooltips):
                self.table.horizontalHeaderItem(i).setToolTip(tooltip)

            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)  # Operation stretches
            self.table.setAlternatingRowColors(True)
            self.table.setSelectionBehavior(QTableWidget.SelectRows)

            # Enable context menu (right-click)
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._show_context_menu)

            # Enable double-click to show details
            self.table.doubleClicked.connect(self._show_event_details)

            layout.addWidget(self.table)

            # Pagination controls
            pagination_layout = QHBoxLayout()
            pagination_layout.setSpacing(8)

            self.page_info_label = QLabel("Page 1 of 1")
            self.page_info_label.setStyleSheet("color: #8b949e; font-size: 12px;")
            pagination_layout.addWidget(self.page_info_label)

            pagination_layout.addStretch()

            # Rows per page selector
            rows_label = QLabel("Rows:")
            rows_label.setStyleSheet("color: #8b949e; font-size: 12px;")
            pagination_layout.addWidget(rows_label)

            self.rows_per_page_combo = QComboBox()
            self.rows_per_page_combo.addItems(["100", "250", "500", "1000", "All"])
            self.rows_per_page_combo.setCurrentIndex(1)  # Default 250
            self.rows_per_page_combo.setFixedWidth(70)
            self.rows_per_page_combo.currentIndexChanged.connect(self._on_page_size_changed)
            pagination_layout.addWidget(self.rows_per_page_combo)

            # Navigation buttons
            self.btn_first = QPushButton("⏮")
            self.btn_first.setFixedSize(32, 28)
            self.btn_first.setToolTip("First page")
            self.btn_first.clicked.connect(lambda: self._go_to_page(0))
            pagination_layout.addWidget(self.btn_first)

            self.btn_prev = QPushButton("◀")
            self.btn_prev.setFixedSize(32, 28)
            self.btn_prev.setToolTip("Previous page")
            self.btn_prev.clicked.connect(lambda: self._go_to_page(self.current_page - 1))
            pagination_layout.addWidget(self.btn_prev)

            self.page_input = QLineEdit("1")
            self.page_input.setFixedWidth(50)
            self.page_input.setAlignment(Qt.AlignCenter)
            self.page_input.setStyleSheet("background-color: #3d444d; border: 1px solid #3d444d; border-radius: 4px; color: #f0f6fc; padding: 4px;")
            self.page_input.returnPressed.connect(self._on_page_input)
            pagination_layout.addWidget(self.page_input)

            self.btn_next = QPushButton("▶")
            self.btn_next.setFixedSize(32, 28)
            self.btn_next.setToolTip("Next page")
            self.btn_next.clicked.connect(lambda: self._go_to_page(self.current_page + 1))
            pagination_layout.addWidget(self.btn_next)

            self.btn_last = QPushButton("⏭")
            self.btn_last.setFixedSize(32, 28)
            self.btn_last.setToolTip("Last page")
            self.btn_last.clicked.connect(lambda: self._go_to_page(self.total_pages - 1))
            pagination_layout.addWidget(self.btn_last)

            # Total records label
            self.total_label = QLabel("0 records")
            self.total_label.setStyleSheet("color: #58a6ff; font-size: 12px; font-weight: 600; margin-left: 12px;")
            pagination_layout.addWidget(self.total_label)

            layout.addLayout(pagination_layout)

            # Pagination state
            self.all_events = []
            self.filtered_events = []
            self.current_page = 0
            self.rows_per_page = 250
            self.total_pages = 1

        def update_events(self, events: list):
            """Update OT events"""
            self.all_events = events
            self.filtered_events = events

            # Update protocol filter and count
            protocol_counts = {}
            for e in events:
                if hasattr(e, 'protocol'):
                    proto = e.protocol
                    if hasattr(proto, 'name'):
                        proto_str = str(proto.name)
                    elif hasattr(proto, 'value'):
                        proto_str = str(proto.value)
                    else:
                        proto_str = str(proto)
                    protocol_counts[proto_str] = protocol_counts.get(proto_str, 0) + 1

            self.proto_filter.clear()
            self.proto_filter.addItem("All Protocols")
            self.proto_filter.addItems(sorted(protocol_counts.keys()))

            # Update protocol badges
            for badge in self.proto_badges.values():
                badge.deleteLater()
            self.proto_badges.clear()

            for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1])[:6]:
                icon, color = self.PROTOCOL_ICONS.get(proto.upper(), ("○", "#8b949e"))
                badge = QLabel(f"{icon} {proto}: {count}")
                badge.setStyleSheet(f"""
                    font-size: 12px; font-weight: 600;
                    color: {color};
                    padding: 4px 10px;
                    background-color: {color}15;
                    border-radius: 4px;
                    border: 1px solid {color}30;
                """)
                self.proto_badges[proto] = badge
                self.proto_summary.addWidget(badge)

            # Add stretch at end
            spacer = QWidget()
            spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            self.proto_summary.addWidget(spacer)

            # Reset to first page and refresh
            self.current_page = 0
            self._update_pagination()
            self._refresh_table()

        def _apply_filter(self):
            """Apply current filter"""
            proto = self.proto_filter.currentText()
            if proto == "All Protocols":
                self.filtered_events = self.all_events
            else:
                filtered = []
                for e in self.all_events:
                    event_proto = getattr(e, 'protocol', '')
                    # Handle enum or string comparison
                    if hasattr(event_proto, 'value'):
                        event_proto_str = event_proto.value
                    elif hasattr(event_proto, 'name'):
                        event_proto_str = event_proto.name
                    else:
                        event_proto_str = str(event_proto)
                    if event_proto_str == proto:
                        filtered.append(e)
                self.filtered_events = filtered
            self.current_page = 0
            self._update_pagination()
            self._refresh_table()

        def _on_page_size_changed(self):
            """Handle rows per page change"""
            text = self.rows_per_page_combo.currentText()
            if text == "All":
                self.rows_per_page = len(self.filtered_events) or 1000
            else:
                self.rows_per_page = int(text)
            self.current_page = 0
            self._update_pagination()
            self._refresh_table()

        def _go_to_page(self, page: int):
            """Navigate to specific page"""
            if 0 <= page < self.total_pages:
                self.current_page = page
                self._update_pagination()
                self._refresh_table()

        def _on_page_input(self):
            """Handle manual page input"""
            try:
                page = int(self.page_input.text()) - 1  # Convert to 0-indexed
                self._go_to_page(page)
            except ValueError:
                self.page_input.setText(str(self.current_page + 1))

        def _update_pagination(self):
            """Update pagination controls"""
            total = len(self.filtered_events)
            self.total_pages = max(1, (total + self.rows_per_page - 1) // self.rows_per_page)

            # Update labels
            self.page_info_label.setText(f"Page {self.current_page + 1} of {self.total_pages}")
            self.page_input.setText(str(self.current_page + 1))
            self.total_label.setText(f"{total:,} records")

            # Enable/disable navigation buttons
            self.btn_first.setEnabled(self.current_page > 0)
            self.btn_prev.setEnabled(self.current_page > 0)
            self.btn_next.setEnabled(self.current_page < self.total_pages - 1)
            self.btn_last.setEnabled(self.current_page < self.total_pages - 1)

        def _refresh_table(self):
            """Refresh table with current page data"""
            start_idx = self.current_page * self.rows_per_page
            end_idx = min(start_idx + self.rows_per_page, len(self.filtered_events))
            display_list = self.filtered_events[start_idx:end_idx]

            self.table.setSortingEnabled(False)
            self.table.setUpdatesEnabled(False)
            try:
                self.table.setRowCount(len(display_list))

                risk_colors = {
                    "HIGH": QColor("#f85149"),
                    "MEDIUM": QColor("#d29922"),
                    "LOW": QColor("#3fb950"),
                }
                default_color = QColor("#8b949e")

                for i, e in enumerate(display_list):
                    self.table.setItem(i, 0, QTableWidgetItem(utc_str(getattr(e, 'timestamp', 0))))
                    self.table.setItem(i, 1, QTableWidgetItem(str(getattr(e, 'src_ip', '-'))))
                    self.table.setItem(i, 2, QTableWidgetItem(str(getattr(e, 'dst_ip', '-'))))

                    proto = getattr(e, 'protocol', '-')
                    if hasattr(proto, 'value'):
                        proto_str = proto.value
                    elif hasattr(proto, 'name'):
                        proto_str = proto.name
                    else:
                        proto_str = str(proto)
                    self.table.setItem(i, 3, QTableWidgetItem(proto_str))

                    func_code = getattr(e, 'function_code', '-')
                    self.table.setItem(i, 4, QTableWidgetItem(str(func_code) if func_code else '-'))

                    self.table.setItem(i, 5, QTableWidgetItem(str(getattr(e, 'operation', '-'))))

                    risk = getattr(e, 'risk_level', 'LOW')
                    if hasattr(risk, 'value'):
                        risk = risk.value
                    elif hasattr(risk, 'name'):
                        risk = risk.name
                    risk = str(risk)
                    risk_item = QTableWidgetItem(risk)
                    risk_item.setForeground(risk_colors.get(risk, default_color))
                    self.table.setItem(i, 6, risk_item)

                    mitre = getattr(e, 'mitre_techniques', []) or []
                    mitre_str = ", ".join(str(m) for m in mitre) if mitre else "-"
                    self.table.setItem(i, 7, QTableWidgetItem(mitre_str))
            finally:
                self.table.setUpdatesEnabled(True)
                self.table.setSortingEnabled(True)

        def _show_context_menu(self, position):
            """Show context menu for table row"""
            row = self.table.rowAt(position.y())
            if row < 0:
                return

            menu = QMenu(self)
            menu.setStyleSheet("""
                QMenu {
                    background-color: #3d444d;
                    border: 1px solid #3d444d;
                    border-radius: 6px;
                    padding: 4px;
                }
                QMenu::item {
                    padding: 6px 20px;
                    color: #e6edf3;
                }
                QMenu::item:selected {
                    background-color: #388bfd;
                    color: white;
                }
            """)

            # Copy actions
            copy_row_action = menu.addAction("📋 Copy Row")
            copy_src_action = menu.addAction("📋 Copy Source IP")
            copy_dst_action = menu.addAction("📋 Copy Destination IP")
            menu.addSeparator()
            copy_proto_action = menu.addAction("📋 Copy Protocol")
            copy_mitre_action = menu.addAction("📋 Copy MITRE Techniques")
            menu.addSeparator()
            details_action = menu.addAction("🔍 View Details")

            action = menu.exec_(self.table.viewport().mapToGlobal(position))

            if action == copy_row_action:
                self._copy_row_to_clipboard(row)
            elif action == copy_src_action:
                self._copy_cell_to_clipboard(row, 1)
            elif action == copy_dst_action:
                self._copy_cell_to_clipboard(row, 2)
            elif action == copy_proto_action:
                self._copy_cell_to_clipboard(row, 3)
            elif action == copy_mitre_action:
                self._copy_cell_to_clipboard(row, 7)
            elif action == details_action:
                self._show_event_details_for_row(row)

        def _copy_row_to_clipboard(self, row: int):
            """Copy entire row to clipboard as tab-separated values"""
            values = []
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                values.append(item.text() if item else "")
            clipboard = QApp.clipboard()
            clipboard.setText("\t".join(values))

        def _copy_cell_to_clipboard(self, row: int, col: int):
            """Copy single cell value to clipboard"""
            item = self.table.item(row, col)
            if item:
                clipboard = QApp.clipboard()
                clipboard.setText(item.text())

        def _show_event_details(self, index):
            """Show event details on double-click"""
            row = index.row()
            self._show_event_details_for_row(row)

        def _show_event_details_for_row(self, row: int):
            """Show detailed OT event information in a dialog"""
            # Calculate actual index in filtered list accounting for pagination
            actual_idx = self.current_page * self.rows_per_page + row
            if actual_idx < 0 or actual_idx >= len(self.filtered_events):
                return

            event = self.filtered_events[actual_idx]

            # Create detail dialog
            msg = QMessageBox(self)
            msg.setWindowTitle(f"OT Event Details - {self._get_proto_str(event)}")
            msg.setIcon(QMessageBox.Information)

            details = f"""
<b>Protocol:</b> {self._get_proto_str(event)}<br>
<b>Timestamp:</b> {getattr(event, 'timestamp', 'N/A')}<br>
<b>Source:</b> {getattr(event, 'src_ip', 'N/A')}:{getattr(event, 'src_port', 'N/A')}<br>
<b>Destination:</b> {getattr(event, 'dst_ip', 'N/A')}:{getattr(event, 'dst_port', 'N/A')}<br><br>
<b>Function Code:</b> {getattr(event, 'function_code', 'N/A')}<br>
<b>Operation:</b> {getattr(event, 'operation', 'N/A')}<br>
<b>Risk Level:</b> {getattr(event, 'risk_level', 'N/A')}<br><br>
<b>Registers/Address:</b> {getattr(event, 'start_address', 'N/A')} - {getattr(event, 'quantity', 'N/A')}<br>
<b>Payload Size:</b> {getattr(event, 'payload_size', 'N/A')} bytes<br><br>
<b>MITRE Techniques:</b> {', '.join(str(m) for m in getattr(event, 'mitre_techniques', []) or [])}
"""
            msg.setTextFormat(Qt.RichText)
            msg.setText(details)
            msg.setStyleSheet("""
                QMessageBox {
                    background-color: #252b33;
                }
                QMessageBox QLabel {
                    color: #e6edf3;
                    min-width: 400px;
                }
            """)
            msg.exec_()

        def _get_proto_str(self, event) -> str:
            """Helper to get protocol string from event"""
            proto = getattr(event, 'protocol', '-')
            if hasattr(proto, 'value'):
                return proto.value
            elif hasattr(proto, 'name'):
                return proto.name
            return str(proto)


    # =========================================================================
    # MITRE ATT&CK THREAT MODEL VIEW
    # =========================================================================

    class MITREMatrixView(QWidget):
        """
        MITRE ATT&CK matrix visualization for detected techniques.
        Shows both ICS and Enterprise techniques mapped to tactical phases.
        """

        # MITRE ATT&CK ICS Tactics (ordered by kill chain)
        ICS_TACTICS = [
            ("Initial Access", ["T0817", "T0819", "T0822", "T0847", "T0860",
                                "T0862", "T0864", "T0865", "T0866"]),
            ("Execution", ["T0807", "T0821", "T0823", "T0834", "T0853",
                           "T0863", "T0871"]),
            ("Persistence", ["T0839", "T0859", "T0873"]),
            ("Evasion", ["T0820", "T0849", "T0851", "T0856", "T0872"]),
            ("Discovery", ["T0808", "T0824", "T0825", "T0840", "T0841",
                           "T0842", "T0846", "T0850", "T0854", "T0861",
                           "T0868", "T0870"]),
            ("Lateral Movement", ["T0812", "T0867", "T0843", "T0844", "T0845",
                                  "T0830"]),
            ("Collection", ["T0801", "T0802", "T0811", "T0845", "T0852",
                            "T0869"]),
            ("Command & Control", ["T0869", "T0884"]),
            ("Inhibit Response", ["T0800", "T0803", "T0804", "T0805",
                                  "T0816", "T0835", "T0838", "T0857"]),
            ("Impair Process", ["T0806", "T0831", "T0832", "T0833",
                                "T0836", "T0855", "T0858"]),
            ("Impact", ["T0809", "T0813", "T0814", "T0815", "T0826",
                         "T0827", "T0828", "T0829", "T0837"]),
        ]

        # MITRE ATT&CK Enterprise Tactics (comprehensive for OT/ICS network analysis)
        ENTERPRISE_TACTICS = [
            ("Reconnaissance", ["T1595", "T1590"]),
            ("Initial Access", ["T1190", "T1133", "T1078", "T1199", "T1566", "T1189"]),
            ("Execution", ["T1059", "T1203", "T1047"]),
            ("Persistence", ["T1098", "T1136", "T1053", "T1505", "T1543", "T1547"]),
            ("Privilege Escalation", ["T1068", "T1548", "T1055"]),
            ("Defense Evasion", ["T1070", "T1036", "T1027", "T1140", "T1599"]),
            ("Credential Access", ["T1110", "T1003", "T1558", "T1552", "T1557"]),
            ("Discovery", ["T1046", "T1135", "T1018", "T1082", "T1016", "T1049", "T1083", "T1040"]),
            ("Lateral Movement", ["T1021", "T1080", "T1570", "T1550", "T1210"]),
            ("Collection", ["T1560", "T1005", "T1039", "T1213"]),
            ("C2", ["T1071", "T1095", "T1572", "T1090", "T1219", "T1105", "T1573", "T1132", "T1001", "T1102", "T1568"]),
            ("Exfiltration", ["T1041", "T1048", "T1567"]),
            ("Impact", ["T1485", "T1486", "T1489", "T1490", "T1498", "T1499"]),
        ]

        def __init__(self, theme_manager=None, parent=None):
            super().__init__(parent)
            self.theme_manager = theme_manager
            self.detected_techniques = {}  # tech_id -> count
            self.anomaly_techniques = {}   # tech_id -> list of anomaly info

            from .constants import MITRE_ATTACK_ICS, MITRE_ATTACK_ENTERPRISE
            self._ics_names = MITRE_ATTACK_ICS
            self._ent_names = MITRE_ATTACK_ENTERPRISE

            self._init_ui()

        def _init_ui(self):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(24, 20, 24, 20)
            layout.setSpacing(16)

            # Header
            header = QHBoxLayout()
            header_icon = QLabel("◉")
            header_icon.setStyleSheet("font-size: 24px; color: #ff6b6b;")
            header.addWidget(header_icon)

            title = QLabel("MITRE ATT&CK Threat Model")
            title.setStyleSheet("font-size: 22px; font-weight: 700; margin-left: 8px; color: #f0f6fc;")
            header.addWidget(title)

            self.status_badge = QLabel("◌ Awaiting Analysis")
            self.status_badge.setStyleSheet("""
                font-size: 12px; font-weight: 600;
                color: #e6edf3;
                padding: 4px 12px;
                background-color: #3d444d;
                border-radius: 12px;
                margin-left: 16px;
            """)
            header.addWidget(self.status_badge)
            header.addStretch()

            # Framework selector
            fw_label = QLabel("Framework:")
            fw_label.setStyleSheet("font-size: 13px; color: #e6edf3;")
            header.addWidget(fw_label)
            self.framework_combo = QComboBox()
            self.framework_combo.addItems(["ICS (OT)", "Enterprise (IT)", "Combined"])
            self.framework_combo.setFixedWidth(160)
            self.framework_combo.currentIndexChanged.connect(self._refresh_matrix)
            header.addWidget(self.framework_combo)

            layout.addLayout(header)

            # Summary stats row
            stats_row = QHBoxLayout()
            stats_row.setSpacing(16)

            self.stat_total = QLabel("◉ Techniques: 0")
            self.stat_total.setStyleSheet("font-size: 13px; font-weight: 600; color: #ff6b6b; padding: 4px 10px; background-color: #ff6b6b25; border-radius: 4px;")
            stats_row.addWidget(self.stat_total)

            self.stat_tactics = QLabel("◎ Tactics: 0")
            self.stat_tactics.setStyleSheet("font-size: 13px; font-weight: 600; color: #ffa94d; padding: 4px 10px; background-color: #ffa94d25; border-radius: 4px;")
            stats_row.addWidget(self.stat_tactics)

            self.stat_ics = QLabel("⚙ ICS: 0")
            self.stat_ics.setStyleSheet("font-size: 13px; font-weight: 600; color: #bc8cff; padding: 4px 10px; background-color: #bc8cff25; border-radius: 4px;")
            stats_row.addWidget(self.stat_ics)

            self.stat_ent = QLabel("◈ Enterprise: 0")
            self.stat_ent.setStyleSheet("font-size: 13px; font-weight: 600; color: #74c0fc; padding: 4px 10px; background-color: #74c0fc25; border-radius: 4px;")
            stats_row.addWidget(self.stat_ent)

            self.stat_hits = QLabel("▦ Total Hits: 0")
            self.stat_hits.setStyleSheet("font-size: 13px; font-weight: 600; color: #ffd43b; padding: 4px 10px; background-color: #ffd43b25; border-radius: 4px;")
            stats_row.addWidget(self.stat_hits)

            stats_row.addStretch()
            layout.addLayout(stats_row)

            # Scrollable matrix area
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.NoFrame)

            self.matrix_container = QWidget()
            self.matrix_layout = QVBoxLayout(self.matrix_container)
            self.matrix_layout.setSpacing(8)
            self.matrix_layout.setContentsMargins(0, 0, 0, 0)

            scroll.setWidget(self.matrix_container)
            layout.addWidget(scroll, 1)

            # Detail panel at bottom
            self.detail_text = QTextEdit()
            self.detail_text.setReadOnly(True)
            self.detail_text.setMaximumHeight(180)
            self.detail_text.setPlaceholderText("Click a technique cell to view details...")
            layout.addWidget(self.detail_text)

            self._show_empty_state()

        def _show_empty_state(self):
            """Show empty state message in matrix area."""
            self._clear_matrix()
            empty = QLabel(
                "<div style='text-align:center; color:#6e7681; padding: 60px;'>"
                "<div style='font-size: 36px; margin-bottom: 16px;'>◈</div>"
                "<div style='font-size: 15px; font-weight: 600;'>MITRE ATT&CK Matrix</div>"
                "<div style='font-size: 13px; margin-top: 8px; color: #484f58;'>"
                "Import a PCAP file to visualize detected attack techniques"
                "</div></div>"
            )
            empty.setAlignment(Qt.AlignCenter)
            self.matrix_layout.addWidget(empty)

        def _clear_matrix(self):
            """Remove all widgets from matrix layout."""
            while self.matrix_layout.count():
                item = self.matrix_layout.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()

        def update_from_analyzer(self, analyzer):
            """Update matrix with data from analyzer."""
            raw_techniques = dict(analyzer.mitre_techniques) if hasattr(analyzer, 'mitre_techniques') else {}

            # Build consolidated technique map:
            # - Keep exact matches (T1059, T0833)
            # - Roll up sub-techniques to parent (T1505.003 -> also count under T1505)
            self.detected_techniques = {}
            for tech_id, count in raw_techniques.items():
                self.detected_techniques[tech_id] = self.detected_techniques.get(tech_id, 0) + count
                # Also roll up to parent technique
                if '.' in tech_id:
                    parent = tech_id.split('.')[0]
                    self.detected_techniques[parent] = self.detected_techniques.get(parent, 0) + count

            # Also gather technique info from anomalies AND add to detected_techniques
            self.anomaly_techniques = {}
            for anomaly in getattr(analyzer, 'anomalies', []):
                for tech in getattr(anomaly, 'mitre_techniques', []):
                    if not tech:
                        continue

                    # Also add to detected_techniques if not already counted
                    # This ensures techniques from anomalies are shown in the matrix
                    if tech not in self.detected_techniques:
                        self.detected_techniques[tech] = 0
                    # Only increment if not already counted in raw_techniques
                    if tech not in raw_techniques:
                        self.detected_techniques[tech] += 1

                    # Also handle parent technique for sub-techniques
                    if '.' in tech:
                        parent = tech.split('.')[0]
                        if parent not in self.detected_techniques:
                            self.detected_techniques[parent] = 0
                        if parent not in raw_techniques:
                            self.detected_techniques[parent] += 1

                    info = {
                        'type': getattr(anomaly, 'anomaly_type', ''),
                        'severity': getattr(anomaly, 'severity', ''),
                        'src_ip': getattr(anomaly, 'src_ip', ''),
                        'dst_ip': getattr(anomaly, 'dst_ip', ''),
                        'description': getattr(anomaly, 'description', '')[:120],
                    }
                    # Store under exact ID
                    if tech not in self.anomaly_techniques:
                        self.anomaly_techniques[tech] = []
                    self.anomaly_techniques[tech].append(info)
                    # Also store under parent ID for sub-techniques
                    if '.' in tech:
                        parent = tech.split('.')[0]
                        if parent not in self.anomaly_techniques:
                            self.anomaly_techniques[parent] = []
                        self.anomaly_techniques[parent].append(info)

            # Update stats (count unique base techniques for display)
            unique_techniques = set()
            for t in self.detected_techniques:  # Use detected_techniques which now includes anomaly techniques
                if self.detected_techniques[t] > 0:  # Only count if actually detected
                    unique_techniques.add(t.split('.')[0])
            total_techniques = len(unique_techniques)
            total_hits = sum(self.detected_techniques.values())
            ics_count = sum(1 for t in unique_techniques if t.startswith("T0"))
            ent_count = sum(1 for t in unique_techniques if t.startswith("T1"))

            # Count tactics covered
            tactics_hit = set()
            for tactics_list in [self.ICS_TACTICS, self.ENTERPRISE_TACTICS]:
                for tactic_name, tech_ids in tactics_list:
                    for tid in tech_ids:
                        if tid in self.detected_techniques:
                            tactics_hit.add(tactic_name)
                            break

            self.stat_total.setText(f"◉ Techniques: {total_techniques}")
            self.stat_tactics.setText(f"◎ Tactics: {len(tactics_hit)}")
            self.stat_ics.setText(f"⚙ ICS: {ics_count}")
            self.stat_ent.setText(f"◈ Enterprise: {ent_count}")
            self.stat_hits.setText(f"▦ Total Hits: {total_hits}")

            if total_techniques > 0:
                self.status_badge.setText(f"◉ {total_techniques} techniques detected")
                self.status_badge.setStyleSheet("""
                    font-size: 12px; font-weight: 600;
                    color: #f85149;
                    padding: 4px 12px;
                    background-color: #f8514920;
                    border-radius: 12px;
                    margin-left: 16px;
                """)
            else:
                self.status_badge.setText("◌ No techniques detected")
                self.status_badge.setStyleSheet("""
                    font-size: 12px; font-weight: 600;
                    color: #3fb950;
                    padding: 4px 12px;
                    background-color: #3fb95020;
                    border-radius: 12px;
                    margin-left: 16px;
                """)

            # Auto-select best framework view based on what was detected
            if ics_count > 0 and ent_count > 0:
                self.framework_combo.setCurrentText("Combined")
            elif ent_count > 0:
                self.framework_combo.setCurrentText("Enterprise (IT)")
            elif ics_count > 0:
                self.framework_combo.setCurrentText("ICS (OT)")
            else:
                self.framework_combo.setCurrentText("Combined")

            self._refresh_matrix()

        def _refresh_matrix(self):
            """Rebuild matrix display based on selected framework."""
            self._clear_matrix()
            mode = self.framework_combo.currentText()

            # Collect all technique IDs that are mapped in tactic lists
            mapped_ids = set()

            if mode == "ICS (OT)":
                self._build_matrix_section("MITRE ATT&CK for ICS", self.ICS_TACTICS, self._ics_names, "#a371f7")
                for _, tids in self.ICS_TACTICS:
                    mapped_ids.update(tids)
            elif mode == "Enterprise (IT)":
                self._build_matrix_section("MITRE ATT&CK Enterprise", self.ENTERPRISE_TACTICS, self._ent_names, "#74c0fc")
                for _, tids in self.ENTERPRISE_TACTICS:
                    mapped_ids.update(tids)
            else:
                self._build_matrix_section("MITRE ATT&CK for ICS", self.ICS_TACTICS, self._ics_names, "#bc8cff")
                sep = QFrame()
                sep.setFrameShape(QFrame.HLine)
                sep.setStyleSheet("background-color: #3d444d; max-height: 1px; margin: 8px 0;")
                self.matrix_layout.addWidget(sep)
                self._build_matrix_section("MITRE ATT&CK Enterprise", self.ENTERPRISE_TACTICS, self._ent_names, "#74c0fc")
                for _, tids in self.ICS_TACTICS:
                    mapped_ids.update(tids)
                for _, tids in self.ENTERPRISE_TACTICS:
                    mapped_ids.update(tids)

            # Build "Other Detected" section for unmapped techniques
            unmapped = []
            for tech_id, count in self.detected_techniques.items():
                parent = tech_id.split('.')[0]
                if parent not in mapped_ids and count > 0 and '.' not in tech_id:
                    unmapped.append(tech_id)
            if unmapped:
                all_names = {**self._ics_names, **self._ent_names}
                other_tactics = [("Other Detected", sorted(unmapped))]
                sep2 = QFrame()
                sep2.setFrameShape(QFrame.HLine)
                sep2.setStyleSheet("background-color: #3d444d; max-height: 1px; margin: 8px 0;")
                self.matrix_layout.addWidget(sep2)
                self._build_matrix_section("Other Detected Techniques", other_tactics, all_names, "#ffd43b")

            self.matrix_layout.addStretch()

        def _build_matrix_section(self, section_title, tactics_data, name_lookup, accent_color):
            """Build one MITRE matrix section (ICS or Enterprise)."""
            # Section header
            header = QLabel(f"  {section_title}")
            header.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {accent_color}; padding: 6px 0;")
            self.matrix_layout.addWidget(header)

            for tactic_name, tech_ids in tactics_data:
                # Check if any technique in this tactic was detected
                detected_in_tactic = [t for t in tech_ids if t in self.detected_techniques]
                tactic_total = sum(self.detected_techniques.get(t, 0) for t in tech_ids)

                # Tactic row
                tactic_frame = QFrame()
                tactic_frame.setStyleSheet("""
                    QFrame {
                        background-color: #252b33;
                        border: 1px solid #3d444d;
                        border-radius: 6px;
                        padding: 4px;
                    }
                    QFrame QLabel {
                        color: #f0f6fc;
                    }
                """)
                tactic_layout = QVBoxLayout(tactic_frame)
                tactic_layout.setContentsMargins(10, 6, 10, 6)
                tactic_layout.setSpacing(4)

                # Tactic header
                tactic_header = QHBoxLayout()
                if detected_in_tactic:
                    tactic_icon = QLabel("◉")
                    tactic_icon.setStyleSheet(f"font-size: 14px; color: #69db7c;")
                else:
                    tactic_icon = QLabel("○")
                    tactic_icon.setStyleSheet("font-size: 14px; color: #8b949e;")
                tactic_header.addWidget(tactic_icon)

                tactic_label = QLabel(tactic_name)
                if detected_in_tactic:
                    tactic_label.setStyleSheet(f"font-size: 14px; font-weight: 700; color: #f0f6fc;")
                else:
                    tactic_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #e6edf3;")
                tactic_header.addWidget(tactic_label)

                if detected_in_tactic:
                    count_badge = QLabel(f"{len(detected_in_tactic)}/{len(tech_ids)} | {tactic_total} hits")
                    count_badge.setStyleSheet("font-size: 12px; color: #ffffff; font-weight: 600; padding: 3px 10px; background-color: #69db7c; border-radius: 4px;")
                    tactic_header.addWidget(count_badge)

                tactic_header.addStretch()
                tactic_layout.addLayout(tactic_header)

                # Technique cells (flow layout)
                if detected_in_tactic or True:  # Always show
                    tech_flow = QHBoxLayout()
                    tech_flow.setSpacing(4)

                    for tech_id in tech_ids:
                        count = self.detected_techniques.get(tech_id, 0)
                        tech_name = name_lookup.get(tech_id, tech_id)
                        # Also check sub-techniques (e.g. T1021.002 matches T1021)
                        sub_count = 0
                        for dt_id, dt_count in self.detected_techniques.items():
                            if dt_id.startswith(tech_id + "."):
                                sub_count += dt_count
                                count += dt_count

                        short_name = tech_name[:22] + ".." if len(tech_name) > 24 else tech_name
                        cell = QPushButton(f"{tech_id}\n{short_name}" + (f"\n[{count}]" if count > 0 else ""))
                        cell.setFixedSize(130, 56)
                        cell.setCursor(Qt.PointingHandCursor)

                        if count > 0:
                            # Determine color intensity by count
                            if count >= 10:
                                bg = "#f8514940"
                                border = "#f85149"
                                fg = "#f85149"
                            elif count >= 5:
                                bg = "#db6d2835"
                                border = "#db6d28"
                                fg = "#db6d28"
                            elif count >= 1:
                                bg = "#d2992230"
                                border = "#d29922"
                                fg = "#d29922"
                            else:
                                bg = "transparent"
                                border = "#3d444d"
                                fg = "#6e7681"
                            cell.setStyleSheet(f"""
                                QPushButton {{
                                    background-color: {bg};
                                    border: 1px solid {border};
                                    border-radius: 4px;
                                    color: {fg};
                                    font-size: 10px;
                                    font-weight: 600;
                                    text-align: center;
                                    padding: 2px;
                                }}
                                QPushButton:hover {{
                                    background-color: {border}50;
                                    border: 1px solid {fg};
                                }}
                            """)
                        else:
                            cell.setStyleSheet("""
                                QPushButton {
                                    background-color: #3d444d;
                                    border: 1px solid #3d444d;
                                    border-radius: 4px;
                                    color: #8b949e;
                                    font-size: 10px;
                                    text-align: center;
                                    padding: 2px;
                                }
                                QPushButton:hover {
                                    background-color: #3d444d;
                                    border: 1px solid #484f58;
                                    color: #e6edf3;
                                }
                            """)

                        # Connect click for detail
                        cell.clicked.connect(lambda checked, tid=tech_id, cnt=count: self._show_technique_detail(tid, cnt))
                        tech_flow.addWidget(cell)

                    tech_flow.addStretch()
                    tactic_layout.addLayout(tech_flow)

                self.matrix_layout.addWidget(tactic_frame)

        def _show_technique_detail(self, tech_id, count):
            """Show detail info for a clicked technique."""
            name = self._ics_names.get(tech_id, self._ent_names.get(tech_id, "Unknown"))

            # Get technique tooltip if available
            from .constants import MITRE_TOOLTIPS
            tooltip = MITRE_TOOLTIPS.get(tech_id, "")

            html = f"""
            <div style='padding: 10px;'>
                <div style='font-size: 16px; font-weight: 700; color: #f0f6fc;'>{tech_id}: {name}</div>
            """
            if tooltip:
                html += f"<div style='font-size: 12px; color: #e6edf3; margin-top: 4px;'>{tooltip}</div>"

            if count > 0:
                html += f"<div style='margin-top: 8px; font-size: 13px; color: #ffd43b;'>Detected {count} time(s) in this capture</div>"

                # Show anomaly details
                anomaly_list = self.anomaly_techniques.get(tech_id, [])
                if anomaly_list:
                    html += "<div style='margin-top: 8px;'>"
                    html += "<div style='font-size: 12px; font-weight: 600; color: #74c0fc;'>Related Anomalies:</div>"
                    html += "<table style='margin-top: 4px; font-size: 11px; color: #e6edf3; width: 100%;'>"
                    for info in anomaly_list[:10]:
                        sev = info.get('severity', '')
                        sev_color = {"CRITICAL": "#f85149", "HIGH": "#db6d28", "MEDIUM": "#d29922"}.get(sev, "#8b949e")
                        html += f"""<tr>
                            <td style='color:{sev_color}; font-weight:600; padding: 2px 6px;'>{sev}</td>
                            <td style='padding: 2px 6px;'>{info.get('type', '')}</td>
                            <td style='padding: 2px 6px;'>{info.get('src_ip', '')} -> {info.get('dst_ip', '')}</td>
                            <td style='padding: 2px 6px;'>{info.get('description', '')}</td>
                        </tr>"""
                    if len(anomaly_list) > 10:
                        html += f"<tr><td colspan='4' style='color:#6e7681; padding: 4px 6px;'>... and {len(anomaly_list) - 10} more</td></tr>"
                    html += "</table></div>"
            else:
                html += "<div style='margin-top: 8px; font-size: 12px; color: #3fb950;'>Not detected in this capture</div>"

            html += "</div>"
            self.detail_text.setHtml(html)
