"""
OT PCAP Analyzer - Threat Intelligence & Database GUI Panels
============================================================
UI widgets for integrating Threat Intelligence and the Database Backend.

Features:
- Threat Intel configuration panel
- Database history browser
- API key management
- IOC enrichment display
"""

import html as _html
import os
from typing import Dict, List, Optional

try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QLineEdit, QGroupBox, QTableWidget, QTableWidgetItem,
        QHeaderView, QComboBox, QTextEdit, QMessageBox, QTabWidget,
        QFormLayout, QCheckBox, QSpinBox, QFrame, QFileDialog,
        QProgressBar, QSplitter, QDialog, QDialogButtonBox, QAbstractItemView,
        QStackedWidget, QMenu
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings
    from PyQt5.QtGui import QFont, QColor
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False

from .utils import logger


# =============================================================================
# THREAT INTELLIGENCE PANEL
# =============================================================================

if HAS_PYQT5:

    class ThreatIntelPanel(QWidget):
        """
        Panel for configuring Threat Intelligence and viewing its results.
        """

        # Emitted when new enrichment results are available
        enrichment_completed = pyqtSignal(dict)

        def __init__(self, parent=None):
            super().__init__(parent)

            # Lazy import threat intel module
            self._threat_intel = None

            self._init_ui()

        @property
        def threat_intel(self):
            """Lazy load threat intelligence module."""
            if self._threat_intel is None:
                try:
                    from .threat_intel import ThreatIntelligence
                    self._threat_intel = ThreatIntelligence(enable_online=True)
                    self._threat_intel.load_api_keys_from_file()
                    self._threat_intel.load_api_keys_from_env()
                except Exception as e:
                    logger.warning(f"Threat Intel not available: {e}")
            return self._threat_intel

        def _init_ui(self):
            """Initialize UI components."""
            layout = QVBoxLayout(self)
            layout.setSpacing(16)

            # Header
            header = QLabel("🛡️ Threat Intelligence Integration")
            header.setStyleSheet("font-size: 20px; font-weight: bold; color: #58a6ff;")
            layout.addWidget(header)

            # Status frame
            status_frame = self._create_status_frame()
            layout.addWidget(status_frame)

            # API Keys configuration
            api_group = self._create_api_config_group()
            layout.addWidget(api_group)

            # Manual lookup section
            lookup_group = self._create_lookup_group()
            layout.addWidget(lookup_group)

            # Results table
            results_group = self._create_results_group()
            layout.addWidget(results_group)

            # Statistics
            stats_group = self._create_stats_group()
            layout.addWidget(stats_group)

            layout.addStretch()

        def _create_status_frame(self) -> QFrame:
            """Create status display frame."""
            frame = QFrame()
            frame.setFrameShape(QFrame.StyledPanel)
            frame.setStyleSheet("background: #252b33; border: 1px solid #3d444d; border-radius: 8px; padding: 16px;")

            layout = QHBoxLayout(frame)

            self.status_label = QLabel("⏳ Checking Threat Intelligence status...")
            self.status_label.setStyleSheet("color: #f0f6fc; font-size: 14px;")
            layout.addWidget(self.status_label)

            refresh_btn = QPushButton("🔄 Refresh")
            refresh_btn.clicked.connect(self._refresh_status)
            refresh_btn.setMaximumWidth(100)
            layout.addWidget(refresh_btn)

            # Check status on load
            self._refresh_status()

            return frame

        def _refresh_status(self):
            """Refresh threat intel status."""
            if self.threat_intel is None:
                self.status_label.setText("❌ Threat Intelligence module not available")
                self.status_label.setStyleSheet("color: #ff6b6b; font-size: 14px;")
                return

            apis = self.threat_intel.api_keys.keys()
            if apis:
                api_list = ', '.join(apis)
                self.status_label.setText(f"✅ Configured: {api_list}")
                self.status_label.setStyleSheet("color: #3fb950; font-size: 14px;")
            else:
                self.status_label.setText("⚠️ No API key configured - using local feeds only")
                self.status_label.setStyleSheet("color: #ffd43b; font-size: 14px;")

        def _create_api_config_group(self) -> QGroupBox:
            """Create API configuration group."""
            group = QGroupBox("🔑 API Keys Configuration")
            layout = QFormLayout(group)

            # VirusTotal
            self.vt_key_input = QLineEdit()
            self.vt_key_input.setPlaceholderText("Enter VirusTotal API key...")
            self.vt_key_input.setEchoMode(QLineEdit.Password)
            layout.addRow("VirusTotal:", self.vt_key_input)

            # AbuseIPDB
            self.abuse_key_input = QLineEdit()
            self.abuse_key_input.setPlaceholderText("Enter AbuseIPDB API key...")
            self.abuse_key_input.setEchoMode(QLineEdit.Password)
            layout.addRow("AbuseIPDB:", self.abuse_key_input)

            # Save button
            btn_layout = QHBoxLayout()

            save_btn = QPushButton("💾 Save API Keys")
            save_btn.clicked.connect(self._save_api_keys)
            btn_layout.addWidget(save_btn)

            test_btn = QPushButton("🧪 Test Connection")
            test_btn.clicked.connect(self._test_connection)
            btn_layout.addWidget(test_btn)

            btn_layout.addStretch()
            layout.addRow("", btn_layout)

            return group

        def _save_api_keys(self):
            """Save API keys to config file."""
            try:
                import json
                from pathlib import Path

                config_dir = Path.home() / ".ot_pcap_analyzer"
                config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                config_file = config_dir / "api_keys.json"

                keys = {}
                if self.vt_key_input.text().strip():
                    keys['virustotal'] = self.vt_key_input.text().strip()
                if self.abuse_key_input.text().strip():
                    keys['abuseipdb'] = self.abuse_key_input.text().strip()

                # Owner-only permissions: API keys must not be readable by other local users
                fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as f:
                    json.dump(keys, f)
                try:
                    os.chmod(config_file, 0o600)   # also tighten a pre-existing file
                except OSError:
                    pass

                # Reload into threat intel
                if self.threat_intel:
                    self.threat_intel.load_api_keys_from_file()
                    self._refresh_status()

                QMessageBox.information(self, "Success", "API keys saved successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save API keys: {e}")

        def _test_connection(self):
            """Test API connection."""
            if not self.threat_intel:
                QMessageBox.warning(self, "Warning", "Threat Intelligence not available")
                return

            # Test with a known safe IP (Google DNS)
            try:
                result = self.threat_intel.check_ip("8.8.8.8", use_cache=False)
                sources = result.get('sources', [])

                if 'virustotal' in str(self.threat_intel.api_keys) and 'virustotal' not in result.get('details', {}):
                    QMessageBox.warning(self, "Test Result",
                        "VirusTotal key configured but no response.\nCheck if key is valid.")
                else:
                    QMessageBox.information(self, "Test Result",
                        f"Connection successful!\n\n"
                        f"Tested IP: 8.8.8.8\n"
                        f"Sources checked: {sources or 'local_feed'}\n"
                        f"Is malicious: {result.get('is_malicious', False)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Connection test failed: {e}")

        def _create_lookup_group(self) -> QGroupBox:
            """Create manual lookup group."""
            group = QGroupBox("🔍 Manual IOC Lookup")
            layout = QVBoxLayout(group)

            # Input row
            input_layout = QHBoxLayout()

            self.lookup_type = QComboBox()
            self.lookup_type.addItems(["IP Address", "File Hash", "Domain"])
            self.lookup_type.setMaximumWidth(120)
            input_layout.addWidget(self.lookup_type)

            self.lookup_input = QLineEdit()
            self.lookup_input.setPlaceholderText("Enter IP, hash, or domain...")
            self.lookup_input.returnPressed.connect(self._perform_lookup)
            input_layout.addWidget(self.lookup_input)

            lookup_btn = QPushButton("🔎 Lookup")
            lookup_btn.clicked.connect(self._perform_lookup)
            lookup_btn.setMaximumWidth(100)
            input_layout.addWidget(lookup_btn)

            layout.addLayout(input_layout)

            # Result display
            self.lookup_result = QTextEdit()
            self.lookup_result.setReadOnly(True)
            self.lookup_result.setMaximumHeight(150)
            self.lookup_result.setPlaceholderText("Lookup results will appear here...")
            layout.addWidget(self.lookup_result)

            return group

        def _perform_lookup(self):
            """Perform IOC lookup."""
            if not self.threat_intel:
                self.lookup_result.setText("❌ Threat Intelligence not available")
                return

            value = self.lookup_input.text().strip()
            if not value:
                return

            lookup_type = self.lookup_type.currentText()

            try:
                if lookup_type == "IP Address":
                    result = self.threat_intel.check_ip(value)
                elif lookup_type == "File Hash":
                    result = self.threat_intel.check_hash(value)
                else:  # Domain
                    result = self.threat_intel.check_domain(value)

                self._display_lookup_result(result)

            except Exception as e:
                self.lookup_result.setText(f"❌ Lookup failed: {e}")

        def _display_lookup_result(self, result: Dict):
            """Display lookup result in text area."""
            is_malicious = result.get('is_malicious', False)
            confidence = result.get('confidence', 0)
            severity = result.get('severity', 'Unknown')
            sources = result.get('sources', [])

            # Format result
            if is_malicious:
                status = f"🔴 MALICIOUS (Confidence: {confidence:.0%})"
                color = "#ef4444"
            else:
                status = "✅ CLEAN / Unknown"
                color = "#10b981"

            html = f"""
<div style='font-family: monospace;'>
<h3 style='color: {color};'>{status}</h3>
<p><b>Severity:</b> {_html.escape(str(severity))}</p>
<p><b>Sources:</b> {_html.escape(', '.join(map(str, sources))) if sources else 'Local feed only'}</p>
<p><b>Checked at:</b> {_html.escape(str(result.get('checked_at', 'N/A')))}</p>
<hr/>
<details>
<summary>Raw Details</summary>
<pre>{_html.escape(self._format_details(result.get('details', {})))}</pre>
</details>
</div>
            """

            self.lookup_result.setHtml(html)

        def _format_details(self, details: Dict) -> str:
            """Format details dict for display."""
            import json
            return json.dumps(details, indent=2, default=str)

        def _create_results_group(self) -> QGroupBox:
            """Create enrichment results table."""
            group = QGroupBox("📊 Enrichment Results")
            layout = QVBoxLayout(group)

            self.results_table = QTableWidget()
            self.results_table.setColumnCount(6)
            self.results_table.setHorizontalHeaderLabels([
                "IOC Type", "Value", "Malicious", "Confidence", "Severity", "Sources"
            ])
            self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)  # Value stretches
            self.results_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)  # Sources stretches
            self.results_table.setAlternatingRowColors(True)
            layout.addWidget(self.results_table)

            return group

        def add_enrichment_result(self, ioc_type: str, value: str, result: Dict):
            """Add enrichment result to table."""
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)

            is_malicious = result.get('is_malicious', False)

            self.results_table.setItem(row, 0, QTableWidgetItem(ioc_type))
            self.results_table.setItem(row, 1, QTableWidgetItem(value))

            malicious_item = QTableWidgetItem("YES" if is_malicious else "NO")
            malicious_item.setForeground(Qt.red if is_malicious else Qt.green)
            self.results_table.setItem(row, 2, malicious_item)

            self.results_table.setItem(row, 3, QTableWidgetItem(f"{result.get('confidence', 0):.0%}"))
            self.results_table.setItem(row, 4, QTableWidgetItem(result.get('severity', 'N/A')))
            self.results_table.setItem(row, 5, QTableWidgetItem(', '.join(result.get('sources', []))))

        def _create_stats_group(self) -> QGroupBox:
            """Create statistics group."""
            group = QGroupBox("📈 Statistics")
            layout = QHBoxLayout(group)

            self.stats_labels = {}
            for stat_name in ['Total Lookups', 'Cache Hits', 'Malicious Found', 'API Calls']:
                frame = QFrame()
                frame.setFrameShape(QFrame.StyledPanel)
                frame_layout = QVBoxLayout(frame)

                value_label = QLabel("0")
                value_label.setStyleSheet("font-size: 28px; font-weight: bold; color: #58a6ff;")
                value_label.setAlignment(Qt.AlignCenter)
                frame_layout.addWidget(value_label)

                name_label = QLabel(stat_name)
                name_label.setAlignment(Qt.AlignCenter)
                name_label.setStyleSheet("color: #c9d1d9; font-size: 14px;")
                frame_layout.addWidget(name_label)

                self.stats_labels[stat_name] = value_label
                layout.addWidget(frame)

            return group

        def update_stats(self):
            """Update statistics display."""
            if not self.threat_intel:
                return

            stats = self.threat_intel.get_stats()
            self.stats_labels['Total Lookups'].setText(str(stats.get('total_lookups', 0)))
            self.stats_labels['Cache Hits'].setText(str(stats.get('cache_hits', 0)))
            self.stats_labels['Malicious Found'].setText(str(stats.get('malicious_found', 0)))
            self.stats_labels['API Calls'].setText(str(stats.get('api_calls', 0)))

        def enrich_anomalies(self, anomalies: List) -> List[Dict]:
            """
            Enrich list of anomalies with threat intelligence.

            Args:
                anomalies: List of SecurityAnomaly objects

            Returns:
                List of enrichment results
            """
            if not self.threat_intel:
                return []

            results = []
            checked_ips = set()

            for anomaly in anomalies:
                # Check source IP
                src_ip = getattr(anomaly, 'src_ip', None)
                if src_ip and src_ip not in checked_ips:
                    checked_ips.add(src_ip)
                    result = self.threat_intel.check_ip(src_ip)
                    if result.get('is_malicious'):
                        results.append(result)
                        self.add_enrichment_result('IP', src_ip, result)

                # Check destination IP
                dst_ip = getattr(anomaly, 'dst_ip', None)
                if dst_ip and dst_ip not in checked_ips and dst_ip not in ['Multiple', 'Network']:
                    checked_ips.add(dst_ip)
                    result = self.threat_intel.check_ip(dst_ip)
                    if result.get('is_malicious'):
                        results.append(result)
                        self.add_enrichment_result('IP', dst_ip, result)

            self.update_stats()
            return results


    # =========================================================================
    # DATABASE HISTORY PANEL
    # =========================================================================

    class HistorySettingsDialog(QDialog):
        """Privacy settings for the local scan history."""

        def __init__(self, enabled: bool, retention_days: int, db_path: str, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Scan history settings")
            self.setMinimumWidth(460)
            lay = QVBoxLayout(self)
            lay.setSpacing(14)
            lay.setContentsMargins(20, 18, 20, 16)

            title = QLabel("Scan history")
            title.setObjectName("ValueMedium")
            lay.addWidget(title)
            info = QLabel(
                "Results are stored only on this computer. They can contain internal IP "
                "addresses and plant details, so keep them only as long as you need them.")
            info.setWordWrap(True)
            info.setObjectName("Muted")
            lay.addWidget(info)

            self.enabled_box = QCheckBox("Save every analysis to history")
            self.enabled_box.setChecked(enabled)
            lay.addWidget(self.enabled_box)

            row = QHBoxLayout()
            row.addWidget(QLabel("Automatically delete scans older than"))
            self.retention_spin = QSpinBox()
            self.retention_spin.setRange(0, 3650)
            self.retention_spin.setSuffix(" days")
            self.retention_spin.setSpecialValueText("never")
            self.retention_spin.setValue(max(0, int(retention_days)))
            row.addWidget(self.retention_spin)
            row.addStretch()
            lay.addLayout(row)

            where = QLabel(f"Database: {db_path}")
            where.setObjectName("Muted")
            where.setWordWrap(True)
            where.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lay.addWidget(where)

            buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
            buttons.button(QDialogButtonBox.Save).setObjectName("BtnPrimary")
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            lay.addWidget(buttons)

        def values(self):
            return self.enabled_box.isChecked(), self.retention_spin.value()

    class DatabaseHistoryPanel(QWidget):
        """
        Scan history: every analysis saved locally, with details, comparison,
        re-analysis, export and deletion (single, selected, all, or by age).
        """

        session_selected = pyqtSignal(str)
        reanalyze_requested = pyqtSignal(str)       # capture path
        history_changed = pyqtSignal()              # emitted from the saving thread

        SETTINGS_ORG, SETTINGS_APP = "OTAnalyzer", "SOCGUI"
        PERIODS = [("All time", None), ("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90)]

        def __init__(self, parent=None, database=None, settings=None):
            super().__init__(parent)
            self._database = database
            self._sessions: List[Dict] = []
            self.settings = settings if settings is not None else QSettings(self.SETTINGS_ORG, self.SETTINGS_APP)
            self.history_changed.connect(self._load_sessions)
            self._init_ui()
            self._apply_retention()
            self._load_sessions()

        # ---------------------------------------------------------- settings
        @property
        def history_enabled(self) -> bool:
            return str(self.settings.value("history/enabled", "true")).lower() in ("true", "1")

        @property
        def retention_days(self) -> int:
            try:
                return int(self.settings.value("history/retention_days", 0))
            except (TypeError, ValueError):
                return 0

        @property
        def database(self):
            if self._database is None:
                try:
                    from .database import AnalysisDatabase
                    self._database = AnalysisDatabase()
                except Exception as e:
                    logger.warning(f"Database not available: {e}")
            return self._database

        # ---------------------------------------------------------------- UI
        def _init_ui(self):
            from .gui_components import BarList, Card, KpiCard
            root = QVBoxLayout(self)
            root.setContentsMargins(28, 22, 28, 20)
            root.setSpacing(14)

            head = QHBoxLayout()
            titles = QVBoxLayout()
            titles.setSpacing(2)
            title = QLabel("Scan history")
            title.setObjectName("PageTitle")
            titles.addWidget(title)
            self.storage_label = QLabel("")
            self.storage_label.setObjectName("PageSubtitle")
            titles.addWidget(self.storage_label)
            head.addLayout(titles, 1)
            self.import_btn = QPushButton("Import…")
            self.import_btn.setToolTip("Import a scan exported as JSON")
            self.import_btn.clicked.connect(self._import_session)
            head.addWidget(self.import_btn, 0, Qt.AlignTop)
            self.settings_btn = QPushButton("Settings…")
            self.settings_btn.setToolTip("Turn history on/off and set automatic clean-up")
            self.settings_btn.clicked.connect(self._open_settings)
            head.addWidget(self.settings_btn, 0, Qt.AlignTop)
            self.clear_btn = QPushButton("Delete all history")
            self.clear_btn.setObjectName("BtnDanger")
            self.clear_btn.clicked.connect(self._delete_all)
            head.addWidget(self.clear_btn, 0, Qt.AlignTop)
            root.addLayout(head)

            self.disabled_banner = QLabel(
                "History is turned off — new analyses are not saved. Change this in Settings.")
            self.disabled_banner.setObjectName("RiskMedium")
            self.disabled_banner.setVisible(False)
            root.addWidget(self.disabled_banner)

            tools = QHBoxLayout()
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("Search by capture file name…")
            self.search_input.setClearButtonEnabled(True)
            self.search_input.setMaximumWidth(320)
            self.search_input.textChanged.connect(self._load_sessions)
            tools.addWidget(self.search_input)
            self.period_combo = QComboBox()
            for label, _ in self.PERIODS:
                self.period_combo.addItem(label)
            self.period_combo.currentIndexChanged.connect(self._load_sessions)
            tools.addWidget(self.period_combo)
            tools.addStretch()
            self.count_label = QLabel("")
            self.count_label.setObjectName("Muted")
            tools.addWidget(self.count_label)
            root.addLayout(tools)

            splitter = QSplitter(Qt.Horizontal)
            splitter.setChildrenCollapsible(False)
            splitter.setHandleWidth(16)
            splitter.setStyleSheet("QSplitter::handle { background: transparent; }")

            # sessions list
            self.sessions_table = QTableWidget()
            self.sessions_table.setColumnCount(5)
            self.sessions_table.setHorizontalHeaderLabels(["Capture", "Scanned", "Packets", "Alerts", "Critical"])
            hdr = self.sessions_table.horizontalHeader()
            hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
            hdr.setSectionResizeMode(0, QHeaderView.Stretch)
            hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            hdr.setMinimumSectionSize(64)
            self.sessions_table.verticalHeader().setVisible(False)
            self.sessions_table.setShowGrid(False)
            self.sessions_table.setAlternatingRowColors(True)
            self.sessions_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.sessions_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
            self.sessions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.sessions_table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.sessions_table.customContextMenuRequested.connect(self._session_menu)
            self.sessions_table.itemSelectionChanged.connect(self._on_selection_changed)
            self.sessions_table.setMinimumWidth(500)
            splitter.addWidget(self.sessions_table)

            # detail area: empty / one scan / comparison / many
            self.detail_stack = QStackedWidget()
            self.empty_label = QLabel(
                "No scans yet.\nOpen a PCAP file — each analysis is saved here automatically.")
            self.empty_label.setAlignment(Qt.AlignCenter)
            self.empty_label.setObjectName("Muted")
            self.detail_stack.addWidget(self.empty_label)                 # 0

            detail = QWidget()
            dl = QVBoxLayout(detail)
            dl.setContentsMargins(0, 0, 0, 0)
            dl.setSpacing(12)
            top = QHBoxLayout()
            names = QVBoxLayout()
            names.setSpacing(2)
            self.detail_title = QLabel("")
            self.detail_title.setObjectName("ValueMedium")
            self.detail_title.setTextFormat(Qt.PlainText)
            names.addWidget(self.detail_title)
            self.detail_sub = QLabel("")
            self.detail_sub.setObjectName("Muted")
            self.detail_sub.setTextFormat(Qt.PlainText)
            self.detail_sub.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.detail_sub.setWordWrap(True)
            names.addWidget(self.detail_sub)
            top.addLayout(names, 1)
            self.reanalyze_btn = QPushButton("Analyze again")
            self.reanalyze_btn.setObjectName("BtnPrimary")
            self.reanalyze_btn.clicked.connect(self._reanalyze)
            top.addWidget(self.reanalyze_btn, 0, Qt.AlignTop)
            self.export_btn = QPushButton("Export…")
            self.export_btn.clicked.connect(self._export_session)
            top.addWidget(self.export_btn, 0, Qt.AlignTop)
            self.delete_btn = QPushButton("Delete")
            self.delete_btn.setObjectName("BtnDanger")
            self.delete_btn.clicked.connect(self._delete_selected)
            top.addWidget(self.delete_btn, 0, Qt.AlignTop)
            dl.addLayout(top)

            kpis = QHBoxLayout()
            kpis.setSpacing(10)
            self.kpi_packets = KpiCard("Packets", "accent")
            self.kpi_alerts = KpiCard("Alerts", "medium")
            self.kpi_critical = KpiCard("Critical", "critical")
            self.kpi_iocs = KpiCard("IOCs", "purple")
            for k in (self.kpi_packets, self.kpi_alerts, self.kpi_critical, self.kpi_iocs):
                k.setMinimumHeight(96)
                kpis.addWidget(k)
            dl.addLayout(kpis)

            charts = QHBoxLayout()
            charts.setSpacing(10)
            sev_card = Card("Alerts by severity")
            self.sev_bars = BarList("No alerts", max_rows=4)
            sev_card.body.addWidget(self.sev_bars)
            charts.addWidget(sev_card, 1)
            type_card = Card("Most frequent alerts")
            self.type_bars = BarList("No alerts", max_rows=6)
            type_card.body.addWidget(self.type_bars)
            charts.addWidget(type_card, 1)
            dl.addLayout(charts)

            tabs = QTabWidget()
            self.anomalies_table = QTableWidget()
            self.anomalies_table.setColumnCount(6)
            self.anomalies_table.setHorizontalHeaderLabels(
                ["Severity", "Alert", "Source", "Destination", "Description", "Time (UTC)"])
            ah = self.anomalies_table.horizontalHeader()
            ah.setSectionResizeMode(QHeaderView.ResizeToContents)
            ah.setSectionResizeMode(4, QHeaderView.Stretch)
            self.iocs_table = QTableWidget()
            self.iocs_table.setColumnCount(5)
            self.iocs_table.setHorizontalHeaderLabels(["Type", "Value", "Severity", "Attack type", "Count"])
            ih = self.iocs_table.horizontalHeader()
            ih.setSectionResizeMode(QHeaderView.ResizeToContents)
            ih.setSectionResizeMode(1, QHeaderView.Stretch)
            for t in (self.anomalies_table, self.iocs_table):
                t.verticalHeader().setVisible(False)
                t.setShowGrid(False)
                t.setAlternatingRowColors(True)
                t.setEditTriggers(QAbstractItemView.NoEditTriggers)
                t.setSelectionBehavior(QAbstractItemView.SelectRows)
            tabs.addTab(self.anomalies_table, "Alerts")
            tabs.addTab(self.iocs_table, "IOCs")
            self.detail_tabs = tabs
            dl.addWidget(tabs, 1)
            self.detail_stack.addWidget(detail)                            # 1

            compare = QWidget()
            cl = QVBoxLayout(compare)
            cl.setContentsMargins(0, 0, 0, 0)
            ch = QHBoxLayout()
            self.compare_title = QLabel("Compare scans")
            self.compare_title.setObjectName("ValueMedium")
            ch.addWidget(self.compare_title, 1)
            self.compare_delete_btn = QPushButton("Delete selected")
            self.compare_delete_btn.setObjectName("BtnDanger")
            self.compare_delete_btn.clicked.connect(self._delete_selected)
            ch.addWidget(self.compare_delete_btn)
            cl.addLayout(ch)
            self.compare_text = QTextEdit()
            self.compare_text.setReadOnly(True)
            cl.addWidget(self.compare_text, 1)
            self.detail_stack.addWidget(compare)                           # 2

            many = QWidget()
            ml = QVBoxLayout(many)
            ml.addStretch()
            self.many_label = QLabel("")
            self.many_label.setAlignment(Qt.AlignCenter)
            self.many_label.setObjectName("ValueMedium")
            ml.addWidget(self.many_label)
            mb = QHBoxLayout()
            mb.addStretch()
            many_delete = QPushButton("Delete selected scans")
            many_delete.setObjectName("BtnDanger")
            many_delete.clicked.connect(self._delete_selected)
            mb.addWidget(many_delete)
            mb.addStretch()
            ml.addLayout(mb)
            ml.addStretch()
            self.detail_stack.addWidget(many)                              # 3

            splitter.addWidget(self.detail_stack)
            splitter.setStretchFactor(0, 1)
            splitter.setStretchFactor(1, 1)
            splitter.setSizes([640, 620])
            root.addWidget(splitter, 1)

            # kept for compatibility with older callers
            self.trends_text = self.compare_text
            self.db_stats_labels = {}

        def showEvent(self, event):
            super().showEvent(event)
            self._load_sessions()

        # ------------------------------------------------------------- data
        def _selected_ids(self) -> List[str]:
            rows = sorted({i.row() for i in self.sessions_table.selectedIndexes()})
            ids = []
            for r in rows:
                item = self.sessions_table.item(r, 0)
                if item is not None:
                    ids.append(item.data(Qt.UserRole))
            return [i for i in ids if i]

        def _session_by_id(self, session_id: str) -> Optional[Dict]:
            return next((s for s in self._sessions if s.get("id") == session_id), None)

        @staticmethod
        def _local_time(value) -> str:
            from datetime import datetime, timezone
            if not value:
                return "–"
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value)
                except ValueError:
                    return value
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)   # SQLite CURRENT_TIMESTAMP is UTC
            return value.astimezone().strftime("%Y-%m-%d %H:%M")

        @staticmethod
        def _human_size(n: int) -> str:
            for unit in ("B", "KB", "MB", "GB"):
                if n < 1024 or unit == "GB":
                    return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
                n /= 1024
            return f"{n:.1f} GB"

        def _load_sessions(self, *_):
            if not self.database:
                self.storage_label.setText("History database is not available.")
                return
            keep = set(self._selected_ids())
            search = self.search_input.text().strip()
            days = self.PERIODS[self.period_combo.currentIndex()][1]
            try:
                self._sessions = self.database.list_sessions(search=search, since_days=days)
                info = self.database.storage_info()
            except Exception as e:
                logger.warning(f"Failed to load sessions: {e}")
                return

            self.disabled_banner.setVisible(not self.history_enabled)
            retention = (f"auto-delete after {self.retention_days} days"
                         if self.retention_days else "kept until you delete them")
            self.storage_label.setText(
                f"{info['sessions']} scan{'s' if info['sessions'] != 1 else ''} · "
                f"{self._human_size(info['size_bytes'])} · stored only on this computer · {retention}")
            self.clear_btn.setEnabled(info['sessions'] > 0)
            self.count_label.setText(f"{len(self._sessions)} shown")

            table = self.sessions_table
            table.blockSignals(True)
            table.setRowCount(len(self._sessions))
            from .gui_components import severity_item  # noqa: F401  (theme-aware colours)
            for row, s in enumerate(self._sessions):
                meta = s.get("metadata") or {}
                name = QTableWidgetItem(s.get("pcap_file") or "–")
                name.setData(Qt.UserRole, s.get("id"))
                name.setToolTip(meta.get("capture_path") or s.get("pcap_file") or "")
                table.setItem(row, 0, name)
                table.setItem(row, 1, QTableWidgetItem(self._local_time(s.get("started_at"))))
                for col, value in ((2, s.get("total_packets") or 0), (3, s.get("total_anomalies") or 0),
                                   (4, (meta.get("severity") or {}).get("CRITICAL", 0))):
                    item = QTableWidgetItem(f"{int(value):,}")
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                    if col == 4 and value:
                        item.setForeground(QColor("#f85149"))
                    table.setItem(row, col, item)
                if s.get("id") in keep:
                    table.selectRow(row)
            table.blockSignals(False)
            self._on_selection_changed()

        def _on_selection_changed(self):
            ids = self._selected_ids()
            if not self._sessions:
                self.empty_label.setText(
                    "No scans yet.\nOpen a PCAP file — each analysis is saved here automatically."
                    if not self.search_input.text() and self.period_combo.currentIndex() == 0
                    else "No scans match the current filter.")
                self.detail_stack.setCurrentIndex(0)
            elif not ids:
                self.empty_label.setText("Select a scan to see its details.\n"
                                         "Select two scans to compare them.")
                self.detail_stack.setCurrentIndex(0)
            elif len(ids) == 1:
                self._load_session_details(ids[0])
                self.detail_stack.setCurrentIndex(1)
                self.session_selected.emit(ids[0])
            elif len(ids) == 2:
                self._show_comparison(ids)
                self.detail_stack.setCurrentIndex(2)
            else:
                self.many_label.setText(f"{len(ids)} scans selected")
                self.detail_stack.setCurrentIndex(3)

        def _on_session_selected(self, row: int, col: int = 0):
            """Select a row programmatically (kept for compatibility)."""
            self.sessions_table.selectRow(row)

        def _load_session_details(self, session_id: str):
            import os
            from .gui_components import pretty_type, severity_item, short_time
            if not self.database:
                return
            try:
                s = self.database.session_overview(session_id)
                anomalies = self.database.get_anomalies(session_id=session_id, limit=1000)
                iocs = self.database.get_iocs(session_id=session_id, limit=1000)
            except Exception as e:
                logger.warning(f"Failed to load session details: {e}")
                return
            if not s:
                return
            meta = s.get("metadata") or {}
            path = meta.get("capture_path") or ""
            self.detail_title.setText(s.get("pcap_file") or "–")
            bits = [f"Scanned {self._local_time(s.get('started_at'))}"]
            if meta.get("duration"):
                bits.append(f"capture {meta['duration']}")
            self.detail_sub.setText("  ·  ".join(bits))
            self.detail_sub.setToolTip(f"SHA-256: {s['pcap_hash']}" if s.get("pcap_hash") else "")
            self._current_path = path
            exists = bool(path) and os.path.isfile(path)
            self.reanalyze_btn.setEnabled(exists)
            self.reanalyze_btn.setToolTip(path if exists else "The original capture file is not available any more")

            sev = s.get("severity") or {}
            self.kpi_packets.set_value(f"{s.get('total_packets') or 0:,}", meta.get("file_size", ""))
            self.kpi_alerts.set_value(f"{s.get('total_anomalies') or 0:,}",
                                      f"{len(meta.get('top_techniques') or {})} ATT&CK techniques")
            self.kpi_critical.set_value(f"{sev.get('CRITICAL', 0):,}", f"{sev.get('HIGH', 0)} high")
            self.kpi_iocs.set_value(f"{s.get('ioc_count', 0):,}", "indicators")
            self.sev_bars.set_rows([("Critical", sev.get("CRITICAL", 0), "critical"),
                                    ("High", sev.get("HIGH", 0), "high"),
                                    ("Medium", sev.get("MEDIUM", 0), "medium"),
                                    ("Low", sev.get("LOW", 0), "low")])
            self.type_bars.set_rows((pretty_type(t), n, "accent") for t, n in s.get("top_types") or [])

            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            anomalies.sort(key=lambda a: (order.get(a.get("severity"), 9), str(a.get("timestamp"))))
            self.anomalies_table.setRowCount(len(anomalies))
            for r, a in enumerate(anomalies):
                self.anomalies_table.setItem(r, 0, severity_item(a.get("severity", "")))
                self.anomalies_table.setItem(r, 1, QTableWidgetItem(pretty_type(a.get("anomaly_type", ""))))
                self.anomalies_table.setItem(r, 2, QTableWidgetItem(a.get("src_ip") or ""))
                self.anomalies_table.setItem(r, 3, QTableWidgetItem(a.get("dst_ip") or ""))
                desc = a.get("description") or ""
                d_item = QTableWidgetItem(desc[:160])
                d_item.setToolTip(desc)
                self.anomalies_table.setItem(r, 4, d_item)
                self.anomalies_table.setItem(r, 5, QTableWidgetItem(short_time(a.get("timestamp"))))
            self.iocs_table.setRowCount(len(iocs))
            for r, ioc in enumerate(iocs):
                self.iocs_table.setItem(r, 0, QTableWidgetItem(ioc.get("ioc_type", "")))
                self.iocs_table.setItem(r, 1, QTableWidgetItem(ioc.get("value", "")))
                self.iocs_table.setItem(r, 2, severity_item(ioc.get("severity") or ""))
                self.iocs_table.setItem(r, 3, QTableWidgetItem(pretty_type(ioc.get("attack_type") or "")))
                self.iocs_table.setItem(r, 4, QTableWidgetItem(str(ioc.get("occurrence_count", 1))))

        def _show_comparison(self, ids: List[str]):
            from .gui_components import pretty_type
            sessions = [self._session_by_id(i) for i in ids]
            sessions.sort(key=lambda s: str(s.get("started_at")) if s else "")
            older, newer = sessions
            try:
                diff = self.database.compare_sessions(older["id"], newer["id"])
            except Exception as e:
                logger.warning(f"Compare failed: {e}")
                return
            esc = _html.escape
            self.compare_title.setText("Compare scans")

            def section(title, items, tone):
                if not items:
                    return (f"<p style='margin:10px 0 2px 0; color:#8b949e'><b>{esc(title)}</b>: none</p>")
                rows = "".join(f"<li>{x}</li>" for x in items[:60])
                more = f"<li>… and {len(items) - 60} more</li>" if len(items) > 60 else ""
                return (f"<p style='margin:12px 0 2px 0; color:{tone}'><b>{esc(title)} ({len(items)})</b></p>"
                        f"<ul style='margin-top:2px'>{rows}{more}</ul>")

            html = (
                f"<p><b>{esc(older.get('pcap_file') or '')}</b> "
                f"<span style='color:#8b949e'>({esc(self._local_time(older.get('started_at')))})</span>"
                f" &nbsp;→&nbsp; <b>{esc(newer.get('pcap_file') or '')}</b> "
                f"<span style='color:#8b949e'>({esc(self._local_time(newer.get('started_at')))})</span></p>"
                f"<p style='color:#8b949e'>Alerts: {older.get('total_anomalies') or 0} → "
                f"{newer.get('total_anomalies') or 0} &nbsp;·&nbsp; Packets: {older.get('total_packets') or 0:,} → "
                f"{newer.get('total_packets') or 0:,}</p>"
                + section("New alert types", [esc(pretty_type(t)) for t in diff["new_types"]], "#f85149")
                + section("Alert types no longer seen", [esc(pretty_type(t)) for t in diff["resolved_types"]],
                          "#3fb950")
                + section("Alert types with a different count",
                          [f"{esc(pretty_type(t))}: {a} → {b}" for t, a, b in diff["changed_types"]], "#d29922")
                + section("New indicators (IOCs)", [f"{esc(t)} · {esc(v)}" for t, v in diff["new_iocs"]],
                          "#f85149")
                + section("Indicators no longer seen", [f"{esc(t)} · {esc(v)}" for t, v in diff["gone_iocs"]],
                          "#3fb950")
            )
            self.compare_text.setHtml(html)

        def _update_stats(self):
            """Kept for compatibility: statistics now live in the header line."""
            self._load_sessions()

        # ---------------------------------------------------------- actions
        def _session_menu(self, pos):
            if not self._selected_ids():
                row = self.sessions_table.rowAt(pos.y())
                if row < 0:
                    return
                self.sessions_table.selectRow(row)
            ids = self._selected_ids()
            menu = QMenu(self)
            if len(ids) == 1:
                menu.addAction("Analyze again", self._reanalyze).setEnabled(self.reanalyze_btn.isEnabled())
                menu.addAction("Export…", self._export_session)
                menu.addSeparator()
            menu.addAction(f"Delete {len(ids)} scan{'s' if len(ids) != 1 else ''}", self._delete_selected)
            menu.exec_(self.sessions_table.viewport().mapToGlobal(pos))

        def _confirm(self, title: str, text: str) -> bool:
            box = QMessageBox(QMessageBox.Warning, title, text, QMessageBox.Cancel, self)
            delete = box.addButton("Delete", QMessageBox.DestructiveRole)
            delete.setObjectName("BtnDanger")
            box.setDefaultButton(QMessageBox.Cancel)
            box.exec_()
            return box.clickedButton() is delete

        def _delete_selected(self):
            ids = self._selected_ids()
            if not ids or not self.database:
                return
            n = len(ids)
            if not self._confirm("Delete scans",
                                 f"Permanently delete {n} scan{'s' if n != 1 else ''} with all their "
                                 "alerts and indicators?\nThis cannot be undone."):
                return
            self.database.delete_sessions(ids)
            self.sessions_table.clearSelection()
            self._load_sessions()

        def _delete_all(self):
            if not self.database:
                return
            if not self._confirm("Delete all history",
                                 "Permanently delete every saved scan from this computer?\n"
                                 "Your IOC watchlist is kept. This cannot be undone."):
                return
            self.database.delete_all_sessions()
            self.sessions_table.clearSelection()
            self._load_sessions()

        def _open_settings(self):
            info = self.database.storage_info() if self.database else {"path": "-"}
            dlg = HistorySettingsDialog(self.history_enabled, self.retention_days, info["path"], self)
            if dlg.exec_() != QDialog.Accepted:
                return
            enabled, days = dlg.values()
            self.settings.setValue("history/enabled", "true" if enabled else "false")
            self.settings.setValue("history/retention_days", int(days))
            self._apply_retention()
            self._load_sessions()

        def _apply_retention(self):
            if self.retention_days and self.database:
                try:
                    removed = self.database.purge_older_than(self.retention_days)
                    if removed:
                        logger.info(f"History clean-up removed {removed} old scan(s)")
                except Exception as e:
                    logger.warning(f"History clean-up failed: {e}")

        def _reanalyze(self):
            path = getattr(self, "_current_path", "")
            if path:
                self.reanalyze_requested.emit(path)

        def _export_session(self):
            ids = self._selected_ids()
            if len(ids) != 1 or not self.database:
                QMessageBox.information(self, "Export", "Select one scan to export.")
                return
            session = self._session_by_id(ids[0]) or {}
            base = (session.get("pcap_file") or "scan").rsplit(".", 1)[0]
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export scan", f"{base}_{ids[0][:8]}.json", "JSON files (*.json)")
            if not filename:
                return
            if self.database.export_session(ids[0], filename):
                QMessageBox.information(self, "Export", f"Scan exported to\n{filename}")
            else:
                QMessageBox.critical(self, "Export", "The scan could not be exported.")

        def _import_session(self):
            filename, _ = QFileDialog.getOpenFileName(self, "Import scan", "", "JSON files (*.json)")
            if filename and self.database:
                if self.database.import_session(filename):
                    self._load_sessions()
                else:
                    QMessageBox.critical(self, "Import", "The file is not a valid exported scan.")

        def _search_iocs(self):
            """Kept for compatibility: the search box now filters scans by file name."""
            self._load_sessions()

        def update_theme(self):
            for k in (self.kpi_packets, self.kpi_alerts, self.kpi_critical, self.kpi_iocs):
                k.update_theme()
            for b in (self.sev_bars, self.type_bars):
                b.update()
            if self.detail_stack.currentIndex() == 2:
                self._show_comparison(self._selected_ids())

        # -------------------------------------------------------- persistence
        def store_analysis_results(self, analyzer, pcap_file: str) -> Optional[str]:
            """
            Save one analysis. May run in a background thread: no widget access
            here — the list is refreshed through the ``history_changed`` signal.
            """
            import os
            if not self.history_enabled or not self.database:
                return None
            try:
                summary = analyzer.get_summary() if hasattr(analyzer, "get_summary") else {}
                anomalies = list(getattr(analyzer, "anomalies", []) or [])
                severity = {}
                for a in anomalies:
                    sev = str(getattr(a, "severity", "")).upper()
                    severity[sev] = severity.get(sev, 0) + 1
                capture_path = os.path.abspath(pcap_file) if pcap_file and os.path.exists(pcap_file) else ""
                metadata = {
                    "app_version": summary.get("VERSION", ""),
                    "capture_path": capture_path,
                    "file_size": summary.get("CAPTURE_SIZE", ""),
                    "duration": summary.get("DURATION_STR", ""),
                    "ot_events": summary.get("OT_EVENTS_TOTAL", 0),
                    "assets": summary.get("ASSETS_DISCOVERED", 0),
                    "protocols": summary.get("OT_PROTOCOLS", {}),
                    "top_techniques": summary.get("TOP_MITRE", {}),
                    "severity": severity,
                }
                session_id = self.database.create_session(
                    os.path.basename(pcap_file) or summary.get("CAPTURE_FILE", "capture"),
                    metadata=metadata,
                    pcap_hash=getattr(analyzer, "capture_sha256", None))
                if anomalies:
                    self.database.store_anomalies(session_id, anomalies)
                try:
                    from .ioc_collector import IOCCollector
                    iocs = IOCCollector().extract_iocs(analyzer)
                    if iocs:
                        self.database.store_iocs(session_id, iocs)
                except Exception as e:
                    logger.warning(f"IOCs not saved to history: {e}")
                self.database.update_session(
                    session_id, status="completed",
                    total_packets=getattr(analyzer, "packets_parsed", 0),
                    total_anomalies=len(anomalies))
                self.database.purge_older_than(self.retention_days)
                logger.info(f"Saved analysis to history: {session_id}")
                self.history_changed.emit()
                return session_id
            except Exception as e:
                logger.error(f"Failed to store analysis results: {e}")
                return None

else:
    # Fallback when PyQt5 not available
    class ThreatIntelPanel:
        pass

    class DatabaseHistoryPanel:
        pass

    class HistorySettingsDialog:
        pass
