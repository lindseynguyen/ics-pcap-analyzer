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

from typing import Dict, List, Optional, Any

try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QLineEdit, QGroupBox, QTableWidget, QTableWidgetItem,
        QHeaderView, QComboBox, QTextEdit, QMessageBox, QTabWidget,
        QFormLayout, QCheckBox, QSpinBox, QFrame, QFileDialog,
        QProgressBar, QSplitter
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont
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
                config_dir.mkdir(parents=True, exist_ok=True)
                config_file = config_dir / "api_keys.json"

                keys = {}
                if self.vt_key_input.text().strip():
                    keys['virustotal'] = self.vt_key_input.text().strip()
                if self.abuse_key_input.text().strip():
                    keys['abuseipdb'] = self.abuse_key_input.text().strip()

                with open(config_file, 'w') as f:
                    json.dump(keys, f)

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
<p><b>Severity:</b> {severity}</p>
<p><b>Sources:</b> {', '.join(sources) if sources else 'Local feed only'}</p>
<p><b>Checked at:</b> {result.get('checked_at', 'N/A')}</p>
<hr/>
<details>
<summary>Raw Details</summary>
<pre>{self._format_details(result.get('details', {}))}</pre>
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

    class DatabaseHistoryPanel(QWidget):
        """
        Panel for browsing analysis history from the database.
        """

        session_selected = pyqtSignal(str)  # Emitted when a session is selected

        def __init__(self, parent=None):
            super().__init__(parent)

            # Lazy load database
            self._database = None

            self._init_ui()

        @property
        def database(self):
            """Lazy load database module."""
            if self._database is None:
                try:
                    from .database import AnalysisDatabase
                    self._database = AnalysisDatabase()
                except Exception as e:
                    logger.warning(f"Database not available: {e}")
            return self._database

        def _init_ui(self):
            """Initialize UI components."""
            layout = QVBoxLayout(self)
            layout.setSpacing(12)

            # Header
            header = QLabel("📚 Analysis History Database")
            header.setStyleSheet("font-size: 20px; font-weight: bold; color: #bc8cff;")
            layout.addWidget(header)

            # Toolbar
            toolbar = self._create_toolbar()
            layout.addWidget(toolbar)

            # Splitter for sessions and details
            splitter = QSplitter(Qt.Vertical)

            # Sessions table
            sessions_group = self._create_sessions_group()
            splitter.addWidget(sessions_group)

            # Details tabs
            details_widget = self._create_details_widget()
            splitter.addWidget(details_widget)

            splitter.setSizes([300, 400])
            layout.addWidget(splitter)

            # Statistics
            stats_group = self._create_stats_group()
            layout.addWidget(stats_group)

            # Load initial data
            self._load_sessions()

        def _create_toolbar(self) -> QWidget:
            """Create toolbar with actions."""
            toolbar = QWidget()
            layout = QHBoxLayout(toolbar)
            layout.setContentsMargins(0, 0, 0, 0)

            refresh_btn = QPushButton("🔄 Refresh")
            refresh_btn.clicked.connect(self._load_sessions)
            layout.addWidget(refresh_btn)

            export_btn = QPushButton("📤 Export Session")
            export_btn.clicked.connect(self._export_session)
            layout.addWidget(export_btn)

            import_btn = QPushButton("📥 Import Session")
            import_btn.clicked.connect(self._import_session)
            layout.addWidget(import_btn)

            layout.addStretch()

            # Search
            layout.addWidget(QLabel("🔍 Search IOC:"))
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("IP, hash, domain...")
            self.search_input.setMaximumWidth(200)
            self.search_input.returnPressed.connect(self._search_iocs)
            layout.addWidget(self.search_input)

            search_btn = QPushButton("Search")
            search_btn.clicked.connect(self._search_iocs)
            layout.addWidget(search_btn)

            return toolbar

        def _create_sessions_group(self) -> QGroupBox:
            """Create sessions table."""
            group = QGroupBox("📋 Analysis Sessions")
            layout = QVBoxLayout(group)

            self.sessions_table = QTableWidget()
            self.sessions_table.setColumnCount(6)
            self.sessions_table.setHorizontalHeaderLabels([
                "Session ID", "PCAP File", "Status", "Packets", "Anomalies", "Date"
            ])
            self.sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.sessions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)  # PCAP File stretches
            self.sessions_table.setAlternatingRowColors(True)
            self.sessions_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.sessions_table.cellClicked.connect(self._on_session_selected)
            layout.addWidget(self.sessions_table)

            return group

        def _create_details_widget(self) -> QWidget:
            """Create details tabs widget."""
            tabs = QTabWidget()

            # Anomalies tab
            self.anomalies_table = QTableWidget()
            self.anomalies_table.setColumnCount(6)
            self.anomalies_table.setHorizontalHeaderLabels([
                "Type", "Severity", "Source IP", "Dest IP", "Description", "Time"
            ])
            self.anomalies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.anomalies_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)  # Description stretches
            tabs.addTab(self.anomalies_table, "⚠️ Anomalies")

            # IOCs tab
            self.iocs_table = QTableWidget()
            self.iocs_table.setColumnCount(5)
            self.iocs_table.setHorizontalHeaderLabels([
                "Type", "Value", "Severity", "Attack Type", "Count"
            ])
            self.iocs_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.iocs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)  # Value stretches
            tabs.addTab(self.iocs_table, "🔍 IOCs")

            # Trends tab
            self.trends_text = QTextEdit()
            self.trends_text.setReadOnly(True)
            tabs.addTab(self.trends_text, "📈 Trends")

            return tabs

        def _create_stats_group(self) -> QGroupBox:
            """Create overall statistics group."""
            group = QGroupBox("📊 Database Statistics (Last 30 Days)")
            layout = QHBoxLayout(group)

            self.db_stats_labels = {}
            for stat_name in ['Sessions', 'Total Anomalies', 'Unique IOCs', 'Critical Alerts']:
                frame = QFrame()
                frame.setFrameShape(QFrame.StyledPanel)
                frame_layout = QVBoxLayout(frame)

                value_label = QLabel("0")
                value_label.setStyleSheet("font-size: 28px; font-weight: bold; color: #bc8cff;")
                value_label.setAlignment(Qt.AlignCenter)
                frame_layout.addWidget(value_label)

                name_label = QLabel(stat_name)
                name_label.setAlignment(Qt.AlignCenter)
                name_label.setStyleSheet("color: #c9d1d9; font-size: 14px;")
                frame_layout.addWidget(name_label)

                self.db_stats_labels[stat_name] = value_label
                layout.addWidget(frame)

            return group

        def _load_sessions(self):
            """Load sessions from database."""
            if not self.database:
                return

            try:
                sessions = self.database.get_recent_sessions(limit=50)

                self.sessions_table.setRowCount(0)
                for session in sessions:
                    row = self.sessions_table.rowCount()
                    self.sessions_table.insertRow(row)

                    self.sessions_table.setItem(row, 0, QTableWidgetItem(session.get('id', '')))
                    self.sessions_table.setItem(row, 1, QTableWidgetItem(session.get('pcap_file', '')))
                    self.sessions_table.setItem(row, 2, QTableWidgetItem(session.get('status', '')))
                    self.sessions_table.setItem(row, 3, QTableWidgetItem(str(session.get('total_packets', 0))))
                    self.sessions_table.setItem(row, 4, QTableWidgetItem(str(session.get('total_anomalies', 0))))
                    self.sessions_table.setItem(row, 5, QTableWidgetItem(str(session.get('started_at', ''))))

                # Update stats
                self._update_stats()

            except Exception as e:
                logger.warning(f"Failed to load sessions: {e}")

        def _on_session_selected(self, row: int, col: int):
            """Handle session selection."""
            session_id = self.sessions_table.item(row, 0).text()
            self._load_session_details(session_id)
            self.session_selected.emit(session_id)

        def _load_session_details(self, session_id: str):
            """Load session details."""
            if not self.database:
                return

            try:
                # Load anomalies
                anomalies = self.database.get_anomalies(session_id=session_id, limit=100)

                self.anomalies_table.setRowCount(0)
                for anomaly in anomalies:
                    row = self.anomalies_table.rowCount()
                    self.anomalies_table.insertRow(row)

                    self.anomalies_table.setItem(row, 0, QTableWidgetItem(anomaly.get('anomaly_type', '')))

                    severity_item = QTableWidgetItem(anomaly.get('severity', ''))
                    severity = anomaly.get('severity', '')
                    if severity == 'CRITICAL':
                        severity_item.setForeground(Qt.red)
                    elif severity == 'HIGH':
                        severity_item.setForeground(Qt.darkYellow)
                    self.anomalies_table.setItem(row, 1, severity_item)

                    self.anomalies_table.setItem(row, 2, QTableWidgetItem(anomaly.get('src_ip', '')))
                    self.anomalies_table.setItem(row, 3, QTableWidgetItem(anomaly.get('dst_ip', '')))
                    self.anomalies_table.setItem(row, 4, QTableWidgetItem(anomaly.get('description', '')[:50]))
                    self.anomalies_table.setItem(row, 5, QTableWidgetItem(str(anomaly.get('timestamp', ''))))

                # Load IOCs
                iocs = self.database.get_iocs(session_id=session_id, limit=100)

                self.iocs_table.setRowCount(0)
                for ioc in iocs:
                    row = self.iocs_table.rowCount()
                    self.iocs_table.insertRow(row)

                    self.iocs_table.setItem(row, 0, QTableWidgetItem(ioc.get('ioc_type', '')))
                    self.iocs_table.setItem(row, 1, QTableWidgetItem(ioc.get('value', '')))
                    self.iocs_table.setItem(row, 2, QTableWidgetItem(ioc.get('severity', '')))
                    self.iocs_table.setItem(row, 3, QTableWidgetItem(ioc.get('attack_type', '')))
                    self.iocs_table.setItem(row, 4, QTableWidgetItem(str(ioc.get('occurrence_count', 0))))

            except Exception as e:
                logger.warning(f"Failed to load session details: {e}")

        def _update_stats(self):
            """Update database statistics."""
            if not self.database:
                return

            try:
                stats = self.database.get_statistics(days=30)

                session_stats = stats.get('sessions', {})
                self.db_stats_labels['Sessions'].setText(str(session_stats.get('total', 0)))
                self.db_stats_labels['Total Anomalies'].setText(str(session_stats.get('total_anomalies', 0)))

                ioc_stats = stats.get('ioc_types', {})
                total_iocs = sum(t.get('unique', 0) for t in ioc_stats.values())
                self.db_stats_labels['Unique IOCs'].setText(str(total_iocs))

                severity_stats = stats.get('severity_distribution', {})
                self.db_stats_labels['Critical Alerts'].setText(str(severity_stats.get('CRITICAL', 0)))

                # Update trends text
                self._update_trends_display(stats)

            except Exception as e:
                logger.warning(f"Failed to update stats: {e}")

        def _update_trends_display(self, stats: Dict):
            """Update trends display."""
            html = "<h3>📈 Analysis Trends (Last 30 Days)</h3>"

            # Anomaly types
            anomaly_types = stats.get('anomaly_types', {})
            if anomaly_types:
                html += "<h4>Top Anomaly Types:</h4><ul>"
                for atype, count in sorted(anomaly_types.items(), key=lambda x: -x[1])[:10]:
                    html += f"<li>{atype}: {count}</li>"
                html += "</ul>"

            # Top IPs
            top_ips = stats.get('top_source_ips', [])
            if top_ips:
                html += "<h4>Top Attacking IPs:</h4><ul>"
                for ip_data in top_ips[:5]:
                    html += f"<li>{ip_data['ip']}: {ip_data['count']} events</li>"
                html += "</ul>"

            self.trends_text.setHtml(html)

        def _export_session(self):
            """Export selected session."""
            selected = self.sessions_table.selectedItems()
            if not selected:
                QMessageBox.warning(self, "Warning", "Please select a session to export")
                return

            session_id = self.sessions_table.item(selected[0].row(), 0).text()

            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Session", f"session_{session_id}.json", "JSON files (*.json)"
            )

            if filename and self.database:
                if self.database.export_session(session_id, filename):
                    QMessageBox.information(self, "Success", f"Session exported to {filename}")
                else:
                    QMessageBox.critical(self, "Error", "Failed to export session")

        def _import_session(self):
            """Import session from file."""
            filename, _ = QFileDialog.getOpenFileName(
                self, "Import Session", "", "JSON files (*.json)"
            )

            if filename and self.database:
                session_id = self.database.import_session(filename)
                if session_id:
                    QMessageBox.information(self, "Success", f"Session imported: {session_id}")
                    self._load_sessions()
                else:
                    QMessageBox.critical(self, "Error", "Failed to import session")

        def _search_iocs(self):
            """Search IOCs in database."""
            query = self.search_input.text().strip()
            if not query or not self.database:
                return

            try:
                results = self.database.search_iocs(query, limit=50)

                if results:
                    # Show in IOCs table
                    self.iocs_table.setRowCount(0)
                    for ioc in results:
                        row = self.iocs_table.rowCount()
                        self.iocs_table.insertRow(row)

                        self.iocs_table.setItem(row, 0, QTableWidgetItem(ioc.get('ioc_type', '')))
                        self.iocs_table.setItem(row, 1, QTableWidgetItem(ioc.get('value', '')))
                        self.iocs_table.setItem(row, 2, QTableWidgetItem(ioc.get('severity', '')))
                        self.iocs_table.setItem(row, 3, QTableWidgetItem(ioc.get('attack_type', '')))
                        self.iocs_table.setItem(row, 4, QTableWidgetItem(str(ioc.get('occurrence_count', 0))))

                    QMessageBox.information(self, "Search Results", f"Found {len(results)} matching IOCs")
                else:
                    QMessageBox.information(self, "Search Results", "No matching IOCs found")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Search failed: {e}")

        def store_analysis_results(self, analyzer, pcap_file: str) -> Optional[str]:
            """
            Store analysis results to database.

            NOTE: This method may be called from a background thread.
            Do NOT update any GUI elements here. Use signals/slots for UI updates.

            Args:
                analyzer: OTAnalyzer instance with results
                pcap_file: Path to analyzed PCAP file

            Returns:
                Session ID if successful
            """
            if not self.database:
                return None

            try:
                # Create session
                session_id = self.database.create_session(pcap_file, metadata={
                    'version': getattr(analyzer, 'VERSION', 'unknown'),
                    'packets_parsed': analyzer.packets_parsed,
                })

                # Store anomalies
                if hasattr(analyzer, 'anomalies'):
                    self.database.store_anomalies(session_id, analyzer.anomalies)

                # Store IOCs if available
                if hasattr(analyzer, 'ioc_results') and analyzer.ioc_results:
                    self.database.store_iocs(session_id, analyzer.ioc_results)

                # Update session status
                self.database.update_session(
                    session_id,
                    status='completed',
                    total_packets=analyzer.packets_parsed,
                    total_anomalies=len(getattr(analyzer, 'anomalies', []))
                )

                logger.info(f"Stored analysis results to database: {session_id}")

                # NOTE: Do NOT call _load_sessions() here!
                # It updates GUI from background thread which causes crash.
                # The UI will be refreshed next time user navigates to History tab.

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
