"""
OT PCAP Analyzer - IOC Panel
=============================
UI widget for displaying and exporting Indicators of Compromise (IOCs).
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QComboBox, QLineEdit, QPushButton,
    QFileDialog, QTextEdit, QSizePolicy, QGraphicsDropShadowEffect,
    QAbstractItemView, QMenu, QApplication, QMessageBox
)
from PyQt5.QtCore import Qt, QSize, QUrl
from PyQt5.QtGui import QColor, QDesktopServices

import html as _html
import urllib.parse
from datetime import datetime
from typing import Dict, List

from .ioc_collector import IOCCollector
from .ioc_models import IOCRecord
from .utils import is_internal_ip as _is_internal_ip


# Color constants - SOC Theme (High Contrast)
SEVERITY_COLORS = {
    "CRITICAL": ("#5c1f1f", "#ff4444"),  # (background, text) - high contrast red
    "HIGH": ("#5c3a1f", "#ff9933"),       # orange
    "MEDIUM": ("#5c4a1f", "#ffcc00"),     # yellow
    "LOW": ("#2d4a2d", "#66cc66"),        # green
}

IOC_TYPE_ICONS = {
    "IP": "🌐",
    "HASH": "🔐",
    "DOMAIN": "🔗",
    "URL": "📎",
    "MITRE_TECHNIQUE": "⚔️",
}


class IOCStatCard(QFrame):
    """Compact stat card for IOC dashboard."""

    def __init__(self, title: str, value: str = "0", color: str = "#3b82f6"):
        super().__init__()
        self.setObjectName("IOCStatCard")

        # Fixed size
        self.setMinimumSize(QSize(140, 85))
        self.setMaximumSize(QSize(200, 85))
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

        # SOC theme styling - left accent bar (high contrast)
        self.setStyleSheet(f"""
            QFrame#IOCStatCard {{
                background-color: #2d333b;
                border-radius: 8px;
                border: 1px solid #444c56;
                border-left: 4px solid {color};
            }}
            QFrame#IOCStatCard:hover {{
                background-color: #373e47;
                border-color: {color};
            }}
        """)

        # Shadow
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(8)
        shadow.setColor(QColor(0, 0, 0, 40))
        shadow.setOffset(0, 2)
        self.setGraphicsEffect(shadow)

        # Layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(4)

        # Title - uppercase, larger
        title_label = QLabel(title.upper())
        title_label.setStyleSheet(
            "color: #e6edf3; font-size: 12px; font-weight: 600; letter-spacing: 1px;"
        )
        title_label.setWordWrap(True)
        layout.addWidget(title_label)

        # Value - large, bold
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(
            "color: #f0f6fc; font-size: 32px; font-weight: 700; margin-top: 2px;"
        )
        layout.addWidget(self.value_label)

    def set_value(self, value: str):
        """Update card value."""
        self.value_label.setText(str(value))


class IOCPanel(QWidget):
    """
    IOC Extraction and Export Panel.

    Displays categorized IOCs with filtering, sorting, and export capabilities.
    """

    def __init__(self, parent=None, theme_manager=None):
        super().__init__(parent)
        self.theme_manager = theme_manager
        self.iocs: Dict[str, List[IOCRecord]] = {}
        self.filtered_iocs: List[IOCRecord] = []
        self.analyzer = None

        # Pagination state
        self.current_page = 0
        self.rows_per_page = 100
        self.total_pages = 1

        self._init_ui()

    def _init_ui(self):
        """Initialize UI components."""
        # Set high contrast dark theme background
        self.setStyleSheet("""
            QWidget {
                background-color: #0d1117;
                color: #ffffff;
            }
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(12)

        # Title
        title = QLabel("IOC Dashboard")
        title.setStyleSheet(
            "font-size: 22px; margin-bottom: 8px; font-weight: 700; color: #ffffff; letter-spacing: 0.5px;"
        )
        main_layout.addWidget(title)

        # Stat cards container
        cards_container = QFrame()
        cards_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        cards_container.setMaximumHeight(100)

        cards_layout = QHBoxLayout(cards_container)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(10)

        self.card_total = IOCStatCard("Total IOCs", "0", "#4285f4")
        self.card_ips = IOCStatCard("Malicious IPs", "0", "#ea4335")
        self.card_hashes = IOCStatCard("File Hashes", "0", "#4285f4")
        self.card_techniques = IOCStatCard("MITRE Techniques", "0", "#fbbc04")
        self.card_critical = IOCStatCard("Critical", "0", "#ea4335")

        for card in [self.card_total, self.card_ips, self.card_hashes,
                     self.card_techniques, self.card_critical]:
            cards_layout.addWidget(card)

        cards_layout.addStretch()
        main_layout.addWidget(cards_container)

        # Filter toolbar
        toolbar = self._create_toolbar()
        main_layout.addWidget(toolbar)

        # IOC Table
        self.ioc_table = self._create_table()
        main_layout.addWidget(self.ioc_table)

        # Pagination controls
        pagination_layout = QHBoxLayout()
        pagination_layout.setSpacing(8)

        self.page_info_label = QLabel("Page 1 of 1")
        self.page_info_label.setStyleSheet("color: #adbac7; font-size: 13px; font-weight: 500;")
        pagination_layout.addWidget(self.page_info_label)

        pagination_layout.addStretch()

        # Rows per page selector
        rows_label = QLabel("Rows:")
        rows_label.setStyleSheet("color: #adbac7; font-size: 13px; font-weight: 500;")
        pagination_layout.addWidget(rows_label)

        self.rows_per_page_combo = QComboBox()
        self.rows_per_page_combo.addItems(["50", "100", "250", "500", "All"])
        self.rows_per_page_combo.setCurrentIndex(1)  # Default 100
        self.rows_per_page_combo.setFixedWidth(80)
        self.rows_per_page_combo.setStyleSheet("""
            QComboBox {
                background-color: #22272e;
                border: 2px solid #444c56;
                border-radius: 6px;
                padding: 6px 10px;
                color: #ffffff;
                font-size: 13px;
                font-weight: 500;
            }
            QComboBox:hover {
                border-color: #1f6feb;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #2d333b;
                border: 2px solid #444c56;
                selection-background-color: #1f6feb;
                color: #ffffff;
            }
        """)
        self.rows_per_page_combo.currentIndexChanged.connect(self._on_page_size_changed)
        pagination_layout.addWidget(self.rows_per_page_combo)

        # Navigation buttons - using ASCII text for compatibility
        btn_style = """
            QPushButton {
                background-color: #22272e;
                border: 2px solid #444c56;
                border-radius: 6px;
                color: #ffffff;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2d333b;
                border-color: #1f6feb;
                color: #58a6ff;
            }
            QPushButton:disabled {
                color: #545d68;
                background-color: #1c2128;
                border-color: #2d333b;
            }
        """

        self.btn_first = QPushButton("<<")
        self.btn_first.setFixedSize(36, 30)
        self.btn_first.setToolTip("First page")
        self.btn_first.setStyleSheet(btn_style)
        self.btn_first.clicked.connect(lambda: self._go_to_page(0))
        pagination_layout.addWidget(self.btn_first)

        self.btn_prev = QPushButton("<")
        self.btn_prev.setFixedSize(36, 30)
        self.btn_prev.setToolTip("Previous page")
        self.btn_prev.setStyleSheet(btn_style)
        self.btn_prev.clicked.connect(lambda: self._go_to_page(self.current_page - 1))
        pagination_layout.addWidget(self.btn_prev)

        self.page_input = QLineEdit("1")
        self.page_input.setFixedWidth(50)
        self.page_input.setAlignment(Qt.AlignCenter)
        self.page_input.setStyleSheet("""
            QLineEdit {
                background-color: #22272e;
                border: 2px solid #444c56;
                border-radius: 6px;
                color: #ffffff;
                padding: 6px;
                font-size: 13px;
                font-weight: 600;
            }
            QLineEdit:focus {
                border-color: #1f6feb;
            }
        """)
        self.page_input.returnPressed.connect(self._on_page_input)
        pagination_layout.addWidget(self.page_input)

        self.btn_next = QPushButton(">")
        self.btn_next.setFixedSize(36, 30)
        self.btn_next.setToolTip("Next page")
        self.btn_next.setStyleSheet(btn_style)
        self.btn_next.clicked.connect(lambda: self._go_to_page(self.current_page + 1))
        pagination_layout.addWidget(self.btn_next)

        self.btn_last = QPushButton(">>")
        self.btn_last.setFixedSize(36, 30)
        self.btn_last.setToolTip("Last page")
        self.btn_last.setStyleSheet(btn_style)
        self.btn_last.clicked.connect(lambda: self._go_to_page(self.total_pages - 1))
        pagination_layout.addWidget(self.btn_last)

        # Total records label
        self.total_label = QLabel("0 IOCs")
        self.total_label.setStyleSheet("color: #58a6ff; font-size: 13px; font-weight: 700; margin-left: 16px;")
        pagination_layout.addWidget(self.total_label)

        main_layout.addLayout(pagination_layout)

        # Detail panel (initially hidden)
        self.detail_panel = QTextEdit()
        self.detail_panel.setReadOnly(True)
        self.detail_panel.setMaximumHeight(160)
        self.detail_panel.setStyleSheet("""
            QTextEdit {
                background-color: #2d333b;
                border: 2px solid #1f6feb;
                border-radius: 8px;
                padding: 16px;
                font-size: 14px;
                color: #ffffff;
            }
        """)
        self.detail_panel.setVisible(False)
        main_layout.addWidget(self.detail_panel)

        # Show empty state
        self._show_empty_state()

    def _create_toolbar(self) -> QFrame:
        """Create filter and export toolbar."""
        toolbar = QFrame()
        toolbar.setStyleSheet("""
            QFrame {
                background-color: #2d333b;
                border: 1px solid #444c56;
                border-radius: 8px;
                padding: 8px;
            }
            QLabel {
                color: #ffffff;
                font-weight: 600;
            }
            QComboBox {
                background-color: #22272e;
                border: 2px solid #444c56;
                border-radius: 6px;
                padding: 8px 12px;
                color: #ffffff;
                font-size: 13px;
                min-height: 20px;
            }
            QComboBox:hover {
                border-color: #1f6feb;
                background-color: #2d333b;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d333b;
                border: 2px solid #444c56;
                selection-background-color: #1f6feb;
                color: #ffffff;
                padding: 4px;
            }
            QLineEdit {
                background-color: #22272e;
                border: 2px solid #444c56;
                border-radius: 6px;
                padding: 8px 12px;
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit:focus {
                border-color: #1f6feb;
                background-color: #2d333b;
            }
            QLineEdit::placeholder {
                color: #768390;
            }
        """)

        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(16)

        # Type filter
        type_label = QLabel("Type:")
        type_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #e6edf3;")
        layout.addWidget(type_label)

        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "All Types", "IP", "HASH", "DOMAIN", "URL", "MITRE_TECHNIQUE"
        ])
        self.type_filter.setFixedWidth(150)
        self.type_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.type_filter)

        # Severity filter
        severity_label = QLabel("Severity:")
        severity_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #e6edf3;")
        layout.addWidget(severity_label)

        self.severity_filter = QComboBox()
        self.severity_filter.addItems([
            "All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"
        ])
        self.severity_filter.setFixedWidth(150)
        self.severity_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.severity_filter)

        # Attack Type filter
        attack_label = QLabel("Attack Type:")
        attack_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #e6edf3;")
        layout.addWidget(attack_label)

        self.attack_filter = QComboBox()
        self.attack_filter.addItems([
            "All Attacks",
            "WEBSHELL",
            "SQL_INJECTION",
            "XSS",
            "PORT_SCAN",
            "DNS_TUNNELING",
            "ARP_SPOOFING",
            "C2_BEACON",
            "DATA_EXFILTRATION",
            "BRUTE_FORCE",
            "LATERAL_MOVEMENT",
            "HTTP_ATTACK",
            "OT_PROTOCOL_ATTACK",
            "OTHER"
        ])
        self.attack_filter.setFixedWidth(160)
        self.attack_filter.setToolTip("Filter IOCs by attack type for assessment")
        self.attack_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.attack_filter)

        # Search box
        search_label = QLabel("Search:")
        search_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #e6edf3;")
        layout.addWidget(search_label)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search IOC value or description...")
        self.search_box.setFixedWidth(250)
        self.search_box.textChanged.connect(self._apply_filters)
        layout.addWidget(self.search_box)

        layout.addStretch()

        # Export buttons
        self.export_json_btn = QPushButton("Export JSON")
        self.export_json_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: #ffffff;
                border: 2px solid #1f6feb;
                border-radius: 6px;
                padding: 10px 18px;
                font-size: 13px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #388bfd;
                border-color: #388bfd;
            }
        """)
        self.export_json_btn.setMinimumWidth(130)
        self.export_json_btn.clicked.connect(self._export_json)
        layout.addWidget(self.export_json_btn)

        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                border: 2px solid #238636;
                border-radius: 6px;
                padding: 10px 18px;
                font-size: 13px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #2ea043;
                border-color: #2ea043;
            }
        """)
        self.export_csv_btn.setMinimumWidth(130)
        self.export_csv_btn.clicked.connect(self._export_csv)
        layout.addWidget(self.export_csv_btn)

        return toolbar

    def _create_table(self) -> QTableWidget:
        """Create IOC table with enhanced features."""
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            "Type", "Value", "Severity", "First Seen", "Last Seen", "Occurrences", "Context"
        ])

        # Add tooltips for column headers
        header_tooltips = [
            "IOC type: IP, HASH, DOMAIN, URL, MITRE_TECHNIQUE",
            "IOC value. Double-click to copy. Right-click to look up",
            "Severity: CRITICAL > HIGH > MEDIUM > LOW",
            "First time the IOC was seen in traffic",
            "Last time the IOC was seen in traffic",
            "Number of IOC occurrences in the entire capture",
            "Detection context (anomaly type, attack chain, etc.)"
        ]
        for i, tooltip in enumerate(header_tooltips):
            if table.horizontalHeaderItem(i):
                table.horizontalHeaderItem(i).setToolTip(tooltip)

        # Dark theme table styling - HIGH CONTRAST for readability
        table.setStyleSheet("""
            QTableWidget {
                background-color: #1c2128;
                alternate-background-color: #22272e;
                border: 1px solid #444c56;
                border-radius: 8px;
                gridline-color: #2d333b;
                color: #ffffff;
                font-size: 13px;
                selection-background-color: #1f6feb;
            }
            QTableWidget::item {
                padding: 10px 8px;
                border-bottom: 1px solid #2d333b;
                color: #ffffff;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb;
                color: #ffffff;
            }
            QTableWidget::item:hover {
                background-color: #2d333b;
            }
            QHeaderView::section {
                background-color: #2d333b;
                padding: 12px 8px;
                border: none;
                border-bottom: 2px solid #1f6feb;
                border-right: 1px solid #1c2128;
                font-weight: 700;
                font-size: 12px;
                color: #ffffff;
                text-transform: uppercase;
            }
            QScrollBar:vertical {
                background-color: #1c2128;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #444c56;
                border-radius: 6px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #1f6feb;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        table.setAlternatingRowColors(True)

        # Column widths - auto-fit content, stretch Value and Context
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Value stretches
        header.setSectionResizeMode(6, QHeaderView.Stretch)  # Context stretches

        # Table behavior
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSortingEnabled(True)
        table.verticalHeader().setVisible(False)

        # Connect row selection
        table.itemSelectionChanged.connect(self._on_row_selected)

        # Enable context menu (right-click)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self._show_context_menu)

        # Enable double-click to copy value
        table.cellDoubleClicked.connect(self._on_cell_double_click)

        return table

    def update_iocs(self, analyzer):
        """
        Update IOC panel with data from analyzer.

        Args:
            analyzer: OTAnalyzer instance
        """
        self.analyzer = analyzer

        if not analyzer:
            self._show_empty_state()
            return

        # Extract IOCs
        collector = IOCCollector()
        self.iocs = collector.extract_iocs(analyzer)

        # Update stat cards
        self._update_stat_cards()

        # Populate table
        self._apply_filters()

    def _update_stat_cards(self):
        """Update stat card values."""
        # Calculate total excluding by_attack_type (which is a dict, not list)
        total = 0
        for key, ioc_list in self.iocs.items():
            if key == "by_attack_type":
                continue
            if isinstance(ioc_list, list):
                total += len(ioc_list)
        self.card_total.set_value(str(total))

        ips_count = len(self.iocs.get("malicious_ips", []))
        self.card_ips.set_value(str(ips_count))

        hashes_count = len(self.iocs.get("file_hashes", []))
        self.card_hashes.set_value(str(hashes_count))

        techniques_count = len(self.iocs.get("mitre_techniques", []))
        self.card_techniques.set_value(str(techniques_count))

        # Count critical IOCs (excluding by_attack_type)
        critical_count = 0
        for key, ioc_list in self.iocs.items():
            if key == "by_attack_type":
                continue
            if isinstance(ioc_list, list):
                critical_count += sum(1 for ioc in ioc_list if hasattr(ioc, 'severity') and ioc.severity == "CRITICAL")
        self.card_critical.set_value(str(critical_count))

    def _apply_filters(self):
        """Apply type, severity, attack type, and search filters to IOC list."""
        # Flatten all IOCs (excluding by_attack_type which is a dict of lists)
        all_iocs = []
        for key, ioc_list in self.iocs.items():
            if key == "by_attack_type":
                continue  # Handle separately
            if isinstance(ioc_list, list):
                all_iocs.extend(ioc_list)

        # Apply type filter
        type_filter = self.type_filter.currentText()
        if type_filter != "All Types":
            all_iocs = [ioc for ioc in all_iocs if ioc.ioc_type == type_filter]

        # Apply severity filter
        severity_filter = self.severity_filter.currentText()
        if severity_filter != "All Severities":
            all_iocs = [ioc for ioc in all_iocs if ioc.severity == severity_filter]

        # Apply attack type filter
        attack_filter = self.attack_filter.currentText()
        if attack_filter != "All Attacks":
            # Get IOCs from the by_attack_type category
            attack_iocs = self.iocs.get("by_attack_type", {})
            if attack_filter in attack_iocs:
                # Replace all_iocs with attack-specific IOCs
                all_iocs = attack_iocs[attack_filter]
            else:
                # No IOCs for this attack type - filter by context
                all_iocs = [ioc for ioc in all_iocs if attack_filter.lower() in ioc.context.lower()]

        # Apply search filter
        search_text = self.search_box.text().lower()
        if search_text:
            all_iocs = [
                ioc for ioc in all_iocs
                if (search_text in ioc.value.lower() or
                    search_text in ioc.description.lower())
            ]

        self.filtered_iocs = all_iocs
        self.current_page = 0  # Reset to first page when filter changes
        self._populate_table()

    def _populate_table(self):
        """Populate table with filtered IOCs using pagination."""
        # Update pagination first
        self._update_pagination()

        self.ioc_table.setSortingEnabled(False)
        self.ioc_table.setRowCount(0)

        if not self.filtered_iocs:
            self.ioc_table.setRowCount(1)
            item = QTableWidgetItem("No IOCs found with current filters")
            item.setTextAlignment(Qt.AlignCenter)
            item.setForeground(QColor("#94a3b8"))
            self.ioc_table.setItem(0, 0, item)
            self.ioc_table.setSpan(0, 0, 1, 7)
            return

        # Get current page slice
        start_idx = self.current_page * self.rows_per_page
        end_idx = min(start_idx + self.rows_per_page, len(self.filtered_iocs))
        display_iocs = self.filtered_iocs[start_idx:end_idx]

        self.ioc_table.setRowCount(len(display_iocs))

        for row, ioc in enumerate(display_iocs):
            # Type column
            type_icon = IOC_TYPE_ICONS.get(ioc.ioc_type, "•")
            type_item = QTableWidgetItem(f"{type_icon} {ioc.ioc_type}")
            type_item.setData(Qt.UserRole, ioc)  # Store IOC object
            self.ioc_table.setItem(row, 0, type_item)

            # Value column
            display_value = ioc.value
            if len(display_value) > 50:
                display_value = display_value[:47] + "..."
            value_item = QTableWidgetItem(display_value)
            value_item.setToolTip(f"Click to copy: {ioc.value}")
            self.ioc_table.setItem(row, 1, value_item)

            # Severity column
            sev_bg, sev_text = SEVERITY_COLORS.get(ioc.severity, ("#f3f4f6", "#6b7280"))
            sev_item = QTableWidgetItem(ioc.severity)
            sev_item.setBackground(QColor(sev_bg))
            sev_item.setForeground(QColor(sev_text))
            sev_item.setTextAlignment(Qt.AlignCenter)
            font = sev_item.font()
            font.setBold(True)
            sev_item.setFont(font)
            self.ioc_table.setItem(row, 2, sev_item)

            # First Seen column
            try:
                if ioc.first_seen > 0:
                    first_dt_str = datetime.fromtimestamp(ioc.first_seen).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    first_dt_str = "N/A"
            except:
                first_dt_str = "Invalid"
            first_seen_item = QTableWidgetItem(first_dt_str)
            self.ioc_table.setItem(row, 3, first_seen_item)

            # Last Seen column
            try:
                if ioc.last_seen > 0:
                    last_dt_str = datetime.fromtimestamp(ioc.last_seen).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    last_dt_str = "N/A"
            except:
                last_dt_str = "Invalid"
            last_seen_item = QTableWidgetItem(last_dt_str)
            self.ioc_table.setItem(row, 4, last_seen_item)

            # Occurrences column
            occ_item = QTableWidgetItem(str(ioc.occurrences))
            occ_item.setTextAlignment(Qt.AlignCenter)
            self.ioc_table.setItem(row, 5, occ_item)

            # Context column
            context_display = ioc.context
            if len(context_display) > 60:
                context_display = context_display[:57] + "..."
            context_item = QTableWidgetItem(context_display)
            context_item.setToolTip(ioc.context)
            self.ioc_table.setItem(row, 6, context_item)

        self.ioc_table.setSortingEnabled(True)

    def _on_row_selected(self):
        """Handle table row selection - show detail panel."""
        selected_rows = self.ioc_table.selectedItems()
        if not selected_rows:
            self.detail_panel.setVisible(False)
            return

        # Get IOC from first column of selected row
        row = selected_rows[0].row()
        type_item = self.ioc_table.item(row, 0)
        ioc = type_item.data(Qt.UserRole)

        if not ioc:
            return

        # Build detail HTML
        detail_html = self._build_detail_html(ioc)
        self.detail_panel.setHtml(detail_html)
        self.detail_panel.setVisible(True)

    # =========================================================================
    # PAGINATION METHODS
    # =========================================================================

    def _on_page_size_changed(self):
        """Handle rows per page change."""
        text = self.rows_per_page_combo.currentText()
        if text == "All":
            self.rows_per_page = len(self.filtered_iocs) or 1000
        else:
            self.rows_per_page = int(text)
        self.current_page = 0
        self._populate_table()

    def _go_to_page(self, page: int):
        """Navigate to specific page."""
        if 0 <= page < self.total_pages:
            self.current_page = page
            self._populate_table()

    def _on_page_input(self):
        """Handle manual page input."""
        try:
            page = int(self.page_input.text()) - 1  # Convert to 0-indexed
            self._go_to_page(page)
        except ValueError:
            self.page_input.setText(str(self.current_page + 1))

    def _update_pagination(self):
        """Update pagination controls."""
        total = len(self.filtered_iocs)
        if self.rows_per_page > 0:
            self.total_pages = max(1, (total + self.rows_per_page - 1) // self.rows_per_page)
        else:
            self.total_pages = 1

        # Update labels
        self.page_info_label.setText(f"Page {self.current_page + 1} of {self.total_pages}")
        self.page_input.setText(str(self.current_page + 1))
        self.total_label.setText(f"{total:,} IOCs")

        # Enable/disable navigation buttons
        self.btn_first.setEnabled(self.current_page > 0)
        self.btn_prev.setEnabled(self.current_page > 0)
        self.btn_next.setEnabled(self.current_page < self.total_pages - 1)
        self.btn_last.setEnabled(self.current_page < self.total_pages - 1)

    # =========================================================================
    # CONTEXT MENU & COPY METHODS
    # =========================================================================

    def _show_context_menu(self, position):
        """Show context menu for table row."""
        row = self.ioc_table.rowAt(position.y())
        if row < 0:
            return

        type_item = self.ioc_table.item(row, 0)
        if not type_item:
            return

        ioc = type_item.data(Qt.UserRole)
        if not ioc:
            return

        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #3d444d;
                border: 1px solid #484f58;
                border-radius: 6px;
                padding: 4px;
            }
            QMenu::item {
                padding: 8px 20px;
                color: #f0f6fc;
                font-size: 13px;
            }
            QMenu::item:selected {
                background-color: #58a6ff;
                color: white;
                border-radius: 4px;
            }
            QMenu::separator {
                height: 1px;
                background-color: #484f58;
                margin: 4px 8px;
            }
        """)

        # Copy actions
        copy_value_action = menu.addAction("📋 Copy Value")
        copy_row_action = menu.addAction("📋 Copy Row")
        menu.addSeparator()

        # Lookup actions based on IOC type
        lookup_vt_action = None
        lookup_abuseipdb_action = None
        lookup_shodan_action = None

        if ioc.ioc_type == "IP":
            lookup_vt_action = menu.addAction("🔍 Lookup on VirusTotal")
            lookup_abuseipdb_action = menu.addAction("🔍 Lookup on AbuseIPDB")
            lookup_shodan_action = menu.addAction("🔍 Lookup on Shodan")
        elif ioc.ioc_type == "HASH":
            lookup_vt_action = menu.addAction("🔍 Lookup on VirusTotal")
        elif ioc.ioc_type == "DOMAIN":
            lookup_vt_action = menu.addAction("🔍 Lookup on VirusTotal")
        elif ioc.ioc_type == "URL":
            lookup_vt_action = menu.addAction("🔍 Lookup on VirusTotal")
        elif ioc.ioc_type == "MITRE_TECHNIQUE":
            lookup_mitre_action = menu.addAction("🔍 View on MITRE ATT&CK")

        menu.addSeparator()
        view_details_action = menu.addAction("📄 View Details")

        # Execute menu
        action = menu.exec_(self.ioc_table.viewport().mapToGlobal(position))

        if action == copy_value_action:
            self._copy_to_clipboard(ioc.value)
        elif action == copy_row_action:
            self._copy_row_to_clipboard(row)
        elif action == view_details_action:
            self._on_row_selected()
        elif lookup_vt_action and action == lookup_vt_action:
            self._lookup_virustotal(ioc)
        elif lookup_abuseipdb_action and action == lookup_abuseipdb_action:
            self._lookup_abuseipdb(ioc)
        elif lookup_shodan_action and action == lookup_shodan_action:
            self._lookup_shodan(ioc)
        elif ioc.ioc_type == "MITRE_TECHNIQUE" and action:
            if "MITRE" in action.text():
                self._lookup_mitre(ioc)

    def _on_cell_double_click(self, row: int, col: int):
        """Handle double-click on cell - copy value to clipboard."""
        if col == 1:  # Value column
            type_item = self.ioc_table.item(row, 0)
            if type_item:
                ioc = type_item.data(Qt.UserRole)
                if ioc:
                    self._copy_to_clipboard(ioc.value)
                    return

        # For other columns, copy cell text
        item = self.ioc_table.item(row, col)
        if item:
            self._copy_to_clipboard(item.text())

    def _copy_to_clipboard(self, text: str):
        """Copy text to clipboard with visual feedback."""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        # Show brief notification in status or tooltip
        self.total_label.setText("✓ Copied!")
        # Reset after delay (use QTimer in production)
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(1500, self._update_pagination)

    def _copy_row_to_clipboard(self, row: int):
        """Copy entire row to clipboard as tab-separated values."""
        values = []
        for col in range(self.ioc_table.columnCount()):
            item = self.ioc_table.item(row, col)
            values.append(item.text() if item else "")
        self._copy_to_clipboard("\t".join(values))

    def _external_lookup_allowed(self, ioc) -> bool:
        """Internal / private addresses are never sent to third-party sites."""
        if ioc.ioc_type == "IP" and _is_internal_ip(str(ioc.value)):
            QMessageBox.information(
                self, "Lookup skipped",
                "This is a private / internal address. It has no public reputation "
                "and is not sent to external services.")
            return False
        return True

    def _lookup_virustotal(self, ioc):
        """Open VirusTotal lookup for IOC."""
        if not self._external_lookup_allowed(ioc):
            return
        value = urllib.parse.quote(str(ioc.value), safe="")
        base_url = "https://www.virustotal.com/gui/"
        if ioc.ioc_type == "IP":
            url = f"{base_url}ip-address/{value}"
        elif ioc.ioc_type == "HASH":
            url = f"{base_url}file/{value}"
        elif ioc.ioc_type == "DOMAIN":
            url = f"{base_url}domain/{value}"
        elif ioc.ioc_type == "URL":
            encoded = urllib.parse.quote_plus(str(ioc.value))
            url = f"{base_url}url/{encoded}"
        else:
            url = f"{base_url}search/{value}"

        QDesktopServices.openUrl(QUrl(url))

    def _lookup_abuseipdb(self, ioc):
        """Open AbuseIPDB lookup for IP."""
        if ioc.ioc_type == "IP" and self._external_lookup_allowed(ioc):
            url = f"https://www.abuseipdb.com/check/{urllib.parse.quote(str(ioc.value), safe='')}"
            QDesktopServices.openUrl(QUrl(url))

    def _lookup_shodan(self, ioc):
        """Open Shodan lookup for IP."""
        if ioc.ioc_type == "IP" and self._external_lookup_allowed(ioc):
            url = f"https://www.shodan.io/host/{urllib.parse.quote(str(ioc.value), safe='')}"
            QDesktopServices.openUrl(QUrl(url))

    def _lookup_mitre(self, ioc):
        """Open MITRE ATT&CK page for technique."""
        # Extract technique ID (e.g., T1059 from "T1059 - Command and Scripting Interpreter")
        import re
        match = re.search(r'T\d{4}(?:\.\d{3})?', ioc.value)
        if match:
            tech_id = match.group(0)
            url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
            QDesktopServices.openUrl(QUrl(url))

    def _build_detail_html(self, ioc: IOCRecord) -> str:
        """Build HTML for IOC detail panel."""
        sev_bg, sev_text = SEVERITY_COLORS.get(ioc.severity, ("#f3f4f6", "#6b7280"))

        parts = ["""
        <style>
            body { font-family: 'Inter', 'Segoe UI', sans-serif; margin: 0; font-size: 14px; background-color: #2d333b; color: #ffffff; }
            .header { font-size: 16px; font-weight: 700; color: #58a6ff; margin-bottom: 12px; }
            .badge { display: inline-block; padding: 4px 12px; border-radius: 6px;
                     font-size: 12px; font-weight: 700; }
            .field { margin: 8px 0; line-height: 1.5; }
            .label { font-weight: 700; color: #58a6ff; }
            .value { color: #ffffff; }
        </style>
        """]

        # Header
        parts.append(f"""
        <div class='header'>
            {IOC_TYPE_ICONS.get(ioc.ioc_type, '•')} {_html.escape(str(ioc.ioc_type))}: {_html.escape(str(ioc.value)[:80])}
            <span class='badge' style='background:{sev_bg}; color:{sev_text}; margin-left:8px;'>
                {_html.escape(str(ioc.severity))}
            </span>
        </div>
        """)

        # Description
        desc = _html.escape(str(ioc.description or ''))
        if desc:
            parts.append(f"<div class='field'><span class='value'>{desc}</span></div>")

        # Temporal info
        try:
            first_dt = datetime.fromtimestamp(ioc.first_seen).strftime("%Y-%m-%d %H:%M:%S") if ioc.first_seen > 0 else "N/A"
            last_dt = datetime.fromtimestamp(ioc.last_seen).strftime("%Y-%m-%d %H:%M:%S") if ioc.last_seen > 0 else "N/A"
        except:
            first_dt = "Invalid"
            last_dt = "Invalid"

        parts.append(f"""
        <div class='field'>
            <span class='label'>First Seen:</span> <span class='value'>{first_dt}</span> |
            <span class='label'>Last Seen:</span> <span class='value'>{last_dt}</span> |
            <span class='label'>Occurrences:</span> <span class='value'>{ioc.occurrences}</span>
        </div>
        """)

        # Context
        if ioc.context:
            parts.append(f"<div class='field'><span class='label'>Context:</span> <span class='value'>{_html.escape(str(ioc.context))}</span></div>")

        # Risk score (for IPs)
        if ioc.risk_score > 0:
            parts.append(f"<div class='field'><span class='label'>Risk Score:</span> <span class='value'>{ioc.risk_score:.2f}</span></div>")

        # Associated IPs
        if ioc.associated_ips:
            ips_str = _html.escape(", ".join(map(str, ioc.associated_ips[:10])))
            if len(ioc.associated_ips) > 10:
                ips_str += f" +{len(ioc.associated_ips)-10} more"
            parts.append(f"<div class='field'><span class='label'>Associated IPs:</span> <span class='value'>{ips_str}</span></div>")

        # MITRE Techniques
        if ioc.techniques:
            tech_str = _html.escape(", ".join(map(str, ioc.techniques[:10])))
            parts.append(f"<div class='field'><span class='label'>MITRE Techniques:</span> <span class='value'>{tech_str}</span></div>")

        # Payload preview (for hashes)
        if ioc.payload_preview:
            preview = _html.escape(str(ioc.payload_preview)[:200])
            parts.append(f"<div class='field'><span class='label'>Payload Preview:</span><br/><code style='font-size:11px; color:#58a6ff; background:#3d444d; padding:4px 8px; border-radius:4px;'>{preview}</code></div>")

        return "".join(parts)

    def _show_empty_state(self):
        """Show empty state when no IOCs available."""
        self.card_total.set_value("0")
        self.card_ips.set_value("0")
        self.card_hashes.set_value("0")
        self.card_techniques.set_value("0")
        self.card_critical.set_value("0")

        self.ioc_table.setRowCount(1)
        item = QTableWidgetItem("No IOCs extracted yet. Import a PCAP file to begin analysis.")
        item.setTextAlignment(Qt.AlignCenter)
        item.setForeground(QColor("#94a3b8"))
        self.ioc_table.setItem(0, 0, item)
        self.ioc_table.setSpan(0, 0, 1, 7)

    def _get_file_dialog_stylesheet(self) -> str:
        """Return stylesheet for file dialogs - SOC dark theme."""
        return """
            QFileDialog {
                background-color: #3d444d;
                color: #f0f6fc;
            }
            QFileDialog QWidget {
                background-color: #3d444d;
                color: #f0f6fc;
            }
            QFileDialog QListView, QFileDialog QTreeView {
                background-color: #3d444d;
                alternate-background-color: #484f58;
                color: #f0f6fc;
                border: 1px solid #484f58;
                border-radius: 6px;
                selection-background-color: #58a6ff;
            }
            QFileDialog QListView::item, QFileDialog QTreeView::item {
                color: #f0f6fc;
                padding: 8px 6px;
                min-height: 28px;
            }
            QFileDialog QListView::item:selected, QFileDialog QTreeView::item:selected {
                background-color: #58a6ff;
                color: #ffffff;
            }
            QFileDialog QListView::item:hover, QFileDialog QTreeView::item:hover {
                background-color: #484f58;
            }
            QFileDialog QLabel {
                color: #f0f6fc;
                background-color: transparent;
                font-size: 13px;
            }
            QFileDialog QLineEdit {
                background-color: #484f58;
                color: #f0f6fc;
                border: 2px solid #6e7681;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 14px;
                selection-background-color: #58a6ff;
            }
            QFileDialog QLineEdit:focus {
                border-color: #58a6ff;
            }
            QFileDialog QComboBox {
                background-color: #484f58;
                color: #f0f6fc;
                border: 2px solid #6e7681;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 13px;
            }
            QFileDialog QComboBox:hover {
                border-color: #58a6ff;
            }
            QFileDialog QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QFileDialog QComboBox QAbstractItemView {
                background-color: #484f58;
                color: #f0f6fc;
                border: 1px solid #6e7681;
                selection-background-color: #58a6ff;
            }
            QFileDialog QToolButton {
                background-color: #484f58;
                border: 1px solid #6e7681;
                border-radius: 6px;
                padding: 8px;
                color: #f0f6fc;
            }
            QFileDialog QToolButton:hover {
                background-color: #6e7681;
                border-color: #58a6ff;
            }
            QFileDialog QPushButton {
                background-color: #484f58;
                color: #f0f6fc;
                border: 2px solid #6e7681;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 13px;
            }
            QFileDialog QPushButton:hover {
                background-color: #6e7681;
                border-color: #58a6ff;
            }
            QFileDialog QPushButton:pressed {
                background-color: #58a6ff;
                color: #ffffff;
            }
            QFileDialog QHeaderView::section {
                background-color: #3d444d;
                color: #e6edf3;
                border: none;
                border-bottom: 2px solid #6e7681;
                padding: 10px;
                font-weight: 700;
                font-size: 12px;
            }
            QFileDialog QSplitter::handle {
                background-color: #6e7681;
            }
            QFileDialog QFrame {
                background-color: #3d444d;
            }
            QFileDialog QScrollBar:vertical {
                background-color: #3d444d;
                width: 12px;
                border-radius: 6px;
            }
            QFileDialog QScrollBar::handle:vertical {
                background-color: #6e7681;
                border-radius: 6px;
                min-height: 30px;
            }
            QFileDialog QScrollBar::handle:vertical:hover {
                background-color: #58a6ff;
            }
        """

    def _export_json(self):
        """Export IOCs to JSON file."""
        if not self.iocs or not any(self.iocs.values()):
            return

        dialog = QFileDialog(
            self,
            "Export IOCs to JSON",
            f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)"
        )
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setStyleSheet(self._get_file_dialog_stylesheet())

        if dialog.exec_() != QFileDialog.Accepted:
            return
        filepath = dialog.selectedFiles()[0] if dialog.selectedFiles() else None

        if not filepath:
            return

        try:
            collector = IOCCollector()
            pcap_file = ""
            if self.analyzer and hasattr(self.analyzer, 'pcap_path'):
                pcap_file = self.analyzer.pcap_path

            collector.export_to_json(self.iocs, filepath, pcap_file=pcap_file)
            print(f"IOCs exported to {filepath}")
        except Exception as e:
            print(f"Error exporting JSON: {e}")

    def _export_csv(self):
        """Export IOCs to CSV file."""
        if not self.iocs or not any(self.iocs.values()):
            return

        dialog = QFileDialog(
            self,
            "Export IOCs to CSV",
            f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)"
        )
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setStyleSheet(self._get_file_dialog_stylesheet())

        if dialog.exec_() != QFileDialog.Accepted:
            return
        filepath = dialog.selectedFiles()[0] if dialog.selectedFiles() else None

        if not filepath:
            return

        try:
            collector = IOCCollector()
            collector.export_to_csv(self.iocs, filepath)
            print(f"IOCs exported to {filepath}")
        except Exception as e:
            print(f"Error exporting CSV: {e}")
