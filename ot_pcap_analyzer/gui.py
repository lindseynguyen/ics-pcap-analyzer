"""
OT PCAP Analyzer - GUI (SOC-style)
=================================================
Professional SOC-style UI with:
- Vertical sidebar navigation
- Three-zone layout (top bar, sidebar, main content)
- Risk-first design approach
- Dark theme default
- Asset detail panel with right-side drawer
"""
from .attack_flow_widget import AttackFlowWidget

# Check for PyQt5 availability
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QProgressBar, QTabWidget, QFileDialog,
        QMessageBox, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
        QFrame, QGroupBox, QToolBar, QAction, QComboBox, QSlider,
        QStackedWidget, QSplitter, QListWidget, QListWidgetItem,
        QScrollArea, QSizePolicy, QSpacerItem, QLineEdit
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QSize, QPropertyAnimation, QEasingCurve
    from PyQt5.QtGui import QFont, QColor, QIcon, QPalette, QPainter, QBrush, QPen, QKeySequence
    from PyQt5.QtWidgets import QShortcut, QMenu, QApplication as QApp
    from PyQt5.QtWidgets import QGraphicsDropShadowEffect
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False

if HAS_PYQT5:
    from .version import VERSION
    from . import gui_style
    from .models import AnalyzerConfig
    from .analyzer import OTAnalyzer
    from .utils import timestamp, utc_str, logger

    # Try to import incident_tab, fallback if not available
    try:
        from .incident_tab import IncidentStoryWidget
        HAS_INCIDENT_TAB = True
    except ImportError as e:
        logger.warning(f"Incident tab not available: {e}")
        HAS_INCIDENT_TAB = False

    # Try to import IOC panel
    try:
        from .ioc_panel import IOCPanel
        HAS_IOC_PANEL = True
    except ImportError as e:
        logger.warning(f"IOC panel not available: {e}")
        HAS_IOC_PANEL = False

    # Try to import Threat Intelligence and Database panels
    try:
        from .intel_db_panels import ThreatIntelPanel, DatabaseHistoryPanel
        HAS_INTEL_DB = True
    except ImportError as e:
        logger.warning(f"Threat Intel/Database panels not available: {e}")
        HAS_INTEL_DB = False

    # Dummy widget for missing features
    if not HAS_INCIDENT_TAB:
        class IncidentStoryWidget(QWidget):
            def __init__(self, parent=None):
                super().__init__(parent)
                layout = QVBoxLayout(self)
                label = QLabel("Incident/Attack Story feature not available.")
                label.setAlignment(Qt.AlignCenter)
                layout.addWidget(label)
            def update_incident_view(self, analyzer):
                pass


    # View classes live in gui_theme / gui_widgets / gui_views; re-exported here
    from .gui_theme import SOCIcons, SOCThemeManager  # noqa: F401
    from .gui_widgets import (CompactMetric, RiskSummaryWidget, SidebarNavigation, TopBar, AnalysisWorker, GlobalSearchBar)  # noqa: F401
    from .gui_views import (AssetDetailPanel, AssetClassificationView, DashboardView, AnomaliesView, OTEventsView, MITREMatrixView)  # noqa: F401

    # =========================================================================
    # MAIN WINDOW - SOC Style with Sidebar Navigation
    # =========================================================================

    class MainWindow(QMainWindow):
        """Main application window with SOC-style UI"""

        def __init__(self):
            super().__init__()
            self.analyzer = None
            self.worker = None
            self.theme_manager = SOCThemeManager()
            self._views_filled = False
            gui_style.install()

            self.init_ui()

        def init_ui(self):
            """Initialize the UI"""
            self.setWindowTitle(f"ICS PCAP Analyzer {VERSION}")
            self.setMinimumSize(1200, 760)
            self.resize(1440, 900)

            # Setup keyboard shortcuts
            self._setup_keyboard_shortcuts()

            # Central widget
            central = QWidget()
            main_layout = QVBoxLayout(central)
            main_layout.setContentsMargins(0, 0, 0, 0)
            main_layout.setSpacing(0)

            # Top bar
            self.top_bar = TopBar(self.theme_manager)
            self.top_bar.import_clicked.connect(self.import_pcap)
            self.top_bar.export_clicked.connect(self.export_results)
            self.top_bar.cancel_clicked.connect(self.cancel_analysis)
            main_layout.addWidget(self.top_bar)

            # Global search bar (hidden by default, shown with Ctrl+F)
            self.search_bar = GlobalSearchBar(self.theme_manager)
            self.search_bar.closed.connect(self._on_search_closed)
            main_layout.addWidget(self.search_bar)

            # Content area (sidebar + main)
            content_area = QHBoxLayout()
            content_area.setContentsMargins(0, 0, 0, 0)
            content_area.setSpacing(0)

            # Sidebar navigation
            self.sidebar = SidebarNavigation(self.theme_manager, self)
            self.sidebar.navigation_changed.connect(self.on_navigation_changed)
            self.sidebar.theme_changed.connect(self.apply_theme)  # Connect theme signal
            content_area.addWidget(self.sidebar)

            # Main content - stacked widget
            self.content_stack = QStackedWidget()

            # Add all views
            self.dashboard_view = DashboardView(self.theme_manager)
            if hasattr(self.dashboard_view, "navigate_requested"):
                self.dashboard_view.navigate_requested.connect(self.sidebar.set_active_nav)
            self.content_stack.addWidget(self.dashboard_view)

            self.assets_view = AssetClassificationView(self.theme_manager)
            self.content_stack.addWidget(self.assets_view)

            self.attack_flow_view = AttackFlowWidget()
            self.content_stack.addWidget(self.attack_flow_view)

            # Threat Model - MITRE ATT&CK Matrix
            self.threat_model_view = MITREMatrixView(self.theme_manager)
            self.content_stack.addWidget(self.threat_model_view)

            self.anomalies_view = AnomaliesView(self.theme_manager)
            self.content_stack.addWidget(self.anomalies_view)

            self.ot_events_view = OTEventsView(self.theme_manager)
            self.content_stack.addWidget(self.ot_events_view)

            # IOC Panel
            if HAS_IOC_PANEL:
                self.ioc_view = IOCPanel()
            else:
                self.ioc_view = self._create_placeholder("IOC Analysis")
            self.content_stack.addWidget(self.ioc_view)

            # Incidents
            if HAS_INCIDENT_TAB:
                self.incidents_view = IncidentStoryWidget()
            else:
                self.incidents_view = self._create_placeholder("Incident Analysis")
            self.content_stack.addWidget(self.incidents_view)

            # Threat Intel
            if HAS_INTEL_DB:
                self.threat_intel_view = ThreatIntelPanel()
            else:
                self.threat_intel_view = self._create_placeholder("Threat Intelligence")
            self.content_stack.addWidget(self.threat_intel_view)

            # History
            if HAS_INTEL_DB:
                self.history_view = DatabaseHistoryPanel()
                if hasattr(self.history_view, "reanalyze_requested"):
                    self.history_view.reanalyze_requested.connect(self.start_analysis)
            else:
                self.history_view = self._create_placeholder("Analysis History")
            self.content_stack.addWidget(self.history_view)

            content_area.addWidget(self.content_stack, 1)

            content_widget = QWidget()
            content_widget.setLayout(content_area)
            main_layout.addWidget(content_widget)

            self.setCentralWidget(central)

            # Apply theme
            self.apply_theme()

            # Status bar
            self.statusBar().showMessage("Ready")

        def _setup_keyboard_shortcuts(self):
            """Setup global keyboard shortcuts for quick access"""
            # Ctrl+O: Open/Import PCAP file
            shortcut_open = QShortcut(QKeySequence("Ctrl+O"), self)
            shortcut_open.activated.connect(self.import_pcap)

            # Ctrl+E: Export results
            shortcut_export = QShortcut(QKeySequence("Ctrl+E"), self)
            shortcut_export.activated.connect(self.export_results)

            # Ctrl+Q: Quit application
            shortcut_quit = QShortcut(QKeySequence("Ctrl+Q"), self)
            shortcut_quit.activated.connect(self.close)

            # Ctrl+F: Focus search/filter (if available in current view)
            shortcut_find = QShortcut(QKeySequence("Ctrl+F"), self)
            shortcut_find.activated.connect(self._focus_search)

            # Escape: Cancel current operation or close detail panel
            shortcut_escape = QShortcut(QKeySequence("Escape"), self)
            shortcut_escape.activated.connect(self._handle_escape)

            # F5: Refresh current view
            shortcut_refresh = QShortcut(QKeySequence("F5"), self)
            shortcut_refresh.activated.connect(self._refresh_current_view)

            # Navigation shortcuts: Ctrl+1 through Ctrl+0 for quick view switching
            for i in range(10):
                key = str(i + 1) if i < 9 else "0"
                shortcut = QShortcut(QKeySequence(f"Ctrl+{key}"), self)
                shortcut.activated.connect(lambda idx=i: self._navigate_to_view(idx))

            # Ctrl+D: Toggle dark/light theme
            shortcut_theme = QShortcut(QKeySequence("Ctrl+D"), self)
            shortcut_theme.activated.connect(self._toggle_theme)

            # Ctrl+= / Ctrl++ / Ctrl+-: text size
            for seq, slot in (("Ctrl+=", "_on_zoom_in"), ("Ctrl++", "_on_zoom_in"), ("Ctrl+-", "_on_zoom_out")):
                sc = QShortcut(QKeySequence(seq), self)
                sc.activated.connect(lambda name=slot: getattr(self.sidebar, name)())

        def _focus_search(self):
            """Show global search bar with current view's table"""
            current_view = self.content_stack.currentWidget()

            # Find table in current view
            table = None
            if hasattr(current_view, 'table'):
                table = current_view.table
            elif hasattr(current_view, 'asset_table'):
                table = current_view.asset_table

            if table:
                self.search_bar.show_and_focus(table)
            else:
                # Fallback: focus filter input if no table found
                if hasattr(current_view, 'filter_input'):
                    current_view.filter_input.setFocus()
                    current_view.filter_input.selectAll()
                elif hasattr(current_view, 'search_input'):
                    current_view.search_input.setFocus()
                    current_view.search_input.selectAll()

        def _on_search_closed(self):
            """Handle search bar close"""
            # Return focus to the content
            self.content_stack.currentWidget().setFocus()

        def _handle_escape(self):
            """Handle Escape key - cancel operation or close panels"""
            # If search bar is visible, close it first
            if self.search_bar.isVisible():
                self.search_bar._close()
            # If analysis is running, offer to cancel
            elif self.worker and self.worker.isRunning():
                self.cancel_analysis()
            # If asset detail panel is open, close it
            elif hasattr(self, 'assets_view') and hasattr(self.assets_view, 'detail_panel'):
                if self.assets_view.detail_panel.isVisible():
                    self.assets_view.detail_panel.hide()

        def _refresh_current_view(self):
            """Refresh data in the current view"""
            if not self.analyzer:
                return
            current_view = self.content_stack.currentWidget()
            if hasattr(current_view, 'update_data'):
                current_view.update_data(self.analyzer)
            elif hasattr(current_view, 'update_anomalies'):
                current_view.update_anomalies(self.analyzer.anomalies)

        def _navigate_to_view(self, index: int):
            """Navigate to view by index (0-9)"""
            if 0 <= index < self.content_stack.count():
                self.content_stack.setCurrentIndex(index)
                self.sidebar.set_active_button(index)

        def _toggle_theme(self):
            """Toggle between dark and light theme"""
            if hasattr(self.sidebar, 'toggle_theme'):
                self.sidebar.toggle_theme()

        def _create_placeholder(self, title: str) -> QWidget:
            """Create placeholder widget for features not yet migrated"""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setAlignment(Qt.AlignCenter)

            label = QLabel(f"{title}\n\nFeature available after importing PCAP")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("color: #8b949e; font-size: 14px;")
            layout.addWidget(label)

            return widget

        def on_navigation_changed(self, index: int):
            """Handle sidebar navigation"""
            self.content_stack.setCurrentIndex(index)

        def apply_theme(self):
            """Apply the current theme (and font scale) to the whole application."""
            app = QApplication.instance()
            gui_style.install()
            gui_style.ENGINE.set_theme(self.theme_manager.current_theme)
            if app is not None:
                app.setPalette(gui_style.ENGINE.qpalette())
                app.setStyleSheet(self.theme_manager.get_stylesheet())
                gui_style.apply_theme(app)
            if hasattr(self, "top_bar"):
                self.top_bar.update_theme()

            # Update sidebar with theme colors and font scale
            if hasattr(self.sidebar, 'update_theme'):
                self.sidebar.update_theme()

            # Update child widgets
            all_views = [
                self.dashboard_view, self.assets_view, self.anomalies_view,
                self.ot_events_view, self.threat_model_view, self.attack_flow_view,
                self.ioc_view, self.incidents_view, self.threat_intel_view,
                self.history_view,
            ]
            for view in all_views:
                if hasattr(view, 'update_theme'):
                    view.update_theme()

            # Table and graph colours are set while the views are filled: refill them.
            worker_running = bool(self.worker and self.worker.isRunning())
            if self.analyzer is not None and not worker_running and getattr(self, "_views_filled", False):
                try:
                    self._populate_views(self.analyzer.get_summary(), show_progress=False)
                except Exception as e:  # never let a cosmetic refresh break the UI
                    logger.warning(f"Theme refresh failed: {e}")

        def _create_file_dialog(self, mode: str = "open", caption: str = "",
                                 directory: str = "", filter_str: str = "") -> QFileDialog:
            """
            Create a properly styled file dialog that works with dark theme.
            Uses Qt's non-native dialog to ensure consistent styling on Linux.
            """
            dialog = QFileDialog(self, caption, directory, filter_str)

            # Use Qt's built-in dialog instead of native OS dialog
            # This ensures our stylesheet is applied correctly
            dialog.setOption(QFileDialog.DontUseNativeDialog, True)

            if mode == "open":
                dialog.setFileMode(QFileDialog.ExistingFile)
                dialog.setAcceptMode(QFileDialog.AcceptOpen)
            elif mode == "save":
                dialog.setFileMode(QFileDialog.AnyFile)
                dialog.setAcceptMode(QFileDialog.AcceptSave)

            # Apply the current theme stylesheet to the dialog
            dialog.setStyleSheet(self.theme_manager.get_stylesheet())

            return dialog

        def import_pcap(self):
            """Import PCAP file"""
            # CRITICAL: Stop any running worker before starting a new analysis
            if self.worker and self.worker.isRunning():
                try:
                    # Disconnect signals first to prevent race conditions
                    self.worker.progress.disconnect()
                    self.worker.finished.disconnect()
                    self.worker.error.disconnect()
                except:
                    pass

                # Set running flag to False to stop safe_progress_callback
                self.worker._running = False

                # Set cancel flag on analyzer if available
                if self.analyzer and hasattr(self.analyzer, 'cancel_flag'):
                    self.analyzer.cancel_flag = True

                # Terminate and wait
                self.worker.terminate()
                self.worker.wait(3000)  # Wait max 3 seconds

                # Clean up old worker
                self.worker.deleteLater()
                self.worker = None

            dialog = self._create_file_dialog(
                mode="open",
                caption="Open PCAP/PCAPNG File",
                filter_str="PCAP Files (*.pcap *.pcapng);;All Files (*)"
            )

            if dialog.exec_() != QFileDialog.Accepted:
                return

            file_path = dialog.selectedFiles()[0] if dialog.selectedFiles() else None
            if not file_path:
                return
            self.start_analysis(file_path)

        def start_analysis(self, file_path: str):
            """Analyze ``file_path`` in a worker thread (used by Open and by Scan History)."""
            import os
            if self.worker and self.worker.isRunning():
                QMessageBox.information(self, "Analysis running",
                                        "Please wait for the current analysis to finish or cancel it.")
                return
            if not os.path.isfile(file_path):
                QMessageBox.warning(self, "File not found",
                                    f"The capture file is no longer available:\n{file_path}")
                return

            # Initialize analyzer (fresh instance for new analysis)
            config = AnalyzerConfig()
            self.analyzer = OTAnalyzer(config)

            # Start worker thread with Qt.QueuedConnection to ensure thread-safe UI updates
            self.worker = AnalysisWorker(self.analyzer, file_path)
            self.worker.progress.connect(self.on_progress, Qt.QueuedConnection)
            self.worker.finished.connect(self.on_analysis_complete, Qt.QueuedConnection)
            self.worker.error.connect(self.on_analysis_error, Qt.QueuedConnection)

            self.top_bar.set_status("Analyzing...", "processing")
            self.top_bar.btn_cancel.setEnabled(True)
            self.top_bar.btn_import.setEnabled(False)

            self.worker.start()

        def on_progress(self, current: int, total: int, message: str):
            """Update progress"""
            self.top_bar.set_progress(current, total, message)
            self.top_bar.set_status(f"Processing: {message}", "processing")

        def on_analysis_complete(self):
            """Handle analysis completion - populate views with processEvents to stay responsive"""
            # IMPORTANT: Ensure worker thread has fully finished before UI updates
            # Use waitForFinished pattern instead of wait() to avoid deadlocks
            if self.worker:
                # Disconnect signals first to prevent any race conditions
                try:
                    self.worker.progress.disconnect()
                    self.worker.finished.disconnect()
                    self.worker.error.disconnect()
                except:
                    pass

                # Ensure running flag is False
                self.worker._running = False

                # Wait for thread if still running
                if self.worker.isRunning():
                    self.worker.wait(5000)  # Wait max 5 seconds

                # Clear analyzer reference in worker to help GC
                self.worker.analyzer = None

            self.top_bar.btn_cancel.setEnabled(False)
            self.top_bar.btn_import.setEnabled(True)
            self.top_bar.btn_export.setEnabled(True)

            # Update PCAP info
            summary = self.analyzer.get_summary()
            self.top_bar.set_pcap_info(
                summary.get('CAPTURE_FILE', 'Unknown'),
                summary.get('PACKETS_PARSED', 0),
                summary.get('DURATION_STR', '-')
            )

            self._populate_views(summary)

            # Auto-enrich and DB save in background thread (avoid blocking GUI)
            if HAS_INTEL_DB:
                self._run_background_tasks(summary)

            self.top_bar.set_status("Analysis complete", "ready")
            self.top_bar.set_progress(0, 0, "")
            self.statusBar().showMessage(
                f"Analysis complete: {summary.get('PACKETS_PARSED', 0):,} packets, "
                f"{summary.get('ANOMALIES_DETECTED', 0)} anomalies detected"
            )

        def _populate_views(self, summary, show_progress: bool = True):
            """Fill every view from the current analyzer (also used after a theme switch)."""
            def step(message):
                if show_progress:
                    self.top_bar.set_status(message, "processing")
                QApplication.processEvents()
            # one view at a time, letting the UI breathe in between
            step("Populating dashboard...")
            self.dashboard_view.update_dashboard(summary)
            self.dashboard_view.update_alerts(self.analyzer.anomalies)

            step("Populating assets...")
            self.assets_view.update_assets(self.analyzer)

            step("Populating anomalies...")
            self.anomalies_view.update_anomalies(self.analyzer.anomalies)

            step("Populating OT events...")
            self.ot_events_view.update_events(self.analyzer.ot_events)

            step("Building attack flow...")
            if hasattr(self.attack_flow_view, 'update_from_analyzer'):
                self.attack_flow_view.update_from_analyzer(self.analyzer)
            elif hasattr(self.attack_flow_view, 'update_attack_flow'):
                chain = self.analyzer.attack_chains[0] if self.analyzer.attack_chains else None
                storyline = self.analyzer.storylines[0] if self.analyzer.storylines else None
                all_assets = self.analyzer.assets if hasattr(self.analyzer, 'assets') else None
                self.attack_flow_view.update_attack_flow(chain, storyline, all_assets)

            step("Extracting IOCs...")
            if HAS_IOC_PANEL and hasattr(self.ioc_view, 'update_iocs'):
                self.ioc_view.update_iocs(self.analyzer)

            step("Building incident stories...")
            if HAS_INCIDENT_TAB and hasattr(self.incidents_view, 'update_incident_view'):
                self.incidents_view.update_incident_view(self.analyzer)

            step("Building MITRE ATT&CK matrix...")
            if hasattr(self.threat_model_view, 'update_from_analyzer'):
                self.threat_model_view.update_from_analyzer(self.analyzer)

            self._views_filled = True

        def on_analysis_error(self, error_msg: str):
            """Handle analysis error"""
            # Clean up worker
            if self.worker:
                try:
                    self.worker.progress.disconnect()
                    self.worker.finished.disconnect()
                    self.worker.error.disconnect()
                except:
                    pass

                self.worker._running = False
                if self.worker.isRunning():
                    self.worker.wait(3000)
                self.worker.analyzer = None

            self.top_bar.set_status("Error occurred", "error")
            self.top_bar.btn_cancel.setEnabled(False)
            self.top_bar.btn_import.setEnabled(True)
            self.top_bar.set_progress(0, 0, "")

            QMessageBox.critical(self, "Analysis Error", error_msg)

        def _run_background_tasks(self, summary):
            """Run Threat Intel enrichment and DB save in background thread.

            IMPORTANT: This runs in a separate thread - do NOT access UI elements here.
            Only perform data operations (no widget updates).
            """
            import threading

            # Cache references to avoid accessing self from thread
            analyzer_anomalies = list(self.analyzer.anomalies) if self.analyzer else []
            analyzer_ref = self.analyzer
            pcap_file = getattr(self.analyzer, 'capture_path', '') or summary.get('CAPTURE_FILE', 'unknown')

            # Check if we have the required views (do this in main thread)
            has_threat_intel = hasattr(self, 'threat_intel_view') and hasattr(self.threat_intel_view, 'enrich_anomalies_data')
            has_history = hasattr(self, 'history_view') and hasattr(self.history_view, 'store_analysis_results')

            # Get references for thread-safe operations only
            history_view_ref = self.history_view if has_history else None

            def _bg_work():
                # NOTE: Do NOT access any UI widgets here!
                # Only perform data operations

                # Auto-save analysis results to database history (data-only operation)
                if history_view_ref and analyzer_ref:
                    try:
                        history_view_ref.store_analysis_results(analyzer_ref, pcap_file)
                    except Exception as e:
                        logger.warning(f"Database save failed: {e}")

            thread = threading.Thread(target=_bg_work, daemon=True)
            thread.start()

        def cancel_analysis(self):
            """Cancel running analysis"""
            if self.worker and self.worker.isRunning():
                # Disconnect signals first to prevent race conditions
                try:
                    self.worker.progress.disconnect()
                    self.worker.finished.disconnect()
                    self.worker.error.disconnect()
                except:
                    pass

                # Set cancel flag on analyzer if available
                if self.analyzer and hasattr(self.analyzer, 'cancel_flag'):
                    self.analyzer.cancel_flag = True

                self.worker.terminate()
                self.worker.wait(3000)  # Wait max 3 seconds

                self.top_bar.set_status("Analysis cancelled", "warning")
                self.top_bar.btn_cancel.setEnabled(False)
                self.top_bar.btn_import.setEnabled(True)

        def export_results(self):
            """Export analysis results"""
            if not self.analyzer:
                return

            dialog = self._create_file_dialog(
                mode="save",
                caption="Export Results",
                directory=f"ot_analysis_{timestamp()}.xlsx",
                filter_str="Excel Files (*.xlsx);;CSV Files (*.csv)"
            )

            if dialog.exec_() != QFileDialog.Accepted:
                return

            file_path = dialog.selectedFiles()[0] if dialog.selectedFiles() else None
            if file_path:
                try:
                    self.analyzer.export_excel(file_path)
                    QMessageBox.information(self, "Export Complete", f"Report saved to:\n{file_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", str(e))


    # =========================================================================
    # ENTRY POINT
    # =========================================================================

    def main():
        """Main entry point"""
        import sys
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        app.setApplicationName("ICS PCAP Analyzer")
        gui_style.install()

        window = MainWindow()
        window.show()
        sys.exit(app.exec_())

    def run_gui():
        """Run the GUI application - called by main.py"""
        main()


    # Legacy compatibility - keep ThemeManager alias
    ThemeManager = SOCThemeManager
