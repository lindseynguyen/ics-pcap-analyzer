"""Offscreen GUI smoke test: build the main window and load a finished analysis."""
import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PyQt5.QtWidgets")


@pytest.fixture(scope="module")
def qapp():
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    yield app


def test_main_window_loads_analysis(qapp, analyzed, monkeypatch):
    errors = []
    monkeypatch.setattr(sys, "excepthook", lambda t, v, tb: errors.append((t, v)))
    monkeypatch.setattr(QtWidgets.QMessageBox, "exec_", lambda self: 0)
    from ot_pcap_analyzer import gui
    w = gui.MainWindow()
    w.show()
    qapp.processEvents()
    w.analyzer = analyzed["attacks"]
    w.worker = None
    w.on_analysis_complete()
    for _ in range(30):
        qapp.processEvents()
    if hasattr(w, "assets_view") and getattr(w.assets_view, "assets_data", None):
        w.assets_view._show_asset_detail_on_double_click_row(0)
    if hasattr(w, "incidents_view"):
        for chain in list(getattr(w.incidents_view, "_chains", []))[:3]:
            w.incidents_view._on_chain_selected(chain)
    qapp.processEvents()
    w.close()
    qapp.processEvents()
    assert errors == []


def test_every_view_navigation_theme_and_paging(qapp, analyzed, monkeypatch, tmp_path):
    errors = []
    monkeypatch.setattr(sys, "excepthook", lambda t, v, tb: errors.append((t, v)))
    monkeypatch.setattr(QtWidgets.QMessageBox, "exec_", lambda self: 0)
    for name in ("information", "warning", "critical", "question"):
        monkeypatch.setattr(QtWidgets.QMessageBox, name, staticmethod(lambda *a, **k: 0))
    from ot_pcap_analyzer import gui
    w = gui.MainWindow()
    w.show()
    w.analyzer = analyzed["attacks"]
    w.worker = None
    w.on_analysis_complete()
    qapp.processEvents()
    # visit every page of the stacked content
    stack = next(iter(w.findChildren(QtWidgets.QStackedWidget)), None)
    if stack is not None:
        for i in range(stack.count()):
            w._navigate_to_view(i)
            qapp.processEvents()
    # theme switching both ways
    w._toggle_theme()
    w._toggle_theme()
    # filters and paging on the large tables
    for view in (w.anomalies_view, w.ot_events_view):
        view._apply_filter()
        view._go_to_page(1)
        view._go_to_page(0)
    w.assets_view._apply_filters()
    # global search
    w._focus_search()
    w._on_search_closed()
    w._refresh_current_view()
    qapp.processEvents()
    w.close()
    qapp.processEvents()
    assert errors == []
