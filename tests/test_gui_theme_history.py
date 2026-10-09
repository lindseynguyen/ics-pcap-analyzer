"""Theme engine (light/dark) and scan-history management."""
import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from ot_pcap_analyzer.database import AnalysisDatabase
from ot_pcap_analyzer.gui_style import PALETTES, ThemeEngine


# ----------------------------------------------------------------- theme engine

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_tokens_map_to_same_token_in_other_theme(theme):
    other = "light" if theme == "dark" else "dark"
    engine = ThemeEngine(theme)
    for name in ("app_bg", "surface_2", "border", "text_2", "critical", "accent", "purple"):
        assert engine.map_color(PALETTES[other][name], "bg" if name in ("app_bg", "surface_2") else "fg") \
            == PALETTES[theme][name]


def test_legacy_dark_colours_follow_light_theme():
    e = ThemeEngine("light")
    assert e.map_color("#1c2128", "bg") == PALETTES["light"]["app_bg"]
    assert e.map_color("#252b33", "bg") == PALETTES["light"]["surface"]
    assert e.map_color("#f0f6fc", "fg") == PALETTES["light"]["text"]
    assert e.map_color("#ff6b6b", "fg") == PALETTES["light"]["critical"]
    # dark tinted background becomes a light tint, not a dark block
    tint = e.map_color("#4a2020", "bg")
    assert int(tint[1:3], 16) > 0xE0


def test_white_text_stays_white_on_coloured_buttons():
    e = ThemeEngine("light")
    css = e.translate_css("QPushButton { background-color: #1f6feb; color: #ffffff; }")
    assert "color: #ffffff" in css
    assert "color: " + PALETTES["light"]["text"] in e.translate_css("QLabel { color: #ffffff; }")


def test_css_alpha_hex_becomes_rgba_and_html_is_opaque():
    e = ThemeEngine("dark")
    assert "rgba(" in e.translate_css("background-color: #f8514920;")
    html = e.translate_html("<div style='background: #f8514920'>x</div>")
    assert "rgba" not in html and "#" in html


def test_container_box_styles_are_scoped(qapp):
    from PyQt5.QtWidgets import QFrame, QLabel
    from ot_pcap_analyzer import gui_style
    gui_style.install()
    frame = QFrame()
    frame.setStyleSheet("border: 1px solid #3d444d; color: #f0f6fc;")
    assert frame.styleSheet().startswith("* {")
    assert f"#{frame.objectName()} {{" in frame.styleSheet()
    label = QLabel("x")
    label.setStyleSheet("border: 1px solid #3d444d;")
    assert "{" not in label.styleSheet()


def test_main_window_switches_theme(qapp, analyzed, monkeypatch, tmp_path):
    from PyQt5 import QtWidgets
    from PyQt5.QtGui import QPalette
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in ("information", "warning", "critical", "question"):
        monkeypatch.setattr(QtWidgets.QMessageBox, name, staticmethod(lambda *a, **k: 0))
    from ot_pcap_analyzer import gui, gui_style
    w = gui.MainWindow()
    w.analyzer, w.worker = analyzed["attacks"], None
    w.on_analysis_complete()
    for theme in ("light", "dark", "light"):
        w.sidebar.set_theme(theme)
        qapp.processEvents()
        assert gui_style.ENGINE.theme == theme
        assert qapp.palette().color(QPalette.Window).name() == PALETTES[theme]["app_bg"]
        assert w.sidebar.theme_buttons[theme].isChecked()
    w.sidebar.set_theme("dark")
    w.close()


# ------------------------------------------------------------------- database

def _anomaly(kind="OT_WRITE", sev="HIGH", text="plant detail"):
    return SimpleNamespace(anomaly_type=kind, severity=sev, timestamp=1.0, src_ip="10.0.0.1",
                           dst_ip="10.0.0.2", src_port=1, dst_port=502, protocol="MODBUS",
                           description=text, confidence=0.9)


@pytest.fixture
def db(tmp_path):
    d = AnalysisDatabase(str(tmp_path / "h.db"))
    yield d
    d.close()


def test_delete_sessions_removes_children_and_data(db, tmp_path):
    a = db.create_session("a.pcap")
    b = db.create_session("b.pcap")
    db.store_anomalies(a, [_anomaly(text="SECRET-PLANT-123")])
    db.store_ioc(a, "IP", "203.0.113.9")
    assert db.delete_sessions([a]) == 1
    assert [s["id"] for s in db.list_sessions()] == [b]
    assert db.get_anomalies(session_id=a) == [] and db.get_iocs(session_id=a) == []
    db.close()
    assert b"SECRET-PLANT-123" not in (tmp_path / "h.db").read_bytes()


def test_delete_all_keeps_watchlist(db):
    db.create_session("a.pcap")
    db.add_to_watchlist("IP", "198.51.100.7")
    assert db.delete_all_sessions() == 1
    assert db.storage_info()["sessions"] == 0
    assert db.get_watchlist()


def test_purge_older_than(db):
    old = db.create_session("old.pcap")
    new = db.create_session("new.pcap")
    with db._get_connection() as conn:
        conn.execute("UPDATE sessions SET started_at = ? WHERE id = ?",
                     ((datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=40)).strftime("%Y-%m-%d %H:%M:%S"), old))
        conn.commit()
    assert db.purge_older_than(0) == 0
    assert db.purge_older_than(30) == 1
    assert [s["id"] for s in db.list_sessions()] == [new]
    assert [s["id"] for s in db.list_sessions(since_days=7)] == [new]


def test_search_escapes_wildcards(db):
    db.create_session("100%_done.pcap")
    db.create_session("other.pcap")
    assert [s["pcap_file"] for s in db.list_sessions("100%")] == ["100%_done.pcap"]
    assert len(db.list_sessions("%")) == 1


def test_compare_sessions(db):
    a, b = db.create_session("a.pcap"), db.create_session("b.pcap")
    db.store_anomalies(a, [_anomaly("SCAN"), _anomaly("OT_WRITE")])
    db.store_anomalies(b, [_anomaly("OT_WRITE"), _anomaly("OT_WRITE"), _anomaly("PLC_STOP", "CRITICAL")])
    db.store_ioc(b, "IP", "203.0.113.5")
    diff = db.compare_sessions(a, b)
    assert diff["new_types"] == ["PLC_STOP"]
    assert diff["resolved_types"] == ["SCAN"]
    assert diff["changed_types"] == [("OT_WRITE", 1, 2)]
    assert diff["new_iocs"] == [("IP", "203.0.113.5")]


# ---------------------------------------------------------------- history panel

@pytest.fixture
def panel(qapp, tmp_path, monkeypatch):
    from PyQt5.QtCore import QSettings
    from ot_pcap_analyzer.intel_db_panels import DatabaseHistoryPanel
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    database = AnalysisDatabase(str(tmp_path / "panel.db"))
    p = DatabaseHistoryPanel(database=database, settings=settings)
    yield p
    database.close()


def test_history_panel_store_select_compare_delete(panel, analyzed, captures, qapp, monkeypatch):
    sid1 = panel.store_analysis_results(analyzed["benign"], captures["benign"])
    sid2 = panel.store_analysis_results(analyzed["attacks"], captures["attacks"])
    assert sid1 and sid2
    qapp.processEvents()
    panel._load_sessions()
    table = panel.sessions_table
    assert table.rowCount() == 2

    # stored metadata and IOCs
    overview = panel.database.session_overview(sid2)
    assert overview["metadata"]["capture_path"] == os.path.abspath(captures["attacks"])
    assert overview["ioc_count"] > 0

    table.selectRow(0)
    qapp.processEvents()
    assert panel.detail_stack.currentIndex() == 1
    assert panel.reanalyze_btn.isEnabled()
    emitted = []
    panel.reanalyze_requested.connect(emitted.append)
    panel._reanalyze()
    assert emitted and os.path.isfile(emitted[0])

    from PyQt5.QtWidgets import QAbstractItemView
    table.setSelectionMode(QAbstractItemView.MultiSelection)
    table.selectRow(1)
    qapp.processEvents()
    assert panel.detail_stack.currentIndex() == 2
    assert "New alert types" in panel.compare_text.toPlainText()

    monkeypatch.setattr(panel, "_confirm", lambda *a: True)
    panel._delete_selected()
    assert panel.sessions_table.rowCount() == 0
    assert panel.database.storage_info()["sessions"] == 0


def test_history_can_be_turned_off(panel, analyzed, captures):
    panel.settings.setValue("history/enabled", "false")
    assert panel.store_analysis_results(analyzed["benign"], captures["benign"]) is None
    assert panel.database.storage_info()["sessions"] == 0
    panel._load_sessions()
    assert not panel.disabled_banner.isHidden()


def test_delete_all_needs_confirmation(panel, analyzed, captures, monkeypatch):
    panel.store_analysis_results(analyzed["benign"], captures["benign"])
    monkeypatch.setattr(panel, "_confirm", lambda *a: False)
    panel._delete_all()
    assert panel.database.storage_info()["sessions"] == 1
    monkeypatch.setattr(panel, "_confirm", lambda *a: True)
    panel._delete_all()
    assert panel.database.storage_info()["sessions"] == 0


@pytest.fixture(scope="module")
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt5.QtWidgets")
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
