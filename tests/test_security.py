"""Security regression tests: data from captures is attacker-controlled."""
import csv
import json
import os
import stat
import sys

import pytest

from ot_pcap_analyzer import threat_intel as ti
from ot_pcap_analyzer.ioc_models import IOCRecord
from ot_pcap_analyzer.report_export import _excel_safe_value
from ot_pcap_analyzer.threat_intel import ThreatIntelligence
from ot_pcap_analyzer.utils import is_internal_ip, neutralize_formula


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setattr(ti.time, "sleep", lambda s: None)


# --------------------------------------------------------------- formula injection

@pytest.mark.parametrize("value", [
    '=HYPERLINK("http://evil","x")', "+cmd|' /C calc'!A0", "-2+3+cmd|' /C calc'!A0",
    "@SUM(1+1)*cmd|' /C calc'!A0", "\t=1+1", "\r=1+1", "＝1+1",
])
def test_formula_values_are_neutralized(value):
    out = neutralize_formula(value)
    assert out == "'" + value


@pytest.mark.parametrize("value", ["-12.5", "+3", "1e5", "-", "normal text", "", "10.0.0.1", 42, None])
def test_harmless_values_are_unchanged(value):
    assert neutralize_formula(value) == value


def test_excel_export_neutralizes_formulas():
    assert _excel_safe_value("=1+1") == "'=1+1"
    assert _excel_safe_value("GET /index.html") == "GET /index.html"


def test_ioc_csv_export_neutralizes_formulas(tmp_path):
    from ot_pcap_analyzer.ioc_collector import IOCCollector
    rec = IOCRecord(ioc_type="URL", value='=HYPERLINK("http://evil")', severity="HIGH",
                    first_seen=1.0, last_seen=2.0, occurrences=1, context="@ctx",
                    description="+desc")
    out = tmp_path / "iocs.csv"
    IOCCollector().export_to_csv({"URL": [rec]}, str(out))
    rows = list(csv.reader(out.open(encoding="utf-8")))
    data = rows[1]
    assert data[1] == "'=HYPERLINK(\"http://evil\")"
    assert data[7] == "'@ctx"
    assert data[-1] == "'+desc"


# --------------------------------------------------------------- threat intel privacy

class _Recorder:
    def __init__(self):
        self.urls = []

    def __call__(self, url, headers=None, timeout=10):
        self.urls.append(url)
        return None


def _online_intel(monkeypatch):
    intel = ThreatIntelligence(enable_online=True)
    intel.api_keys = {"virustotal": "k", "abuseipdb": "k"}
    rec = _Recorder()
    monkeypatch.setattr(intel, "_make_request", rec)
    return intel, rec


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.10", "172.16.4.4", "127.0.0.1",
                                "169.254.1.1", "fe80::1", "not-an-ip", "8.8.8.8/../x"])
def test_internal_or_invalid_ips_never_leave_the_host(monkeypatch, ip):
    intel, rec = _online_intel(monkeypatch)
    intel.check_ip(ip, use_cache=False)
    assert rec.urls == []


def test_public_ip_is_looked_up(monkeypatch):
    intel, rec = _online_intel(monkeypatch)
    intel.check_ip("8.8.8.8", use_cache=False)
    assert len(rec.urls) == 2


@pytest.mark.parametrize("domain", [
    "plc01.plant.local", "historian.corp", "scada", "hmi.lan", "dc01.internal",
    "router.home.arpa", "1.0.168.192.in-addr.arpa", "evil.com/../../users/me",
    "evil.com?x=1", "a b.com", "",
])
def test_internal_or_malformed_domains_never_leave_the_host(monkeypatch, domain):
    intel, rec = _online_intel(monkeypatch)
    intel.check_domain(domain, use_cache=False)
    assert rec.urls == []


def test_public_domain_is_looked_up(monkeypatch):
    intel, rec = _online_intel(monkeypatch)
    intel.check_domain("Example-Malware.COM.", use_cache=False)
    assert rec.urls == ["https://www.virustotal.com/api/v3/domains/example-malware.com"]


@pytest.mark.parametrize("value", ["abc", "../files", "g" * 64, "d41d8cd98f00b204e9800998ecf8427e/x"])
def test_malformed_hashes_never_reach_the_api(monkeypatch, value):
    intel, rec = _online_intel(monkeypatch)
    intel.check_hash(value, use_cache=False)
    assert rec.urls == []


def test_valid_hash_is_looked_up(monkeypatch):
    intel, rec = _online_intel(monkeypatch)
    intel.check_hash("D41D8CD98F00B204E9800998ECF8427E", use_cache=False)
    assert rec.urls == ["https://www.virustotal.com/api/v3/files/d41d8cd98f00b204e9800998ecf8427e"]


def test_is_internal_ip():
    assert is_internal_ip("10.1.2.3") and is_internal_ip("garbage")
    assert not is_internal_ip("1.1.1.1")


@pytest.mark.parametrize("content", ['["k"]', '"k"', "123", "{bad json"])
def test_malformed_api_key_file_is_ignored(tmp_path, content):
    f = tmp_path / "keys.json"
    f.write_text(content)
    intel = ThreatIntelligence(enable_online=False)
    intel.load_api_keys_from_file(str(f))  # must not raise
    assert intel.api_keys == {}


def test_local_feed_entries_cannot_inject_lines(tmp_path):
    feed = ti.LocalThreatFeed(feed_dir=tmp_path)
    feed.malicious_domains["evil.example"] = {
        "type": "USER_ADDED", "severity": "HIGH", "description": "x\n1.2.3.4,CRITICAL,forged"}
    feed._save_feed("domain")
    lines = [l for l in (tmp_path / "malicious_domains.txt").read_text().splitlines()
             if l and not l.startswith("#")]
    assert len(lines) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_private_directories_are_owner_only(tmp_path):
    cache = ti.ThreatIntelCache()
    assert stat.S_IMODE(os.stat(cache.cache_dir).st_mode) & 0o077 == 0


# --------------------------------------------------------------- GUI HTML injection

QtWidgets = None


@pytest.fixture
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    global QtWidgets
    QtWidgets = pytest.importorskip("PyQt5.QtWidgets")
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)


PAYLOAD = "<img src='file:///etc/passwd'><b>FAKE</b>"


def test_ioc_detail_html_escapes_capture_data(qapp):
    from ot_pcap_analyzer.ioc_panel import IOCPanel
    rec = IOCRecord(ioc_type="URL", value=PAYLOAD, severity="HIGH", first_seen=1.0,
                    last_seen=2.0, occurrences=1, context=PAYLOAD, description=PAYLOAD,
                    associated_ips=[PAYLOAD], techniques=[PAYLOAD])
    rec.payload_preview = PAYLOAD
    html = IOCPanel()._build_detail_html(rec)
    assert "<img" not in html and "<b>FAKE" not in html
    assert "&lt;img" in html


def test_external_lookup_skips_internal_ip(qapp, monkeypatch):
    from ot_pcap_analyzer import ioc_panel
    opened, shown = [], []
    monkeypatch.setattr(ioc_panel.QDesktopServices, "openUrl", lambda u: opened.append(u.toString()))
    monkeypatch.setattr(ioc_panel.QMessageBox, "information", lambda *a, **k: shown.append(a))
    panel = ioc_panel.IOCPanel()
    internal = IOCRecord(ioc_type="IP", value="10.0.0.5", severity="LOW",
                         first_seen=0, last_seen=0, occurrences=1, context="")
    panel._lookup_virustotal(internal)
    panel._lookup_abuseipdb(internal)
    panel._lookup_shodan(internal)
    assert opened == [] and len(shown) == 3
    weird = IOCRecord(ioc_type="DOMAIN", value="evil.com/../../x?y", severity="LOW",
                      first_seen=0, last_seen=0, occurrences=1, context="")
    panel._lookup_virustotal(weird)
    assert opened and "/../" not in opened[0] and "?" not in opened[0].split("/gui/")[1]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_saved_api_keys_are_owner_only(qapp, monkeypatch, tmp_path):
    from pathlib import Path
    from ot_pcap_analyzer import intel_db_panels as p
    monkeypatch.setattr(p.QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(p.QMessageBox, "critical", lambda *a, **k: pytest.fail(a))
    panel = p.ThreatIntelPanel()
    panel.vt_key_input.setText("secret-vt")
    panel._save_api_keys()
    f = Path.home() / ".ot_pcap_analyzer" / "api_keys.json"
    assert json.loads(f.read_text()) == {"virustotal": "secret-vt"}
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
