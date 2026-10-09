"""Behavioural tests for ot_pcap_analyzer.threat_intel (fully offline)."""
import io
import json
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from ot_pcap_analyzer import threat_intel as ti
from ot_pcap_analyzer.models import SecurityAnomaly, SuspiciousPayload
from ot_pcap_analyzer.threat_intel import LocalThreatFeed, ThreatIntelCache, ThreatIntelligence

INDUSTROYER_SHA1 = "d63e3614d75ad0b7d8cd8c8f77f8dd8da8d2e5e5"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Any real urlopen call is recorded; tests assert the list stays empty."""
    calls = []

    def _forbidden(*a, **kw):
        calls.append(a)
        raise AssertionError("network access attempted")

    monkeypatch.setattr(ti.urllib.request, "urlopen", _forbidden)
    monkeypatch.setattr(ti.time, "sleep", lambda s: None)  # rate limiter
    yield calls
    assert calls == [], "threat_intel tried to reach the network"


class _Clock:
    """Controllable replacement for threat_intel.datetime (now() only)."""

    def __init__(self, start):
        self.now_value = start
        clock = self

        class _DT(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock.now_value

        self.cls = _DT

    def advance(self, **kw):
        self.now_value = self.now_value + timedelta(**kw)


@pytest.fixture
def clock(monkeypatch):
    c = _Clock(datetime(2026, 10, 8, 12, 0, 0))
    monkeypatch.setattr(ti, "datetime", c.cls)
    return c


def _anomaly(src="10.0.0.5", dst="10.0.0.6", payload=None):
    return SecurityAnomaly(
        timestamp=1.0, anomaly_type="TEST", severity="HIGH", src_ip=src, dst_ip=dst,
        protocol="TCP", description="d", evidence={}, mitre_techniques=[], confidence=0.5,
        recommendation="r", extracted_payload=payload)


def _payload(sha):
    return SuspiciousPayload(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1,
                             dst_port=2, protocol="TCP", payload_type="BINARY",
                             payload_data=b"x", payload_preview="x",
                             detection_reason="test", sha256_hash=sha)


# --------------------------------------------------------------------------- cache

class TestCache:
    def test_set_get_roundtrip_and_file_persisted(self, tmp_path):
        c = ThreatIntelCache(cache_dir=tmp_path / "c", ttl_hours=1)
        assert c.get("ip", "1.2.3.4") is None
        c.set("ip", "1.2.3.4", {"is_malicious": True})
        assert c.get("ip", "1.2.3.4") == {"is_malicious": True}
        files = list((tmp_path / "c").glob("*.json"))
        assert len(files) == 1
        stored = json.loads(files[0].read_text())
        assert stored["category"] == "ip" and stored["value"] == "1.2.3.4"
        # Categories are part of the key
        assert c.get("domain", "1.2.3.4") is None

    def test_file_cache_survives_new_instance(self, tmp_path):
        ThreatIntelCache(cache_dir=tmp_path).set("hash", "abc", {"v": 1})
        fresh = ThreatIntelCache(cache_dir=tmp_path)
        assert fresh._memory_cache == {}
        assert fresh.get("hash", "abc") == {"v": 1}
        assert len(fresh._memory_cache) == 1  # promoted to memory

    def test_ttl_expiry_memory_and_file(self, tmp_path, clock):
        c = ThreatIntelCache(cache_dir=tmp_path, ttl_hours=2)
        c.set("ip", "8.8.8.8", {"ok": True})
        clock.advance(hours=1, minutes=59)
        assert c.get("ip", "8.8.8.8") == {"ok": True}
        assert ThreatIntelCache(cache_dir=tmp_path, ttl_hours=2).get("ip", "8.8.8.8") == {"ok": True}
        clock.advance(minutes=2)
        assert c.get("ip", "8.8.8.8") is None
        assert ThreatIntelCache(cache_dir=tmp_path, ttl_hours=2).get("ip", "8.8.8.8") is None

    def test_corrupt_cache_file_is_ignored(self, tmp_path):
        c = ThreatIntelCache(cache_dir=tmp_path)
        key = c._get_cache_key("ip", "9.9.9.9")
        (tmp_path / f"{key}.json").write_text("{not json")
        assert c.get("ip", "9.9.9.9") is None
        (tmp_path / f"{key}.json").write_text(json.dumps({"data": {}}))  # missing timestamp
        assert c.get("ip", "9.9.9.9") is None

    def test_clear(self, tmp_path):
        c = ThreatIntelCache(cache_dir=tmp_path)
        c.set("ip", "a", {"x": 1})
        c.set("ip", "b", {"x": 2})
        c.clear()
        assert c.get("ip", "a") is None and list(tmp_path.glob("*.json")) == []

    def test_write_failure_is_logged_not_raised(self, tmp_path, monkeypatch):
        c = ThreatIntelCache(cache_dir=tmp_path)

        def boom(*a, **kw):
            raise IOError("disk full")

        monkeypatch.setattr("builtins.open", boom)
        c.set("ip", "1.1.1.1", {"x": 1})  # must not raise
        monkeypatch.undo()
        assert c.get("ip", "1.1.1.1") == {"x": 1}  # memory cache still populated

    def test_default_dir_under_home(self):
        c = ThreatIntelCache()
        assert c.cache_dir == Path.home() / ".ot_pcap_analyzer" / "cache"
        assert c.cache_dir.is_dir()


# --------------------------------------------------------------------------- local feed

class TestLocalFeed:
    def test_builtin_ot_indicators(self, tmp_path):
        f = LocalThreatFeed(feed_dir=tmp_path)
        hit = f.check_hash(INDUSTROYER_SHA1.upper())
        assert hit["name"] == "Industroyer" and hit["severity"] == "CRITICAL"
        assert f.check_domain("update.microsoft-office365.com")["type"] == "C2_DOMAIN"
        assert f.check_ip("1.2.3.4") is None

    def test_load_user_feed_files(self, tmp_path):
        (tmp_path / "malicious_ips.txt").write_text(
            "# comment\n\n45.33.32.5,CRITICAL,Known C2\n198.51.100.7\n 192.0.2.1 , MEDIUM \n")
        (tmp_path / "malicious_hashes.txt").write_text("ABCDEF0123,LOW,test hash\n")
        (tmp_path / "malicious_domains.txt").write_text("Evil.Example,HIGH,phish\n")
        f = LocalThreatFeed(feed_dir=tmp_path)
        assert f.check_ip("45.33.32.5") == {"type": "USER_DEFINED", "severity": "CRITICAL",
                                             "description": "Known C2"}
        assert f.check_ip("198.51.100.7")["severity"] == "HIGH"
        assert f.check_ip("198.51.100.7")["description"] == "User-defined malicious IP"
        assert f.check_ip("192.0.2.1")["severity"] == "MEDIUM"
        assert f.check_hash("abcdef0123")["description"] == "test hash"
        assert f.check_domain("EVIL.example")["description"] == "phish"

    def test_domain_parent_matching(self, tmp_path):
        f = LocalThreatFeed(feed_dir=tmp_path)
        f.add_domain("evil.example", "HIGH", "parent")
        assert f.check_domain("a.b.evil.example")["description"] == "parent"
        assert f.check_domain("notevil.example") is None
        assert f.check_domain("example") is None

    def test_add_persists_and_reloads(self, tmp_path):
        f = LocalThreatFeed(feed_dir=tmp_path)
        f.add_ip("45.33.32.9", "CRITICAL", "scanner")
        f.add_hash("DEADBEEF", "MEDIUM")
        f.add_domain("Bad.Test")
        text = (tmp_path / "malicious_ips.txt").read_text()
        assert text.startswith("# IP threat feed")
        # Built-in indicators are never written to user files
        assert INDUSTROYER_SHA1 not in (tmp_path / "malicious_hashes.txt").read_text()
        g = LocalThreatFeed(feed_dir=tmp_path)
        assert g.check_ip("45.33.32.9")["severity"] == "CRITICAL"
        assert g.check_ip("45.33.32.9")["description"] == "scanner"
        assert g.check_hash("deadbeef")["description"] == "Added by user"
        assert g.check_domain("bad.test")["severity"] == "HIGH"

    # Regression test: _save_feed writes descriptions unquoted in a comma-separated file; reload splits on ',' and truncates them
    def test_description_with_comma_roundtrips(self, tmp_path):
        LocalThreatFeed(feed_dir=tmp_path).add_ip("45.33.32.9", "HIGH", "C2 server, APT33 campaign")
        assert LocalThreatFeed(feed_dir=tmp_path).check_ip("45.33.32.9")["description"] == \
            "C2 server, APT33 campaign"

    def test_save_unknown_type_is_noop(self, tmp_path):
        feeds = tmp_path / "feeds"
        f = LocalThreatFeed(feed_dir=feeds)
        f._save_feed("bogus")
        assert list(feeds.iterdir()) == []

    def test_unreadable_feed_file_logged(self, tmp_path):
        (tmp_path / "malicious_ips.txt").mkdir()  # a directory -> IOError on open
        (tmp_path / "malicious_hashes.txt").mkdir()
        (tmp_path / "malicious_domains.txt").mkdir()
        f = LocalThreatFeed(feed_dir=tmp_path)
        assert f.malicious_ips == {}


# --------------------------------------------------------------------------- offline intel

class TestThreatIntelligenceOffline:
    def test_unknown_ip_is_clean_and_cached(self):
        intel = ThreatIntelligence(enable_online=False)
        r = intel.check_ip("8.8.4.4")
        assert r["is_malicious"] is False and r["severity"] == "LOW" and r["sources"] == []
        again = intel.check_ip("8.8.4.4")
        assert again == r
        assert intel.stats["total_lookups"] == 2 and intel.stats["cache_hits"] == 1

    def test_local_feed_ip_hit(self):
        intel = ThreatIntelligence(enable_online=False)
        intel.local_feed.add_ip("45.33.32.50", "CRITICAL", "c2")
        r = intel.check_ip("45.33.32.50", use_cache=False)
        assert r["is_malicious"] and r["confidence"] == 0.95 and r["severity"] == "CRITICAL"
        assert r["sources"] == ["local_feed"]
        assert intel.stats["local_hits"] == 1 and intel.stats["malicious_found"] == 1
        assert intel.cache.get("ip", "45.33.32.50") is None  # use_cache=False skips writing

    def test_hash_lookup_builtin(self):
        intel = ThreatIntelligence(enable_online=False)
        r = intel.check_hash(INDUSTROYER_SHA1.upper())
        assert r["hash"] == INDUSTROYER_SHA1
        assert r["is_malicious"] and r["malware_name"] == "Industroyer" and r["severity"] == "CRITICAL"
        assert intel.check_hash(INDUSTROYER_SHA1)["malware_name"] == "Industroyer"
        assert intel.stats["cache_hits"] == 1
        clean = intel.check_hash("00" * 32)
        assert clean["is_malicious"] is False and clean["malware_name"] is None

    def test_domain_lookup(self):
        intel = ThreatIntelligence(enable_online=False)
        r = intel.check_domain("Login.Update.Microsoft-Office365.com")
        assert r["domain"] == "login.update.microsoft-office365.com"
        assert r["is_malicious"] and r["severity"] == "CRITICAL"
        assert intel.check_domain("example.org")["is_malicious"] is False
        intel.check_domain("example.org")
        assert intel.stats["cache_hits"] == 1

    def test_online_keys_ignored_when_offline(self, monkeypatch):
        intel = ThreatIntelligence(enable_online=False)
        intel.set_api_key("VirusTotal", "k")
        intel.set_api_key("abuseipdb", "k2")
        monkeypatch.setattr(intel, "_make_request", lambda *a, **k: pytest.fail("online call"))
        intel.check_ip("1.2.3.4")
        intel.check_hash("ab" * 16)
        intel.check_domain("x.test")
        assert intel.stats["api_calls"] == 0

    def test_enrich_anomaly(self):
        intel = ThreatIntelligence(enable_online=False)
        intel.local_feed.add_ip("45.33.32.50")
        intel.local_feed.add_ip("198.51.100.1")
        a = _anomaly(src="45.33.32.50", dst="198.51.100.1", payload=_payload(INDUSTROYER_SHA1))
        e = intel.enrich_anomaly(a)
        assert e["threat_intel_checked"] is True
        assert [(f["type"], f["value"]) for f in e["findings"]] == [
            ("ip", "45.33.32.50"), ("ip", "198.51.100.1"), ("hash", INDUSTROYER_SHA1)]

    def test_enrich_skips_placeholder_and_clean(self):
        intel = ThreatIntelligence(enable_online=False)
        intel.local_feed.add_ip("Multiple")  # would match if placeholder were looked up
        e = intel.enrich_anomaly(_anomaly(src="10.1.1.1", dst="Multiple", payload=_payload("")))
        assert e["findings"] == []
        assert intel.stats["total_lookups"] == 1  # only src_ip checked
        e2 = intel.enrich_anomaly(SimpleNamespace())  # no attributes at all
        assert e2 == {"threat_intel_checked": True, "findings": []}

    def test_get_stats(self):
        intel = ThreatIntelligence(enable_online=False)
        intel.set_api_key("virustotal", "k")
        intel.check_ip("1.1.1.1")
        intel.check_ip("1.1.1.1")
        s = intel.get_stats()
        assert s["cache_hit_rate"] == 50.0
        assert s["local_feed_hashes"] >= 3 and s["local_feed_domains"] >= 1
        assert s["apis_configured"] == ["virustotal"]
        assert ThreatIntelligence(enable_online=False).get_stats()["cache_hit_rate"] == 0

    def test_load_api_keys_env_and_file(self, monkeypatch, tmp_path):
        intel = ThreatIntelligence(enable_online=False)
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab")
        intel.load_api_keys_from_env()
        assert intel.api_keys == {"virustotal": "vt", "abuseipdb": "ab"}

        intel2 = ThreatIntelligence(enable_online=False)
        cfg = tmp_path / "keys.json"
        cfg.write_text(json.dumps({"virustotal": "fromfile"}))
        intel2.load_api_keys_from_file(str(cfg))
        assert intel2.api_keys == {"virustotal": "fromfile"}
        cfg.write_text("not json")
        intel2.load_api_keys_from_file(str(cfg))  # logged, not raised
        intel2.load_api_keys_from_file(str(tmp_path / "missing.json"))
        assert intel2.api_keys == {"virustotal": "fromfile"}

    def test_load_api_keys_default_path(self):
        p = Path.home() / ".ot_pcap_analyzer" / "api_keys.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"abuseipdb": "x"}))
        intel = ThreatIntelligence(enable_online=False)
        intel.load_api_keys_from_file()
        assert intel.api_keys == {"abuseipdb": "x"}


# --------------------------------------------------------------------------- online (mocked)

def _vt(stats, **attrs):
    return {"data": {"attributes": {"last_analysis_stats": stats, **attrs}}}


@pytest.fixture
def online(monkeypatch):
    intel = ThreatIntelligence(enable_online=True)
    intel.set_api_key("virustotal", "vt-key")
    intel.set_api_key("abuseipdb", "ab-key")
    responses = {}
    requested = []

    def fake(url, headers=None, timeout=10):
        requested.append((url, headers))
        for prefix, resp in responses.items():
            if url.startswith(prefix):
                return resp
        return None

    monkeypatch.setattr(intel, "_make_request", fake)
    return SimpleNamespace(intel=intel, responses=responses, requested=requested)


class TestThreatIntelligenceOnlineMocked:
    def test_ip_virustotal_and_abuseipdb(self, online):
        online.responses["https://www.virustotal.com/api/v3/ip_addresses/"] = _vt(
            {"malicious": 6, "suspicious": 1, "harmless": 3}, country="NL", as_owner="AS1")
        online.responses["https://api.abuseipdb.com/"] = {
            "data": {"abuseConfidenceScore": 90, "totalReports": 12, "isTor": True}}
        r = online.intel.check_ip("45.33.32.77")
        assert r["is_malicious"] and r["severity"] == "CRITICAL"
        assert r["sources"] == ["virustotal", "abuseipdb"]
        assert r["confidence"] == pytest.approx(0.9)
        assert r["details"]["virustotal"]["total_engines"] == 10
        assert r["details"]["virustotal"]["country"] == "NL"
        assert r["details"]["abuseipdb"]["is_tor"] is True
        assert online.intel.stats["api_calls"] == 2
        urls = [u for u, _ in online.requested]
        assert urls[0].endswith("/ip_addresses/45.33.32.77")
        assert online.requested[0][1] == {"x-apikey": "vt-key"}
        assert online.requested[1][1]["Key"] == "ab-key"

    @pytest.mark.parametrize("malicious,total,severity", [(3, 10, "HIGH"), (1, 10, "LOW")])
    def test_ip_virustotal_severity_thresholds(self, online, malicious, total, severity):
        online.intel.api_keys.pop("abuseipdb")
        online.responses["https://www.virustotal.com"] = _vt(
            {"malicious": malicious, "harmless": total - malicious})
        r = online.intel.check_ip("45.33.32.1")
        assert r["is_malicious"] and r["severity"] == severity
        assert r["confidence"] == pytest.approx(malicious / total)

    def test_ip_abuseipdb_medium_score(self, online):
        online.intel.api_keys.pop("virustotal")
        online.responses["https://api.abuseipdb.com/"] = {"data": {"abuseConfidenceScore": 60}}
        r = online.intel.check_ip("45.33.32.2")
        assert r["severity"] == "HIGH" and r["confidence"] == pytest.approx(0.6)
        online.responses["https://api.abuseipdb.com/"] = {"data": {"abuseConfidenceScore": 20}}
        assert online.intel.check_ip("45.33.32.3")["is_malicious"] is False

    def test_failed_api_response_is_not_malicious(self, online):
        r = online.intel.check_ip("45.33.32.4")  # fake returns None for everything
        assert r["is_malicious"] is False and r["details"] == {}
        online.responses["https://www.virustotal.com"] = {"error": "x"}  # no 'data' key
        assert online.intel.check_hash("ab" * 20)["details"] == {}
        assert online.intel.check_domain("a.test")["details"] == {}

    def test_hash_virustotal(self, online):
        online.responses["https://www.virustotal.com/api/v3/files/"] = _vt(
            {"malicious": 40, "undetected": 20},
            popular_threat_classification={"suggested_threat_label": "trojan.industroyer"},
            type_description="Win32 DLL", size=1234)
        r = online.intel.check_hash("AB" * 32)
        assert r["is_malicious"] and r["severity"] == "CRITICAL"
        assert r["malware_name"] == "trojan.industroyer"
        assert r["details"]["virustotal"]["file_type"] == "Win32 DLL"
        assert online.requested[-1][0].endswith("/files/" + "ab" * 32)
        online.responses["https://www.virustotal.com/api/v3/files/"] = _vt({"malicious": 3, "undetected": 7})
        assert online.intel.check_hash("cd" * 32)["severity"] == "HIGH"

    @pytest.mark.parametrize("malicious,severity", [(4, "CRITICAL"), (2, "HIGH"), (1, "LOW")])
    def test_domain_virustotal_thresholds(self, online, malicious, severity):
        online.responses["https://www.virustotal.com/api/v3/domains/"] = _vt(
            {"malicious": malicious, "harmless": 10 - malicious}, registrar="R")
        r = online.intel.check_domain("bad.test")
        assert r["is_malicious"] and r["severity"] == severity
        assert r["details"]["virustotal"]["registrar"] == "R"

    def test_private_helpers_without_key_return_none(self):
        intel = ThreatIntelligence(enable_online=True)
        assert intel._check_ip_virustotal("1.1.1.1") is None
        assert intel._check_ip_abuseipdb("1.1.1.1") is None
        assert intel._check_hash_virustotal("aa") is None
        assert intel._check_domain_virustotal("a.test") is None

    def test_rate_limit_sleeps_for_remaining_interval(self, monkeypatch):
        intel = ThreatIntelligence(enable_online=False)
        slept = []
        now = [1000.0]
        monkeypatch.setattr(ti.time, "time", lambda: now[0])
        monkeypatch.setattr(ti.time, "sleep", lambda s: slept.append(s))
        assert intel._rate_limit("virustotal") is True
        assert slept == []
        now[0] += 5.0
        intel._rate_limit("virustotal")  # 4/min => 15 s interval, 10 s remaining
        assert slept == [pytest.approx(10.0)]

    # Regression test: check_ip sends RFC1918/internal OT addresses to VirusTotal/AbuseIPDB (leaks plant topology, burns rate limit)
    def test_private_ip_not_sent_online(self, online):
        online.intel.check_ip("192.168.10.20")
        online.intel.check_ip("10.0.0.1")
        assert online.requested == []


class TestMakeRequest:
    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _patch(self, monkeypatch, behaviour):
        seen = {}

        def fake_urlopen(req, timeout=None, context=None):
            seen["req"], seen["timeout"] = req, timeout
            return behaviour()

        monkeypatch.setattr(ti.urllib.request, "urlopen", fake_urlopen)
        return seen

    def test_success(self, monkeypatch):
        seen = self._patch(monkeypatch, lambda: self._Resp(b'{"data": 1}'))
        intel = ThreatIntelligence(enable_online=False)
        assert intel._make_request("https://x.test/a", {"k": "v"}, timeout=3) == {"data": 1}
        assert seen["req"].get_header("K") == "v" and seen["timeout"] == 3

    @pytest.mark.parametrize("exc", [
        urllib.error.HTTPError("u", 404, "nf", {}, None),
        urllib.error.URLError("down"),
        RuntimeError("weird"),
    ])
    def test_errors_return_none(self, monkeypatch, exc):
        def raise_():
            raise exc
        self._patch(monkeypatch, raise_)
        assert ThreatIntelligence(enable_online=False)._make_request("https://x.test") is None

    def test_invalid_json_returns_none(self, monkeypatch):
        self._patch(monkeypatch, lambda: self._Resp(b"<html>"))
        assert ThreatIntelligence(enable_online=False)._make_request("https://x.test") is None
