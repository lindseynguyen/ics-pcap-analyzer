"""Behavioural tests for ot_pcap_analyzer.database (SQLite history backend)."""
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from ot_pcap_analyzer import database as dbmod
from ot_pcap_analyzer.database import AnalysisDatabase
from ot_pcap_analyzer.models import SecurityAnomaly

NOW = time.time()
YESTERDAY = NOW - 86400


def _anom(atype="MODBUS_WRITE", severity="HIGH", src="192.168.10.66", dst="192.168.10.20",
          ts=YESTERDAY, **extra):
    a = SecurityAnomaly(
        timestamp=ts, anomaly_type=atype, severity=severity, src_ip=src, dst_ip=dst,
        protocol="Modbus", description=f"{atype} from {src}", evidence={"fc": 6},
        mitre_techniques=["T0836"], confidence=0.8, recommendation="block")
    for k, v in extra.items():
        setattr(a, k, v)
    return a


@pytest.fixture
def db(tmp_path):
    d = AnalysisDatabase(tmp_path / "analysis.db")
    yield d
    d.close()


@pytest.fixture
def session(db, tmp_path):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1fakepcap")
    return db.create_session(str(pcap), metadata={"analyst": "unit"})


# --------------------------------------------------------------------------- helpers

class TestTimestampHelpers:
    def test_ts_to_db(self):
        assert dbmod._ts_to_db(None) is None
        assert dbmod._ts_to_db("") is None
        assert dbmod._ts_to_db(0) == "1970-01-01 00:00:00"
        assert dbmod._ts_to_db(1767225600.5) == "2026-01-01 00:00:00.500000"
        assert dbmod._ts_to_db(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02 03:04:05"
        assert dbmod._ts_to_db("not-a-number") == "not-a-number"
        assert dbmod._ts_to_db(1e30) is None  # out of range

    def test_convert_timestamp(self):
        assert dbmod._convert_timestamp(b"1767225600") == datetime(2026, 1, 1)
        assert dbmod._convert_timestamp(b"2026-01-01 10:00:00") == datetime(2026, 1, 1, 10)
        assert dbmod._convert_timestamp(b"1e30") == "1e30"
        assert dbmod._convert_timestamp(b"garbage") == "garbage"


# --------------------------------------------------------------------------- sessions

class TestSessions:
    def test_schema_and_default_path(self):
        d = AnalysisDatabase()
        assert Path(d.db_path) == Path.home() / ".ot_pcap_analyzer" / "analysis.db"
        with d._get_connection() as conn:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"sessions", "anomalies", "iocs", "ioc_watchlist", "attack_timeline"} <= tables
            versions = [r[0] for r in conn.execute("SELECT version FROM schema_version")]
        d.close()
        # Re-opening must not duplicate the schema version row
        d2 = AnalysisDatabase()
        with d2._get_connection() as conn:
            assert [r[0] for r in conn.execute("SELECT version FROM schema_version")] == versions == [1]
        d2.close()

    def test_create_and_get_session(self, db, session, tmp_path):
        s = db.get_session(session)
        assert s["status"] == "running" and s["total_packets"] == 0
        assert json.loads(s["metadata"]) == {"analyst": "unit"}
        import hashlib
        assert s["pcap_hash"] == hashlib.sha256((tmp_path / "cap.pcap").read_bytes()).hexdigest()
        assert isinstance(s["started_at"], datetime)
        assert db.get_session("nope") is None

    def test_session_for_missing_file_has_no_hash(self, db):
        sid = db.create_session("/does/not/exist.pcap")
        assert db.get_session(sid)["pcap_hash"] is None
        assert db.get_session(sid)["metadata"] is None

    def test_update_session(self, db, session):
        db.update_session(session)  # no-op
        db.update_session(session, status="completed", total_packets=1234, total_anomalies=5)
        s = db.get_session(session)
        assert s["status"] == "completed" and s["total_packets"] == 1234 and s["total_anomalies"] == 5
        assert isinstance(s["completed_at"], datetime)
        db.update_session(session, status="failed")
        assert db.get_session(session)["status"] == "failed"

    def test_recent_sessions(self, db):
        ids = {db.create_session(f"/x/{i}.pcap") for i in range(3)}
        recent = db.get_recent_sessions()
        assert {r["id"] for r in recent} == ids
        assert len(db.get_recent_sessions(limit=2)) == 2

    def test_rollback_on_error(self, db, session):
        with pytest.raises(sqlite3.OperationalError):
            with db._get_connection() as conn:
                conn.execute("INSERT INTO sessions (id, pcap_file) VALUES ('zz', 'f')")
                conn.execute("SELECT * FROM no_such_table")
        assert db.get_session("zz") is None


# --------------------------------------------------------------------------- anomalies

class TestAnomalies:
    def test_store_single_and_query(self, db, session):
        aid = db.store_anomaly(session, _anom(), enrichment={"findings": [1]})
        assert aid > 0
        [row] = db.get_anomalies(session_id=session)
        assert row["anomaly_type"] == "MODBUS_WRITE" and row["severity"] == "HIGH"
        assert isinstance(row["timestamp"], datetime)
        assert abs(row["timestamp"] - datetime.fromtimestamp(YESTERDAY, timezone.utc).replace(tzinfo=None)) < timedelta(seconds=1)
        assert row["raw_data"]["evidence"] == {"fc": 6}
        assert row["raw_data"]["mitre_techniques"] == ["T0836"]
        assert row["enrichment_data"] == {"findings": [1]}
        assert row["confidence"] == 0.8

    def test_unserializable_attrs_are_stringified(self, db, session):
        a = _anom(blob=object(), _private="hidden")
        db.store_anomaly(session, a)
        raw = db.get_anomalies(session_id=session)[0]["raw_data"]
        assert raw["blob"].startswith("<object object")
        assert "_private" not in raw

    def test_defaults_for_plain_object(self, db, session):
        db.store_anomaly(session, SimpleNamespace(description="bare"))
        [row] = db.get_anomalies(session_id=session)
        assert row["anomaly_type"] == "Unknown" and row["severity"] == "MEDIUM"
        assert row["timestamp"] is None and row["enrichment_data"] is None

    def test_batch_store_and_filters(self, db, session):
        anomalies = [
            _anom("MODBUS_WRITE", "CRITICAL", ts=NOW - 3600),
            _anom("PORT_SCAN", "MEDIUM", src="10.0.0.9", ts=NOW - 7200),
            _anom("PORT_SCAN", "LOW", src="10.0.0.9", ts=NOW - 10 * 86400),
            _anom("BAD", severity=["unbindable"]),  # sqlite cannot bind a list -> skipped
        ]
        n = db.store_anomalies(session, anomalies, enrichments={0: {"ti": True}})
        assert n == 3
        assert len(db.get_anomalies()) == 3
        assert len(db.get_anomalies(anomaly_type="PORT_SCAN")) == 2
        assert [r["severity"] for r in db.get_anomalies(severity="CRITICAL")] == ["CRITICAL"]
        assert db.get_anomalies(severity="CRITICAL")[0]["enrichment_data"] == {"ti": True}
        assert len(db.get_anomalies(src_ip="10.0.0.9")) == 2
        utc_now = datetime.now(timezone.utc).replace(tzinfo=None)
        recent = db.get_anomalies(start_time=utc_now - timedelta(days=1))
        assert {r["anomaly_type"] for r in recent} == {"MODBUS_WRITE", "PORT_SCAN"} and len(recent) == 2
        old = db.get_anomalies(end_time=utc_now - timedelta(days=5))
        assert [r["severity"] for r in old] == ["LOW"]
        assert len(db.get_anomalies(limit=1)) == 1
        # Newest first
        ts = [r["timestamp"] for r in db.get_anomalies()]
        assert ts == sorted(ts, reverse=True)

    def test_legacy_numeric_timestamp_readable(self, db, session):
        with db._get_connection() as conn:
            conn.execute("INSERT INTO anomalies (session_id, anomaly_type, severity, timestamp) "
                         "VALUES (?, 'LEGACY', 'LOW', ?)", (session, 1767225600.0))
            conn.commit()
        [row] = db.get_anomalies(anomaly_type="LEGACY")
        assert row["timestamp"] == datetime(2026, 1, 1)


# --------------------------------------------------------------------------- IOCs

class TestIOCs:
    def test_store_ioc_dedup_and_counts(self, db, session):
        i1 = db.store_ioc(session, "IP", "203.0.113.50", severity="HIGH", attack_type="C2",
                          context={"port": 4444})
        i2 = db.store_ioc(session, "IP", "203.0.113.50", threat_intel={"vt": 5})
        i3 = db.store_ioc(session, "IP", "203.0.113.50")  # None threat_intel keeps old value
        assert i1 == i2 == i3
        [ioc] = db.get_iocs(session_id=session)
        assert ioc["occurrence_count"] == 3
        assert ioc["context"] == {"port": 4444}
        assert ioc["threat_intel"] == {"vt": 5}
        assert ioc["last_seen"] >= ioc["first_seen"]
        # Same value in another session is a separate record
        other = db.create_session("/other.pcap")
        assert db.store_ioc(other, "IP", "203.0.113.50") != i1
        assert len(db.get_iocs()) == 2

    def test_store_iocs_from_collector_output(self, db, session):
        V = SimpleNamespace
        iocs = {
            "ip_addresses": [V(value="203.0.113.50", severity="CRITICAL"), "198.51.100.1"],
            "domains": ["evil.test"],
            "custom_thing": ["x1"],
            "by_attack_type": {
                "WEBSHELL": [V(type="URL", value="http://h/shell.php", severity="CRITICAL"),
                             "ignored-no-attrs"],
            },
            "summary": {"not": "a list"},
        }
        assert db.store_iocs(session, iocs) == 5
        by_type = {i["ioc_type"]: i for i in db.get_iocs(session_id=session)}
        assert set(by_type) == {"IP", "DOMAIN", "CUSTOM_THING", "URL"}
        assert by_type["URL"]["attack_type"] == "WEBSHELL"
        assert by_type["URL"]["context"] == {"source": "by_attack_type"}
        assert len(db.get_iocs(ioc_type="IP")) == 2
        crit = [i for i in db.get_iocs(ioc_type="IP") if i["value"] == "203.0.113.50"][0]
        assert crit["severity"] == "CRITICAL"
        assert [i["value"] for i in db.get_iocs(attack_type="WEBSHELL")] == ["http://h/shell.php"]
        assert len(db.get_iocs(limit=2)) == 2

    def test_get_iocs_ordered_by_occurrence(self, db, session):
        db.store_ioc(session, "IP", "a")
        for _ in range(3):
            db.store_ioc(session, "IP", "b")
        assert [i["value"] for i in db.get_iocs()] == ["b", "a"]

    def test_search_iocs(self, db, session):
        db.store_ioc(session, "DOMAIN", "c2.evil.test", context={"q": 1}, threat_intel={"x": 1})
        db.store_ioc(session, "DOMAIN", "www.good.test")
        db.store_ioc(session, "IP", "10.0.0.1")
        hits = db.search_iocs("evil")
        assert [h["value"] for h in hits] == ["c2.evil.test"]
        assert hits[0]["pcap_file"].endswith("cap.pcap")
        assert hits[0]["context"] == {"q": 1} and hits[0]["threat_intel"] == {"x": 1}
        assert len(db.search_iocs(".test")) == 2
        assert len(db.search_iocs("")) == 3
        assert len(db.search_iocs("", limit=1)) == 1
        assert db.search_iocs("nomatch") == []


# --------------------------------------------------------------------------- watchlist

class TestWatchlist:
    def test_add_check_list(self, db):
        wid = db.add_to_watchlist("IP", "203.0.113.50", "CRITICAL", "C2", tags=["apt", "c2"],
                                  source="cti")
        assert wid > 0
        hit = db.check_watchlist("IP", "203.0.113.50")
        assert hit["severity"] == "CRITICAL" and hit["tags"] == ["apt", "c2"]
        assert hit["source"] == "cti"
        # The check itself increments hit_count
        assert db.get_watchlist()[0]["hit_count"] == 1
        assert db.check_watchlist("DOMAIN", "203.0.113.50") is None  # type must match
        assert db.check_watchlist("IP", "1.1.1.1") is None

    def test_duplicate_add_bumps_hit_count(self, db):
        db.add_to_watchlist("DOMAIN", "evil.test")
        assert db.add_to_watchlist("DOMAIN", "evil.test") == 0
        [entry] = db.get_watchlist()
        assert entry["hit_count"] == 1 and entry["severity"] == "HIGH"
        assert entry["tags"] is None
        assert entry["last_seen_at"] is not None

    def test_filters_and_inactive(self, db):
        db.add_to_watchlist("IP", "1.2.3.4")
        db.add_to_watchlist("HASH", "ab" * 16)
        db.add_to_watchlist("IP", "5.6.7.8")
        with db._get_connection() as conn:
            conn.execute("UPDATE ioc_watchlist SET is_active = 0 WHERE value = '5.6.7.8'")
            conn.commit()
        assert {e["value"] for e in db.get_watchlist(ioc_type="IP")} == {"1.2.3.4"}
        assert len(db.get_watchlist(ioc_type="IP", active_only=False)) == 2
        assert len(db.get_watchlist(active_only=False)) == 3
        assert db.check_watchlist("IP", "5.6.7.8") is None


# --------------------------------------------------------------------------- analytics

class TestAnalytics:
    def _populate(self, db, session):
        db.store_anomalies(session, [
            _anom("MODBUS_WRITE", "CRITICAL", ts=NOW - 2 * 86400),
            _anom("MODBUS_WRITE", "HIGH", ts=NOW - 2 * 86400 + 60),
            _anom("PORT_SCAN", "MEDIUM", src="10.0.0.9", ts=NOW - 86400),
            _anom("PORT_SCAN", "LOW", src="10.0.0.9", dst="192.168.10.66", ts=NOW - 86400),
            _anom("ANCIENT", "LOW", ts=NOW - 400 * 86400),
        ])
        db.store_ioc(session, "IP", "203.0.113.50")
        db.store_ioc(session, "IP", "203.0.113.50")
        db.store_ioc(session, "DOMAIN", "evil.test")
        db.update_session(session, status="completed", total_packets=500, total_anomalies=5)

    def test_get_statistics(self, db, session):
        self._populate(db, session)
        db.create_session("/second.pcap")
        s = db.get_statistics()
        assert s["sessions"] == {"total": 2, "completed": 1, "total_packets": 500,
                                 "total_anomalies": 5}
        assert s["anomaly_types"] == {"MODBUS_WRITE": 2, "PORT_SCAN": 2, "ANCIENT": 1}
        assert s["severity_distribution"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 2}
        assert s["top_source_ips"][0] == {"ip": "192.168.10.66", "count": 3}
        assert s["ioc_types"]["IP"] == {"unique": 1, "total_occurrences": 2}
        assert s["ioc_types"]["DOMAIN"] == {"unique": 1, "total_occurrences": 1}

    def test_get_statistics_empty(self, db):
        s = db.get_statistics()
        assert s["sessions"]["total"] == 0 and s["anomaly_types"] == {} and s["top_source_ips"] == []

    def test_attack_trends_by_day(self, db, session):
        self._populate(db, session)
        trends = db.get_attack_trends(days=30)
        assert sum(t["total_anomalies"] for t in trends) == 4  # ANCIENT excluded
        assert all(t["period"] is not None for t in trends)
        periods = [t["period"] for t in trends]
        assert periods == sorted(periods)
        assert all(len(p) == 10 for p in periods)  # YYYY-MM-DD
        assert sum(t["critical"] for t in trends) == 1
        assert sum(t["low"] for t in trends) == 1
        assert sum(t["medium"] + t["high"] for t in trends) == 2

    @pytest.mark.parametrize("interval,length", [("hour", 16), ("week", 7)])
    def test_attack_trends_other_intervals(self, db, session, interval, length):
        self._populate(db, session)
        trends = db.get_attack_trends(days=30, interval=interval)
        assert sum(t["total_anomalies"] for t in trends) == 4
        assert all(len(t["period"]) == length for t in trends)

    def test_ip_reputation_history(self, db, session):
        self._populate(db, session)
        h = db.get_ip_reputation_history("192.168.10.66")
        # src of 3 anomalies + dst of 1
        assert h["total_anomalies"] == 4
        assert h["anomaly_types"] == {"MODBUS_WRITE": 2, "ANCIENT": 1, "PORT_SCAN": 1}
        assert h["first_seen"] < h["last_seen"]
        assert [s["id"] for s in h["sessions"]] == [session]
        empty = db.get_ip_reputation_history("8.8.8.8")
        assert empty["total_anomalies"] == 0 and empty["first_seen"] is None and empty["sessions"] == []

    # Regression test: get_ip_reputation_history compares MIN(timestamp) across anomaly types with '<' and crashes with TypeError when one type has only NULL timestamps
    def test_ip_reputation_history_with_missing_timestamps(self, db, session):
        db.store_anomaly(session, _anom("AAA_WITH_TS", ts=NOW - 60))
        db.store_anomaly(session, _anom("ZZZ_NO_TS", ts=None))
        h = db.get_ip_reputation_history("192.168.10.66")
        assert h["total_anomalies"] == 2
        assert h["first_seen"] is not None


# --------------------------------------------------------------------------- export / import

class TestExportImport:
    def test_roundtrip(self, db, session, tmp_path):
        db.store_anomalies(session, [_anom(ts=NOW - 100), _anom("PORT_SCAN", "LOW", ts=NOW - 50)],
                           enrichments={1: {"ti": "x"}})
        db.store_ioc(session, "IP", "203.0.113.50", context={"c": 1}, threat_intel={"t": 2})
        db.store_ioc(session, "IP", "203.0.113.50")
        out = tmp_path / "export.json"
        assert db.export_session(session, str(out)) is True
        data = json.loads(out.read_text())
        assert data["export_version"] == "1.0"
        assert data["session"]["id"] == session
        assert len(data["anomalies"]) == 2 and len(data["iocs"]) == 1

        other = AnalysisDatabase(tmp_path / "other.db")
        new_id = other.import_session(str(out))
        assert new_id and new_id != session
        meta = json.loads(other.get_session(new_id)["metadata"])
        assert meta == {"imported_from": str(out), "original_session_id": session}
        anomalies = other.get_anomalies(session_id=new_id)
        assert sorted(a["anomaly_type"] for a in anomalies) == ["MODBUS_WRITE", "PORT_SCAN"]
        assert {a["anomaly_type"]: a["enrichment_data"] for a in anomalies}["PORT_SCAN"] == {"ti": "x"}
        orig_ts = sorted(a["timestamp"] for a in db.get_anomalies(session_id=session))
        assert sorted(a["timestamp"] for a in anomalies) == orig_ts
        [ioc] = other.get_iocs(session_id=new_id)
        assert ioc["occurrence_count"] == 2 and ioc["context"] == {"c": 1}
        assert ioc["threat_intel"] == {"t": 2}
        other.close()

    def test_export_missing_session(self, db, tmp_path):
        out = tmp_path / "x.json"
        assert db.export_session("missing", str(out)) is False
        assert not out.exists()

    def test_export_unwritable_path(self, db, session, tmp_path):
        assert db.export_session(session, str(tmp_path / "no" / "dir" / "x.json")) is False

    def test_import_failures(self, db, tmp_path):
        assert db.import_session(str(tmp_path / "missing.json")) is None
        bad = tmp_path / "bad.json"
        bad.write_text("{oops")
        assert db.import_session(str(bad)) is None

    def test_import_minimal_file(self, db, tmp_path):
        f = tmp_path / "min.json"
        f.write_text(json.dumps({}))
        sid = db.import_session(str(f))
        assert db.get_session(sid)["pcap_file"] == "imported"
        assert db.get_anomalies(session_id=sid) == []


# --------------------------------------------------------------------------- maintenance

def test_vacuum_and_close_reopen(db, session):
    db.store_anomalies(session, [_anom() for _ in range(20)])
    db.vacuum()
    db.close()
    db.close()  # idempotent
    assert len(db.get_anomalies(session_id=session)) == 20  # lazily reconnects
