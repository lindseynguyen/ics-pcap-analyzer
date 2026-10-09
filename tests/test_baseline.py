"""Behavioural tests for the baseline learning / whitelist engine (ot_pcap_analyzer.baseline)."""
import struct
from collections import Counter
from datetime import datetime

import pytest

import pcap_factory as pf
from ot_pcap_analyzer.baseline import BaselineEngine
from ot_pcap_analyzer.models import SecurityAnomaly, WhitelistRule
from ot_pcap_analyzer.parsers import ProtocolParser as P

TS = pf.BASE_TS
HMI, PLC, ATT = pf.HMI, pf.PLC, pf.ATTACKER


def mb_event(ts=TS, src=HMI, dst=PLC, fc=3, sport=50200):
    body = struct.pack(">HH", 0, 10) if fc in (1, 2, 3, 4) else struct.pack(">HH", 10, 99)
    e = P.parse_modbus_tcp(pf.modbus(1, 1, fc, body), ts, src, dst, sport, 502, 1)
    assert e is not None
    return e


def s7_event(ts=TS, src=HMI, dst=PLC, func=0x04):
    e = P.parse_s7comm(pf.s7_job(func, b"\x01"), ts, src, dst, 50102, 102, 1)
    assert e is not None
    return e


def anomaly(ts=TS, src=ATT, dst=PLC, conf=0.9, atype="RAPID_WRITE_SEQUENCE"):
    return SecurityAnomaly(
        timestamp=ts, anomaly_type=atype, severity="HIGH", src_ip=src, dst_ip=dst,
        protocol="MODBUS_TCP", description="d", evidence={}, mitre_techniques=["T0831"],
        confidence=conf, recommendation="r")


def stable_engine(events, period=10.0):
    eng = BaselineEngine(learning_period=period)
    for e in events:
        assert eng.learn_from_event(e)
    return eng


# ------------------------------------------------------------------ learning
def test_learn_creates_one_baseline_per_pair_and_protocol():
    eng = BaselineEngine()
    eng.learn_from_event(mb_event(TS, fc=3))
    eng.learn_from_event(mb_event(TS + 1, fc=6))
    eng.learn_from_event(s7_event(TS + 2))
    eng.learn_from_event(mb_event(TS + 3, src=ATT))
    assert len(eng.baselines) == 3
    mb = eng.baselines[eng._make_baseline_key(HMI, PLC, mb_event().protocol.value)]
    assert mb.samples_count == 2
    assert mb.normal_function_codes == {3, 6}
    assert mb.normal_operations == {"READ", "WRITE"}
    assert mb.first_seen == TS and mb.last_updated == TS + 1
    assert mb.src_port == 50200 and mb.dst_port == 502
    assert eng.total_events_learned == 4


def test_learn_records_active_hours_and_days():
    eng = BaselineEngine()
    eng.learn_from_event(mb_event(TS))
    b = next(iter(eng.baselines.values()))
    dt = datetime.fromtimestamp(TS)
    assert b.active_hours == {dt.hour}
    assert b.active_days == {dt.weekday()}


def test_baseline_becomes_stable_only_after_learning_period():
    eng = BaselineEngine(learning_period=60.0)
    eng.learn_from_event(mb_event(TS))
    eng.learn_from_event(mb_event(TS + 59.0))
    b = next(iter(eng.baselines.values()))
    assert not b.is_stable
    assert eng.get_statistics()["learning_baselines"] == 1
    eng.learn_from_event(mb_event(TS + 60.0))
    assert b.is_stable
    stats = eng.get_statistics()
    assert stats["stable_baselines"] == 1 and stats["learning_baselines"] == 0


def test_explicit_current_time_overrides_event_timestamp():
    eng = BaselineEngine(learning_period=100.0)
    eng.learn_from_event(mb_event(TS), current_time=TS)
    eng.learn_from_event(mb_event(TS), current_time=TS + 100.0)
    assert next(iter(eng.baselines.values())).is_stable


def test_max_baselines_limit_blocks_only_new_pairs():
    eng = BaselineEngine(max_baselines=1)
    assert eng.learn_from_event(mb_event(TS)) is True
    assert eng.learn_from_event(mb_event(TS + 1, src=ATT)) is False
    assert eng.learn_from_event(mb_event(TS + 2)) is True  # existing pair still learns
    assert len(eng.baselines) == 1
    assert eng.total_events_learned == 2


# Regression test: baseline.py learn_from_event sets last_updated=current_time before computing interval, so every interval is 0
def test_interval_statistics_reflect_polling_period():
    eng = BaselineEngine()
    for i in range(5):
        eng.learn_from_event(mb_event(TS + 10.0 * i))
    b = next(iter(eng.baselines.values()))
    assert b.avg_interval == pytest.approx(10.0)
    assert b.min_interval == pytest.approx(10.0)
    assert b.max_interval == pytest.approx(10.0)


# ------------------------------------------------------------------ is_anomalous with baselines
def test_no_rules_and_no_baseline_reports_unchanged():
    eng = BaselineEngine()
    a = anomaly(conf=0.77)
    assert eng.is_anomalous(a) == (True, 0.77)
    assert eng.is_anomalous(a, mb_event(TS)) == (True, 0.77)


def test_learning_baseline_does_not_reduce_confidence():
    eng = BaselineEngine(learning_period=1e9)
    ev = mb_event(TS, fc=6)
    eng.learn_from_event(ev)
    assert eng.is_anomalous(anomaly(conf=0.5), ev) == (True, 0.5)


def test_stable_baseline_reduces_confidence_for_known_behaviour():
    events = [mb_event(TS + i, fc=6) for i in range(12)]
    eng = stable_engine(events)
    ok, conf = eng.is_anomalous(anomaly(conf=0.5), events[-1])
    assert ok is True
    # known function code (x0.8), known operation (x0.8), usual hour/day (x0.9)
    assert conf == pytest.approx(0.5 * 0.8 * 0.8 * 0.9)


def test_stable_baseline_unknown_function_only_time_reduction():
    events = [mb_event(TS + i, fc=3) for i in range(12)]
    eng = stable_engine(events)
    write = mb_event(TS + 13, fc=6)
    ok, conf = eng.is_anomalous(anomaly(conf=0.5), write)
    assert ok and conf == pytest.approx(0.5 * 0.9)


def test_stable_baseline_filters_low_confidence_matching_anomaly():
    events = [mb_event(TS + i, fc=6) for i in range(12)]
    eng = stable_engine(events)
    ok, conf = eng.is_anomalous(anomaly(conf=0.2), events[-1])
    assert ok is False
    assert conf == pytest.approx(0.2 * 0.576)
    assert eng.get_statistics()["total_anomalies_filtered"] == 1


def test_baseline_for_other_pair_does_not_apply():
    events = [mb_event(TS + i, fc=6) for i in range(12)]
    eng = stable_engine(events)
    other = mb_event(TS + 13, src=ATT, fc=6)
    assert eng.is_anomalous(anomaly(conf=0.2), other) == (True, 0.2)


# ------------------------------------------------------------------ whitelist rules
def test_whitelist_rule_reduces_confidence_when_matching():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="r1", name="eng-ws", src_ip_pattern=ATT,
                                         confidence_reduction=0.3))
    ok, conf = eng.is_anomalous(anomaly(conf=0.9))
    assert ok and conf == pytest.approx(0.6)
    # non-matching source is untouched
    assert eng.is_anomalous(anomaly(src=HMI, conf=0.9)) == (True, 0.9)


def test_whitelist_rule_filters_when_confidence_drops_below_threshold():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="r1", src_ip_pattern=ATT, dst_ip_pattern=PLC,
                                         confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9)) == (False, 0.0)
    assert eng.total_anomalies_filtered == 1
    # destination mismatch -> rule does not apply
    assert eng.is_anomalous(anomaly(dst=pf.RTU, conf=0.9)) == (True, 0.9)


def test_whitelist_rules_are_cumulative():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="a", src_ip_pattern="*", confidence_reduction=0.3))
    eng.add_whitelist_rule(WhitelistRule(rule_id="b", src_ip_pattern="*", confidence_reduction=0.3))
    ok, conf = eng.is_anomalous(anomaly(conf=0.5))
    assert ok is False and conf == 0.0


def test_disabled_and_expired_rules_are_ignored():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="off", src_ip_pattern="*", enabled=False,
                                         confidence_reduction=1.0))
    eng.add_whitelist_rule(WhitelistRule(rule_id="old", src_ip_pattern="*", expires_at=TS - 1,
                                         confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9)) == (True, 0.9)
    eng.add_whitelist_rule(WhitelistRule(rule_id="future", src_ip_pattern="*", expires_at=TS + 3600,
                                         confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9))[0] is False
    stats = eng.get_statistics()
    assert stats["whitelist_rules"] == 3 and stats["active_rules"] == 2


def test_function_code_filter_in_rule():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="fc", src_ip_pattern="*", function_codes=[3],
                                         confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9), mb_event(TS, fc=6)) == (True, 0.9)
    assert eng.is_anomalous(anomaly(conf=0.9), mb_event(TS, fc=3))[0] is False


def test_time_restrictions_in_rule():
    hour = datetime.fromtimestamp(TS).hour
    day = datetime.fromtimestamp(TS).weekday()
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="night", allowed_hours=[(hour + 1) % 24],
                                         confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9))[0] is True
    eng.add_whitelist_rule(WhitelistRule(rule_id="other-day", allowed_hours=[hour],
                                         allowed_days=[(day + 1) % 7], confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9))[0] is True
    eng.add_whitelist_rule(WhitelistRule(rule_id="now", allowed_hours=[hour], allowed_days=[day],
                                         confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9))[0] is False


def test_wildcard_protocol_rule_matches_any_event():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="any", protocol="*", confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9), mb_event(TS))[0] is False


# Regression test: baseline.py is_anomalous compares event.protocol.value (an int from enum auto()) with the rule's protocol name string, so protocol-specific whitelist 
def test_protocol_specific_rule_matches_its_protocol():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="mb", protocol="MODBUS_TCP", confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9), mb_event(TS))[0] is False


def test_protocol_specific_rule_does_not_match_other_protocol():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="mb", protocol="MODBUS_TCP", confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9), s7_event(TS)) == (True, 0.9)


# Regression test: baseline.py is_anomalous reads anomaly.src_port/dst_port, which SecurityAnomaly does not have -> AttributeError for any port-pattern rule
def test_port_pattern_rule_applies_to_anomaly():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="p", dst_port_pattern="502", confidence_reduction=1.0))
    assert eng.is_anomalous(anomaly(conf=0.9), mb_event(TS))[0] is False


# ------------------------------------------------------------------ pattern matching helpers
@pytest.mark.parametrize("ip,pattern,expected", [
    ("10.0.1.5", "*", True),
    ("10.0.1.5", "10.0.1.5", True),
    ("10.0.1.5", "10.0.1.6", False),
    ("10.0.1.5", "10.0.1.*", True),
    ("10.0.2.5", "10.0.1.*", False),
    ("10.0.1.5", "10.*", True),
    ("110.0.1.5", "10.*", False),          # anchored, dots are literal
    ("10x0x1x5", "10.0.1.*", False),
    ("10.0.1.5", "10.0.1.0/24", False),    # CIDR documented as not implemented
])
def test_match_ip_pattern(ip, pattern, expected):
    assert BaselineEngine()._match_ip_pattern(ip, pattern) is expected


@pytest.mark.parametrize("port,pattern,expected", [
    (502, "*", True),
    (502, "502", True),
    (503, "502", False),
    (1500, "1000-2000", True),
    (1000, "1000-2000", True),
    (2000, "1000-2000", True),
    (2001, "1000-2000", False),
    (502, "abc", False),
    (502, "1-2-3", False),
])
def test_match_port_pattern(port, pattern, expected):
    assert BaselineEngine()._match_port_pattern(port, pattern) is expected


def test_add_and_remove_whitelist_rules():
    eng = BaselineEngine()
    eng.add_whitelist_rule(WhitelistRule(rule_id="a", name="A"))
    eng.add_whitelist_rule(WhitelistRule(rule_id="b", name="B"))
    assert eng.remove_whitelist_rule("a") is True
    assert [r.rule_id for r in eng.whitelist_rules] == ["b"]
    assert eng.remove_whitelist_rule("a") is False
    assert eng.remove_whitelist_rule("missing") is False


def test_statistics_initial_state():
    assert BaselineEngine().get_statistics() == {
        "total_baselines": 0, "stable_baselines": 0, "learning_baselines": 0,
        "whitelist_rules": 0, "active_rules": 0, "total_events_learned": 0,
        "total_anomalies_filtered": 0,
    }


# ------------------------------------------------------------------ end-to-end
def test_baseline_disabled_by_default(analyzed):
    assert analyzed["ot_protocols"].baseline_engine is None


def test_end_to_end_learning_on_ot_capture(captures, analyze):
    a = analyze(captures["ot_protocols"], enable_baseline=True, baseline_learning_period=1.0)
    eng = a.baseline_engine
    assert eng is not None
    pairs = {(e.src_ip, e.dst_ip, e.protocol.value) for e in a.ot_events}
    stats = eng.get_statistics()
    assert stats["total_events_learned"] == len(a.ot_events) > 0
    assert stats["total_baselines"] == len(pairs)
    for b in eng.baselines.values():
        assert b.samples_count >= 1
    counts = Counter((e.src_ip, e.dst_ip, e.protocol.value) for e in a.ot_events)
    for (s, d, p), n in counts.items():
        assert eng.baselines[eng._make_baseline_key(s, d, p)].samples_count == n


def test_end_to_end_baseline_keeps_attack_detections(captures, analyzed, analyze):
    """A long learning period must not suppress anything; attacks remain visible."""
    plain = analyzed["attacks"]
    a = analyze(captures["attacks"], enable_baseline=True)  # 24 h learning, nothing stable
    assert a.baseline_engine.get_statistics()["stable_baselines"] == 0
    assert a.baseline_engine.total_anomalies_filtered == 0
    assert sorted(x.anomaly_type for x in a.anomalies) == sorted(x.anomaly_type for x in plain.anomalies)


def test_end_to_end_benign_capture_stays_clean_with_baseline(captures, analyze):
    a = analyze(captures["benign"], enable_baseline=True, baseline_learning_period=5.0)
    assert a.anomalies == []
    assert a.baseline_engine.get_statistics()["stable_baselines"] >= 1


def test_end_to_end_whitelist_suppresses_only_ot_event_anomalies(captures, analyzed):
    from ot_pcap_analyzer.analyzer import OTAnalyzer
    from ot_pcap_analyzer.models import AnalyzerConfig
    a = OTAnalyzer(AnalyzerConfig(enable_baseline=True))
    a.baseline_engine.add_whitelist_rule(
        WhitelistRule(rule_id="att", src_ip_pattern=ATT, confidence_reduction=1.0))
    a.analyze_capture(captures["attacks"])

    plain_types = {x.anomaly_type for x in analyzed["attacks"].anomalies if x.src_ip == ATT}
    wl_types = {x.anomaly_type for x in a.anomalies if x.src_ip == ATT}
    assert a.baseline_engine.total_anomalies_filtered > 0
    # OT-event driven alerts from the whitelisted host are gone ...
    assert "RAPID_WRITE_SEQUENCE" in plain_types and "RAPID_WRITE_SEQUENCE" not in wl_types
    # ... network-level detections bypass the baseline and are still reported
    assert "IT_PORT_SCAN_FAST" in wl_types
    assert wl_types < plain_types
