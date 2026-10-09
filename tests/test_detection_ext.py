"""Tests for ot_pcap_analyzer.detection (BehaviorProfiler and RuleEngine)."""
import json
import logging
import os
import random
import time

import pytest

from ot_pcap_analyzer.constants import OTProtocol
from ot_pcap_analyzer.detection.behavior import (
    BehaviorProfiler, event_op, infer_is_request, is_dangerous,
)
from ot_pcap_analyzer.detection.rules_engine import Rule, RuleEngine, RuleError
from ot_pcap_analyzer.models import OTEvent, SecurityAnomaly

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE_RULES = os.path.join(ROOT, "examples", "rules", "example_rules.yml")

MASTER, MASTER2, PLC = "10.0.0.10", "10.0.0.11", "10.0.0.20"
LOGGER = "OT_PCAP_ANALYZER"


def ev(ts, src=MASTER, dst=PLC, sport=50000, dport=502, proto=OTProtocol.MODBUS_TCP,
       fc=3, name="Read Holding Registers", op_type="READ", risk="LOW", details=None,
       unit_id=1, addr=0, mitre=None):
    return OTEvent(timestamp=float(ts), src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                   protocol=proto, function_code=fc, function_name=name,
                   operation_type=op_type, risk_level=risk, unit_id=unit_id,
                   data_address=addr, mitre_techniques=list(mitre or []),
                   details=dict(details) if details is not None else {})


def read_req(ts, src=MASTER, dst=PLC, fc=3, with_details=True, sport=50000):
    d = {"op": "READ", "is_request": True, "target": "HR 0", "count": 10} if with_details else {}
    return ev(ts, src=src, dst=dst, sport=sport, fc=fc, details=d)


def read_resp(ts, src=PLC, dst=MASTER, fc=3, with_details=True, dport=50000):
    d = {"op": "READ", "is_request": False} if with_details else {}
    return ev(ts, src=src, dst=dst, sport=502, dport=dport, fc=fc, details=d)


def write_req(ts, value, src=MASTER, dst=PLC, target="HR 40100", fc=6, with_details=True):
    d = {"op": "WRITE", "is_request": True, "target": target, "value": value} \
        if with_details else {}
    return ev(ts, src=src, dst=dst, fc=fc, name="Write Single Register", op_type="WRITE",
              risk="MEDIUM", details=d, addr=40100, mitre=["T0831", "T0836"])


def baseline(duration=300, with_details=True, skip=None):
    """Stable plant: MASTER polls PLC (fc3, 1 s), MASTER2 polls PLC (fc4, 2 s),
    MASTER writes a setpoint around 100 every 10 s."""
    skip = skip or (lambda e: False)
    out = []
    for t in range(duration):
        out.append(read_req(t, with_details=with_details))
        out.append(read_resp(t + 0.01, with_details=with_details))
        if t % 2 == 0:
            out.append(read_req(t + 0.5, src=MASTER2, fc=4, with_details=with_details,
                                sport=50001))
            out.append(read_resp(t + 0.51, dst=MASTER2, fc=4, with_details=with_details,
                                 dport=50001))
        if t % 10 == 5:
            out.append(write_req(t + 0.2, 98 + (t // 10) % 5, with_details=with_details))
    return [e for e in out if not skip(e)]


def types(anomalies):
    return sorted(a.anomaly_type for a in anomalies)


def only(anomalies, atype):
    found = [a for a in anomalies if a.anomaly_type == atype]
    assert len(found) == 1, (atype, [(a.anomaly_type, a.description) for a in anomalies])
    return found[0]


# =========================================================================== helpers

def test_helpers_fallbacks():
    e = ev(0, op_type="WRITE")                         # no details
    assert event_op(e) == "WRITE" and is_dangerous(e)
    assert event_op(ev(0, op_type="CONTROL")) == "CONTROL"
    assert event_op(ev(0, op_type="DIAGNOSTIC")) == ""
    assert infer_is_request(ev(0, sport=50000, dport=502)) is True
    assert infer_is_request(ev(0, sport=502, dport=50000)) is False
    assert infer_is_request(ev(0, sport=0, dport=0)) is False
    assert infer_is_request(ev(0, sport=502, dport=50000, details={"is_request": True}))
    assert not is_dangerous(ev(0, details={"op": "READ"}))
    assert is_dangerous(ev(0, details={"op": "PLC_STOP"}, op_type="OTHER"))


# =========================================================================== behaviour

class TestBehaviorStable:
    def test_stable_environment_no_alerts(self):
        assert BehaviorProfiler().analyze(baseline()) == []

    def test_stable_without_details_no_alerts(self):
        assert BehaviorProfiler().analyze(baseline(with_details=False)) == []

    def test_unsorted_input_is_deterministic(self):
        events = baseline() + [write_req(200, 100, src="10.0.0.66")]
        shuffled = list(events)
        random.Random(1).shuffle(shuffled)
        a = BehaviorProfiler().analyze(events)
        b = BehaviorProfiler().analyze(shuffled)
        assert [(x.anomaly_type, x.timestamp, x.src_ip) for x in a] == \
               [(x.anomaly_type, x.timestamp, x.src_ip) for x in b]
        assert all(isinstance(x, SecurityAnomaly) for x in a)


class TestLearningWindow:
    def test_empty_and_too_few_events(self):
        assert BehaviorProfiler().analyze([]) == []
        few = baseline()[:99]
        assert BehaviorProfiler().analyze(few) == []

    def test_capture_shorter_than_learning(self):
        # 200 events in 50 s -> learning (60 s minimum) covers everything
        events = [read_req(i * 0.25) for i in range(200)] + [read_req(49.9, src="10.0.0.66")]
        assert BehaviorProfiler().analyze(events) == []

    def test_min_learning_events_extends_window(self):
        # 120 events, learning by time would end after 10 events
        events = [read_req(i) for i in range(120)]
        events[30] = read_req(30, src="10.0.0.66")   # inside the first 50 events -> learnt
        prof = BehaviorProfiler(learning_fraction=0.05, min_learning_seconds=0,
                                min_learning_events=50)
        assert prof.analyze(events) == []
        events.append(read_req(119.5, src="10.0.0.77"))
        assert types(prof.analyze(events)) == ["OT_NEW_MASTER"]

    def test_invalid_parameters(self):
        with pytest.raises(ValueError):
            BehaviorProfiler(learning_fraction=1.5)
        with pytest.raises(ValueError):
            BehaviorProfiler(min_learning_events=0)


class TestNewMasterAndDevice:
    def test_new_master_write_is_high(self):
        events = baseline() + [write_req(200, 100, src="10.0.0.66"),
                               read_req(201, src="10.0.0.66")]
        out = BehaviorProfiler().analyze(events)
        a = only(out, "OT_NEW_MASTER")
        assert a.severity == "HIGH" and a.src_ip == "10.0.0.66" and a.dst_ip == PLC
        assert a.timestamp == 200 and a.protocol == "MODBUS_TCP"
        assert a.mitre_techniques == ["T0848", "T0855"]
        assert a.evidence["event_count"] == 2 and a.evidence["write_or_control"] is True
        assert MASTER in a.evidence["known_peers"]
        assert a.evidence["learning_end"] == pytest.approx(89.7, abs=0.5)
        assert 0.5 <= a.confidence <= 0.85 and a.recommendation and a.behavior
        assert not [x for x in out if x.anomaly_type == "OT_NEW_FUNCTION"]

    def test_new_master_read_is_medium_without_details(self):
        events = baseline(with_details=False) + [read_req(200, src="10.0.0.66",
                                                          with_details=False)]
        a = only(BehaviorProfiler().analyze(events), "OT_NEW_MASTER")
        assert a.severity == "MEDIUM"

    def test_new_device(self):
        events = baseline() + [read_req(200, dst="10.0.0.99"), read_req(201, dst="10.0.0.99")]
        out = BehaviorProfiler().analyze(events)
        assert types(out) == ["OT_NEW_DEVICE"]
        a = out[0]
        assert a.severity == "LOW" and a.evidence["device"] == "10.0.0.99"
        assert a.evidence["event_count"] == 2

    def test_master_seen_in_learning_is_not_new(self):
        events = baseline() + [read_req(250, src=MASTER2, fc=4, sport=50001)]
        assert BehaviorProfiler().analyze(events) == []

    def test_responses_from_new_peer_are_ignored(self):
        events = baseline() + [read_resp(200, dst="10.0.0.66", dport=50123)]
        assert BehaviorProfiler().analyze(events) == []


class TestNewFunction:
    def test_dangerous_new_function_is_high(self):
        events = baseline() + [ev(150, fc=16, name="Write Multiple Registers", op_type="WRITE",
                                  risk="HIGH", details={"op": "WRITE", "is_request": True},
                                  mitre=["T0831"])]
        a = only(BehaviorProfiler().analyze(events), "OT_NEW_FUNCTION")
        assert a.severity == "HIGH" and a.evidence["function_code"] == 16
        assert a.mitre_techniques[0] == "T0855" and "T0831" in a.mitre_techniques
        assert a.evidence["known_function_codes"] == [3, 6]

    def test_benign_new_function_is_medium(self):
        events = baseline() + [ev(150, fc=17, name="Report Server ID", op_type="DIAGNOSTIC",
                                  details={"op": "IDENTIFY", "is_request": True}),
                               ev(160, fc=17, name="Report Server ID", op_type="DIAGNOSTIC",
                                  details={"op": "IDENTIFY", "is_request": True})]
        a = only(BehaviorProfiler().analyze(events), "OT_NEW_FUNCTION")
        assert a.severity == "MEDIUM" and a.timestamp == 150
        assert a.evidence["event_count"] == 2

    def test_new_function_in_learning_is_not_flagged(self):
        events = baseline() + [ev(20, fc=17, details={"op": "IDENTIFY", "is_request": True}),
                               ev(220, fc=17, details={"op": "IDENTIFY", "is_request": True})]
        assert BehaviorProfiler().analyze(events) == []


def goose(ts, src="00:11:22:33:44:55", dst="01:0c:cd:01:00:01", fc=0, cyclic=True, **extra):
    d = {"op": "PUBLISH", "is_request": None, "cyclic": cyclic, "target": "LD0/LLN0$GO$gcb1"}
    d.update(extra)
    return ev(ts, src=src, dst=dst, sport=0, dport=0, proto=OTProtocol.IEC_61850_GOOSE,
              fc=fc, name="GOOSE", op_type="PUBLISH", details=d)


class TestMacAddresses:
    def stable(self):
        return [goose(t * 0.5) for t in range(600)]

    def test_stable_goose_no_alerts(self):
        assert BehaviorProfiler().analyze(self.stable()) == []

    def test_new_goose_publisher(self):
        events = self.stable() + [goose(250, src="aa:bb:cc:dd:ee:ff")]
        a = only(BehaviorProfiler().analyze(events), "OT_NEW_MASTER")
        assert a.src_ip == "aa:bb:cc:dd:ee:ff" and "IEC_61850_GOOSE publisher" in a.description
        assert a.evidence["role"] == "publisher"

    def test_cyclic_publication_new_fc_ignored(self):
        events = self.stable() + [goose(250, fc=7)]
        assert BehaviorProfiler().analyze(events) == []

    def test_layer2_request_new_master(self):
        dcp = lambda t, src: ev(t, src=src, dst="00:0e:8c:00:00:01", sport=0, dport=0,  # noqa
                                proto=OTProtocol.PROFINET_DCP, fc=4, name="DCP Set",
                                op_type="WRITE",
                                details={"op": "SET_NAME", "is_request": True})
        events = self.stable() + [dcp(t, "00:1b:1b:aa:bb:cc") for t in range(0, 60, 5)] + \
            [dcp(260, "de:ad:be:ef:00:01")]
        a = only(BehaviorProfiler().analyze(events), "OT_NEW_MASTER")
        assert a.severity == "HIGH" and a.dst_ip == "00:0e:8c:00:00:01"

    def test_new_layer2_device(self):
        events = self.stable() + [goose(250, src="aa:bb:cc:dd:ee:ff", dst="01:0c:cd:01:00:09")]
        a = only(BehaviorProfiler().analyze(events), "OT_NEW_DEVICE")
        assert a.evidence["device"] == "aa:bb:cc:dd:ee:ff" and a.evidence["role"] == "publisher"


class TestPollingDeviation:
    def test_polling_stopped(self):
        events = baseline(skip=lambda e: e.function_code == 3 and e.timestamp >= 200)
        a = only(BehaviorProfiler().analyze(events), "OT_POLLING_DEVIATION")
        assert a.evidence["deviation"] == "STOPPED" and a.evidence["function_code"] == 3
        assert a.evidence["expected_period"] == pytest.approx(1.0)
        assert a.evidence["polling_resumed"] is False
        assert a.mitre_techniques == ["T0814", "T0815"] and a.severity == "MEDIUM"

    def test_polling_interrupted(self):
        events = baseline(skip=lambda e: e.function_code == 3 and 150 <= e.timestamp < 180)
        a = only(BehaviorProfiler().analyze(events), "OT_POLLING_DEVIATION")
        assert a.evidence["deviation"] == "INTERRUPTED"
        assert a.evidence["gap_seconds"] == pytest.approx(31.0)
        assert a.evidence["polling_resumed"] is True

    def test_short_jitter_is_not_a_gap(self):
        events = baseline(skip=lambda e: e.function_code == 3 and 150 <= e.timestamp < 154)
        assert BehaviorProfiler().analyze(events) == []

    def test_polling_storm(self):
        events = baseline() + [read_req(200 + i * 0.01) for i in range(200)]
        out = BehaviorProfiler().analyze(events)
        a = only(out, "OT_POLLING_DEVIATION")
        assert a.evidence["deviation"] == "STORM" and a.evidence["max_in_window"] > 50
        assert a.mitre_techniques == ["T0814"]

    def test_irregular_flow_not_profiled(self):
        rnd = random.Random(3)
        events, t = [], 0.0
        while t < 300:
            events.append(read_req(t))
            t += rnd.choice([0.1, 3.0, 9.0])
        events = [e for e in events if not (150 <= e.timestamp < 200)]
        assert [a for a in BehaviorProfiler().analyze(events)
                if a.anomaly_type == "OT_POLLING_DEVIATION"] == []


class TestValueOutOfRange:
    def test_out_of_range_write(self):
        events = baseline() + [write_req(250, 5000), write_req(251, 4000),
                               write_req(252, -900)]
        a = only(BehaviorProfiler().analyze(events), "OT_VALUE_OUT_OF_RANGE")
        e = a.evidence
        assert a.severity == "HIGH" and a.mitre_techniques == ["T0836", "T0831"]
        assert e["value"] == 5000 and e["occurrences"] == 3 and e["target"] == "HR 40100"
        assert e["learned_min"] == 98 and e["learned_max"] == 102
        assert e["learned_median"] == 100 and e["learned_mad"] == 1
        assert a.timestamp == 250 and "learning_end" in e

    def test_small_excursion_not_flagged(self):
        events = baseline() + [write_req(250, 103)]
        assert BehaviorProfiler().analyze(events) == []

    def test_fallback_target_is_data_address(self):
        def w(t, v):
            e = write_req(t, v)
            del e.details["target"]
            return e
        events = [e for e in baseline() if e.operation_type != "WRITE"]
        events += [w(t + 0.2, 10 + t % 3) for t in range(5, 300, 10)] + [w(250.5, 900)]
        a = only(BehaviorProfiler().analyze(events), "OT_VALUE_OUT_OF_RANGE")
        assert a.evidence["target"] == "40100"

    def test_not_enough_samples(self):
        events = [e for e in baseline() if e.operation_type != "WRITE"]
        events += [write_req(10, 100), write_req(20, 100), write_req(250, 9999)]
        assert [a for a in BehaviorProfiler().analyze(events)
                if a.anomaly_type == "OT_VALUE_OUT_OF_RANGE"] == []


# =========================================================================== rules engine

def rule(rid="R1", **match):
    return {"id": rid, "name": f"rule {rid}", "match": match}


def fires(spec, event):
    return bool(RuleEngine([spec]).evaluate(event))


class TestRuleMatching:
    def test_basic_anomaly_fields(self):
        spec = {"id": "OTR-001.a", "name": "Modbus write", "severity": "high",
                "description": "desc", "mitre": ["T0836"],
                "match": {"protocol": "modbus_tcp", "op": ["WRITE"]}}
        eng = RuleEngine([spec])
        assert len(eng) == 1
        out = eng.evaluate(write_req(5, 42))
        assert len(out) == 1
        a = out[0]
        assert a.anomaly_type == "CUSTOM_OTR_001_A" and a.severity == "HIGH"
        assert a.description == "Modbus write: desc" and a.confidence == 0.8
        assert a.mitre_techniques == ["T0836"] and a.protocol == "MODBUS_TCP"
        m = a.evidence["matched_event"]
        assert a.evidence["rule_id"] == "OTR-001.a" and a.evidence["rule_name"] == "Modbus write"
        assert m == {"function_name": "Write Single Register", "function_code": 6,
                     "op": "WRITE", "target": "HR 40100", "value": 42}
        assert a.recommendation

    def test_mitre_defaults_to_event(self):
        a = RuleEngine([rule(op="WRITE")]).evaluate(write_req(0, 1))[0]
        assert a.mitre_techniques == ["T0831", "T0836"]

    def test_protocol(self):
        assert fires(rule(protocol=["DNP3", "MODBUS_TCP"]), read_req(0))
        assert not fires(rule(protocol="S7COMM"), read_req(0))
        assert fires(rule(protocol=OTProtocol.MODBUS_TCP), read_req(0))

    def test_op_and_fallback_and_prefix(self):
        assert fires(rule(op="read"), read_req(0))
        assert fires(rule(op="WRITE"), write_req(0, 1, with_details=False))   # from op type
        ctrl = ev(0, details={"op": "CONTROL_EXECUTE"})
        assert fires(rule(op="CONTROL_*"), ctrl)
        assert not fires(rule(op="CONTROL_*"), read_req(0))
        assert fires(rule(op="CONTROL"), ev(0, op_type="CONTROL"))

    def test_function_code_hex(self):
        e = ev(0, fc=16)
        assert fires(rule(function_code=["0x10"]), e)
        assert fires(rule(function_code=16), e)
        assert not fires(rule(function_code=[5, 6]), e)

    def test_operation_type_risk_unit(self):
        e = write_req(0, 1)
        assert fires(rule(operation_type="write", risk_level=["MEDIUM", "HIGH"], unit_id=[1]), e)
        assert not fires(rule(risk_level="CRITICAL"), e)
        assert not fires(rule(unit_id=2), e)

    def test_ip_cidr_and_negation(self):
        spec = rule(src_ip=["10.0.0.0/8", "!10.1.2.3", "!192.168.10.0/24"])
        assert fires(spec, read_req(0, src="10.9.9.9"))
        assert not fires(spec, read_req(0, src="10.1.2.3"))
        assert not fires(spec, read_req(0, src="172.16.0.1"))
        only_neg = rule(src_ip=["!10.0.0.0/24", "!192.168.10.0/24"])
        assert fires(only_neg, read_req(0, src="10.0.1.1"))
        assert not fires(only_neg, read_req(0, src="192.168.10.7"))
        assert fires(rule(dst_ip="any"), read_req(0))
        assert fires(rule(dst_ip=["any", "!10.0.0.21"]), read_req(0))
        assert not fires(rule(dst_ip=["any", "!10.0.0.20"]), read_req(0))

    def test_ipv6(self):
        spec = rule(src_ip="fd00::/8")
        assert fires(spec, read_req(0, src="fd00::1"))
        assert not fires(spec, read_req(0, src="10.0.0.1"))
        assert not fires(rule(src_ip="10.0.0.0/8"), read_req(0, src="fd00::1"))

    def test_mac_addresses(self):
        g = goose(0)
        assert fires(rule(src_ip="00:11:22:33:44:55"), g)
        assert fires(rule(src_ip="00-11-22-33-44-55"), g)
        assert not fires(rule(src_ip="!00:11:22:33:44:55"), g)
        assert fires(rule(src_ip="!aa:bb:cc:dd:ee:ff"), g)
        assert not fires(rule(src_ip="10.0.0.0/8"), g)          # MAC never in a CIDR

    def test_ports(self):
        spec = rule(dst_port=[502, "20000-20010"])
        assert fires(spec, read_req(0))
        assert fires(spec, ev(0, dport=20005))
        assert not fires(spec, ev(0, dport=20011))
        assert fires(rule(src_port="49152-65535"), read_req(0))
        assert not fires(rule(src_port=["!50000"]), read_req(0))

    def test_target_regex(self):
        e = ev(0, details={"target": "CA=1 IOA=4001"})
        assert fires(rule(target=r"IOA=40[0-9]{2}\b"), e)
        assert not fires(rule(target=r"IOA=5\d+"), e)
        assert not fires(rule(target="."), ev(0))                # no target -> no match

    def test_value_comparisons(self):
        e = write_req(0, 150)
        assert fires(rule(value_gt=100), e)
        assert not fires(rule(value_gt=150), e)
        assert fires(rule(value_ge=150, value_le=150, value_eq=150), e)
        assert fires(rule(value_lt=150.5), e)
        assert not fires(rule(value_lt=150), e)
        assert not fires(rule(value_gt=0), read_req(0))         # no value
        assert not fires(rule(value_gt=0), ev(0, details={"value": True}))

    def test_details_equality(self):
        e = goose(0, goose_test=True, iec104_select=False)
        assert fires(rule(details={"goose_test": True}), e)
        assert fires(rule(details={"goose_test": True, "iec104_select": False}), e)
        assert not fires(rule(details={"goose_test": False}), e)
        assert not fires(rule(details={"goose_test": 1}), e)     # strict bool
        assert not fires(rule(details={"missing": True}), e)

    def test_is_request(self):
        assert fires(rule(is_request=True), read_req(0))
        assert fires(rule(is_request=False), read_resp(0))
        assert fires(rule(is_request=True), read_req(0, with_details=False))   # inferred

    def test_no_match_section_matches_all(self):
        assert fires({"id": "ALL", "name": "everything"}, read_req(0))

    def test_disabled_rule(self):
        spec = dict(rule(op="READ"), enabled=False)
        eng = RuleEngine([spec])
        assert len(eng) == 1 and eng.evaluate(read_req(0)) == []

    def test_protocol_index(self):
        eng = RuleEngine([rule("A", protocol="DNP3"), rule("B", protocol="MODBUS_TCP"),
                          rule("C", op="READ")])
        assert sorted(a.evidence["rule_id"] for a in eng.evaluate(read_req(0))) == ["B", "C"]


class TestThresholdCooldown:
    def test_threshold_group_by(self):
        spec = dict(rule(op="WRITE"),
                    threshold={"count": 5, "seconds": 10, "group_by": ["src_ip", "dst_ip"]},
                    cooldown_seconds=0)
        eng = RuleEngine([spec])
        out = []
        for i in range(4):
            out += eng.evaluate(write_req(i, 1))
            out += eng.evaluate(write_req(i + 0.5, 1, src="10.0.0.99"))
        assert out == []
        out = eng.evaluate(write_req(4, 1))
        assert len(out) == 1
        e = out[0].evidence
        assert e["count"] == 5 and e["window_seconds"] == 10
        assert e["group"] == {"src_ip": MASTER, "dst_ip": PLC}
        assert "5 matching events" in out[0].description
        # counter restarts after an alert
        assert eng.evaluate(write_req(4.5, 1)) == []

    def test_threshold_window_expires(self):
        spec = dict(rule(op="WRITE"), threshold={"count": 3, "seconds": 5})
        eng = RuleEngine([spec])
        out = []
        for t in (0, 4, 8, 12, 16):                  # never 3 within 5 s
            out += eng.evaluate(write_req(t, 1))
        assert out == []
        out += eng.evaluate(write_req(16.5, 1, src="10.0.0.5"))   # global group: 12,16,16.5
        assert len(out) == 1

    def test_cooldown_default_and_custom(self):
        eng = RuleEngine([rule(op="READ")])
        alerts = [a for t in range(0, 130) for a in eng.evaluate(read_req(t))]
        assert [a.timestamp for a in alerts] == [0, 60, 120]
        eng = RuleEngine([dict(rule(op="READ"), cooldown_seconds=0)])
        assert sum(len(eng.evaluate(read_req(t))) for t in range(10)) == 10
        # cooldown is per (src, dst) pair
        eng = RuleEngine([dict(rule(op="READ"), cooldown_seconds=300)])
        assert len(eng.evaluate(read_req(0))) == 1
        assert len(eng.evaluate(read_req(1))) == 0
        assert len(eng.evaluate(read_req(2, src="10.0.0.12"))) == 1

    def test_threshold_with_cooldown(self):
        spec = dict(rule(op="WRITE"), threshold={"count": 2, "seconds": 10},
                    cooldown_seconds=100)
        eng = RuleEngine([spec])
        alerts = [a for t in range(0, 120) for a in eng.evaluate(write_req(t, 1))]
        assert [a.timestamp for a in alerts] == [1, 101]

    def test_reset(self):
        eng = RuleEngine([rule(op="READ")])
        assert eng.evaluate(read_req(0)) and not eng.evaluate(read_req(1))
        eng.reset()
        assert eng.evaluate(read_req(2))


class TestRuleErrors:
    @pytest.mark.parametrize("spec, fragment", [
        ({"name": "x"}, "id"),
        ({"id": "bad id!", "name": "x"}, "invalid id"),
        ({"id": "E1"}, "'name'"),
        ({"id": "E1", "name": "x", "severity": "URGENT"}, "severity"),
        ({"id": "E1", "name": "x", "matchh": {}}, "matchh"),
        (rule("E1", srcip="10.0.0.1"), "srcip"),
        (rule("E1", protocol="MODBUSS"), "MODBUSS"),
        (rule("E1", op="EXPLODE"), "EXPLODE"),
        (rule("E1", function_code="sixteen"), "function_code"),
        (rule("E1", src_ip="10.0.0.300"), "src_ip"),
        (rule("E1", dst_port="70000"), "dst_port"),
        (rule("E1", dst_port="20-10"), "dst_port"),
        (rule("E1", target="(unclosed"), "target"),
        (rule("E1", value_gt="big"), "value_gt"),
        (rule("E1", details=["x"]), "details"),
        (rule("E1", is_request="yes"), "is_request"),
        (rule("E1", risk_level="SEVERE"), "risk_level"),
        (rule("E1", op=[]), "op"),
        (dict(rule("E1"), threshold={"count": 5}), "threshold"),
        (dict(rule("E1"), threshold={"count": 5, "seconds": 1, "group_by": ["host"]}), "host"),
        (dict(rule("E1"), cooldown_seconds=-1), "cooldown_seconds"),
        (dict(rule("E1"), enabled="no"), "enabled"),
    ])
    def test_invalid_rules(self, spec, fragment):
        with pytest.raises(RuleError) as exc:
            RuleEngine().add_rule(spec)
        msg = str(exc.value)
        assert fragment in msg
        if spec.get("id") == "E1":
            assert "E1" in msg

    def test_suggestion_and_duplicates(self):
        with pytest.raises(RuleError, match="did you mean 'src_ip'"):
            Rule(rule("E2", srcip="10.0.0.1"))
        eng = RuleEngine([rule("D1")])
        with pytest.raises(RuleError, match="D1.*duplicate"):
            eng.add_rule(rule("D1"))
        assert isinstance(RuleError("x"), ValueError)


class TestLoading:
    def test_json_list_and_mapping(self, tmp_path):
        (tmp_path / "a.json").write_text(json.dumps([rule("J1", op="READ")]))
        (tmp_path / "b.json").write_text(json.dumps({"rules": [rule("J2", op="WRITE")]}))
        eng = RuleEngine.from_paths([tmp_path / "a.json", str(tmp_path / "b.json")])
        assert sorted(r.id for r in eng.rules) == ["J1", "J2"]
        assert eng.evaluate(read_req(0))[0].evidence["rule_id"] == "J1"

    def test_directory_loading_and_skips(self, tmp_path, caplog):
        caplog.set_level(logging.WARNING, logger=LOGGER)
        (tmp_path / "good.json").write_text(json.dumps(
            {"rules": [rule("G1"), rule("BAD-7", nope=1), rule("G2", op="WRITE")]}))
        (tmp_path / "broken.json").write_text("{not json")
        (tmp_path / "scalar.json").write_text("42")
        (tmp_path / "empty.json").write_text("")
        (tmp_path / "notes.txt").write_text("ignored")
        eng = RuleEngine.from_paths(tmp_path)
        assert sorted(r.id for r in eng.rules) == ["G1", "G2"]
        text = caplog.text
        assert "BAD-7" in text and "good.json" in text and "broken.json" in text
        assert "scalar.json" in text and "notes.txt" not in text

    def test_missing_path_warns(self, tmp_path, caplog):
        caplog.set_level(logging.WARNING, logger=LOGGER)
        eng = RuleEngine.from_paths([tmp_path / "nope.yml"])
        assert len(eng) == 0 and "nope.yml" in caplog.text

    def test_yaml_loading(self, tmp_path, caplog):
        pytest.importorskip("yaml")
        caplog.set_level(logging.WARNING, logger=LOGGER)
        (tmp_path / "r.yml").write_text(
            "- id: Y1\n  name: yaml rule\n  match:\n    protocol: [modbus_tcp]\n"
            "    function_code: ['0x06']\n"
            "- id: Y2\n  name: bad\n  match: {op: [NOPE]}\n")
        (tmp_path / "s.yaml").write_text("rules:\n  - id: Y3\n    name: three\n")
        (tmp_path / "bad.yaml").write_text("rules: [unclosed\n")
        eng = RuleEngine.from_paths([tmp_path])
        assert sorted(r.id for r in eng.rules) == ["Y1", "Y3"]
        assert "Y2" in caplog.text and "bad.yaml" in caplog.text
        assert eng.evaluate(write_req(0, 1))

    def test_yaml_without_pyyaml(self, tmp_path, caplog, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no yaml")
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", fake_import)
        caplog.set_level(logging.WARNING, logger=LOGGER)
        (tmp_path / "r.yml").write_text("- id: Y1\n  name: x\n")
        (tmp_path / "r.json").write_text(json.dumps([rule("J1")]))
        eng = RuleEngine.from_paths(tmp_path)
        assert [r.id for r in eng.rules] == ["J1"]
        assert "PyYAML" in caplog.text and "r.yml" in caplog.text

    def test_default_locations(self, tmp_path):
        assert len(RuleEngine.from_default_locations()) == 0
        d = os.path.join(os.environ["HOME"], ".ot_pcap_analyzer", "rules")
        os.makedirs(d)
        with open(os.path.join(d, "x.json"), "w") as fh:
            json.dump([rule("H1")], fh)
        assert [r.id for r in RuleEngine.from_default_locations().rules] == ["H1"]

    def test_example_rules_file(self, caplog):
        pytest.importorskip("yaml")
        caplog.set_level(logging.WARNING, logger=LOGGER)
        eng = RuleEngine.from_paths([EXAMPLE_RULES])
        assert "skipping" not in caplog.text and "invalid" not in caplog.text.lower()
        assert 6 <= len(eng) <= 10
        hits = eng.evaluate(write_req(0, 1, src="10.20.0.5"))
        assert "CUSTOM_OTR_001" in types(hits)
        stop = ev(1, src="10.30.0.4", proto=OTProtocol.S7COMM, dport=102, fc=0x29,
                  name="PLC Stop", op_type="CONTROL", risk="CRITICAL",
                  details={"op": "PLC_STOP", "is_request": True})
        assert {"CUSTOM_OTR_002", "CUSTOM_OTR_008"} <= set(types(eng.evaluate(stop)))
        sp = write_req(2, 1500, src="10.10.5.3", dst="10.10.1.15", target="HR 40100")
        assert "CUSTOM_OTR_007" in types(eng.evaluate(sp))


# =========================================================================== performance

def test_performance_smoke():
    rnd = random.Random(7)
    masters = [f"10.0.1.{i}" for i in range(20)]
    plcs = [f"10.0.2.{i}" for i in range(10)]
    events = []
    t = 0.0
    for i in range(200_000):
        t += 0.005
        m = masters[i % 20]
        p = plcs[(i // 20) % 10]
        if i % 50 == 0:
            events.append(write_req(t, 100 + rnd.random(), src=m, dst=p))
        elif i % 2:
            events.append(read_req(t, src=m, dst=p, fc=3 + (i % 3 == 0)))
        else:
            events.append(read_resp(t, src=p, dst=m))
    start = time.perf_counter()
    BehaviorProfiler().analyze(events)
    assert time.perf_counter() - start < 20

    specs = []
    for k in range(20):
        specs.append({"id": f"P{k}", "name": f"perf {k}",
                      "match": {"protocol": ["MODBUS_TCP", "DNP3"][k % 2],
                                "op": ["WRITE", "READ"][k % 2],
                                "src_ip": ["10.0.0.0/8", f"!10.0.1.{k}"],
                                "dst_port": [502, "20000-20010"],
                                "target": "HR \\d+"},
                      "threshold": {"count": 10, "seconds": 1,
                                    "group_by": ["src_ip", "dst_ip"]}})
    eng = RuleEngine(specs)
    start = time.perf_counter()
    for e in events[:100_000]:
        eng.evaluate(e)
    assert time.perf_counter() - start < 20
