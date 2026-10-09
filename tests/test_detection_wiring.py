"""Custom rules and behaviour profiling are wired into the analysis pipeline."""
import json

import pytest

from ot_pcap_analyzer.analyzer import OTAnalyzer
from ot_pcap_analyzer.models import AnalyzerConfig

RULE = {"rules": [{
    "id": "TEST-MODBUS-WRITE",
    "name": "Any Modbus write",
    "severity": "HIGH",
    "match": {"protocol": ["MODBUS_TCP"], "function_code": [5, 6, 15, 16]},
}]}


def _types(analyzer):
    return {a.anomaly_type for a in analyzer.anomalies}


def test_rule_file_from_config(captures, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(RULE))
    a = OTAnalyzer(AnalyzerConfig(rule_paths=[str(path)]))
    a.analyze_capture(captures["attacks"])
    assert "CUSTOM_TEST_MODBUS_WRITE" in _types(a)


def test_rules_from_home_directory(captures, tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ot_pcap_analyzer" / "rules").mkdir(parents=True)
    (home / ".ot_pcap_analyzer" / "rules" / "r.json").write_text(json.dumps(RULE))
    monkeypatch.setenv("HOME", str(home))
    a = OTAnalyzer(AnalyzerConfig())
    a.analyze_capture(captures["attacks"])
    assert "CUSTOM_TEST_MODBUS_WRITE" in _types(a)

    b = OTAnalyzer(AnalyzerConfig(load_default_rules=False))
    b.analyze_capture(captures["attacks"])
    assert "CUSTOM_TEST_MODBUS_WRITE" not in _types(b)


def test_broken_rule_file_does_not_stop_analysis(captures, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    a = OTAnalyzer(AnalyzerConfig(rule_paths=[str(bad)]))
    a.analyze_capture(captures["attacks"])
    assert a.anomalies                     # normal detections still run


def test_no_rules_means_no_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert OTAnalyzer(AnalyzerConfig())._rule_engine is None


def test_behaviour_profiling_can_be_disabled(captures, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    behaviour = {"OT_NEW_MASTER", "OT_NEW_DEVICE", "OT_NEW_FUNCTION",
                 "OT_POLLING_DEVIATION", "OT_VALUE_OUT_OF_RANGE"}
    off = OTAnalyzer(AnalyzerConfig(enable_behavior_profiling=False))
    off.analyze_capture(captures["attacks"])
    assert not (_types(off) & behaviour)
    on = OTAnalyzer(AnalyzerConfig())
    on.analyze_capture(captures["attacks"])   # must not fail; results depend on the capture
    assert len(on.anomalies) >= len(off.anomalies)


def test_benign_capture_stays_quiet_with_profiling(captures, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    a = OTAnalyzer(AnalyzerConfig())
    a.analyze_capture(captures["benign"])
    assert a.anomalies == []


@pytest.mark.parametrize("value", [0, 1, 1.5, -0.1])
def test_learning_fraction_validation(value):
    if 0 < value < 1:
        AnalyzerConfig(behavior_learning_fraction=value)
    else:
        with pytest.raises(ValueError):
            AnalyzerConfig(behavior_learning_fraction=value)
