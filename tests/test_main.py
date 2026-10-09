"""In-process tests for the CLI / GUI entry points in ot_pcap_analyzer.main."""
import sys
import types

import pytest

from ot_pcap_analyzer import main as m
from ot_pcap_analyzer.analyzer import OTAnalyzer
from ot_pcap_analyzer.version import VERSION


@pytest.fixture(autouse=True)
def _quiet_logging(monkeypatch):
    # run_cli calls logging.basicConfig(INFO); keep it from changing global logging state
    monkeypatch.setattr(m, "setup_logging", lambda level="INFO": None)


@pytest.fixture
def no_gui(monkeypatch):
    calls = []
    monkeypatch.setattr(m, "run_gui", lambda: calls.append("gui"))
    return calls


@pytest.fixture
def exports(monkeypatch):
    """Record export_excel calls instead of writing workbooks (fast)."""
    paths = []
    monkeypatch.setattr(OTAnalyzer, "export_excel", lambda self, p: paths.append(p))
    return paths


# --------------------------------------------------------------------------- run_cli

def test_run_cli_exports_real_report(captures, tmp_path, capsys):
    out = tmp_path / "report.xlsx"
    analyzer = m.run_cli(captures["benign"], output=str(out))
    assert isinstance(analyzer, OTAnalyzer)
    assert analyzer.config.use_ml is True and analyzer.config.enable_correlation is False
    assert out.exists() and out.stat().st_size > 0
    text = capsys.readouterr().out
    assert "ANALYSIS SUMMARY" in text
    assert f"Report exported: {out}" in text
    summary = analyzer.get_summary()
    scalar_key = next(k for k, v in summary.items() if not isinstance(v, dict))
    assert f"  {scalar_key}: {summary[scalar_key]}" in text


def test_run_cli_default_output_name(captures, tmp_path, monkeypatch, capsys, exports):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(m, "timestamp", lambda: "20260101_000000")
    m.run_cli(captures["benign"])
    assert exports == ["ot_security_report_20260101_000000.xlsx"]
    assert "Report exported: ot_security_report_20260101_000000.xlsx" in capsys.readouterr().out


def test_run_cli_max_packets_and_advanced(captures, capsys, exports, monkeypatch):
    seen = {}
    orig = OTAnalyzer.analyze_capture

    def spy(self, path, max_packets=None):
        seen["max_packets"] = max_packets
        return orig(self, path, max_packets)

    monkeypatch.setattr(OTAnalyzer, "analyze_capture", spy)
    a = m.run_cli(captures["attacks"], output="x.xlsx", max_packets=100000, enable_advanced=True)
    assert seen["max_packets"] == 100000
    assert a.config.enable_correlation and a.config.enable_baseline and a.config.enable_storyline
    assert exports == ["x.xlsx"]
    out = capsys.readouterr().out
    assert a.attack_chains, "attacks capture should yield at least one correlated chain"
    assert f"ATTACK CHAINS DETECTED: {len(a.attack_chains)}" in out
    c = a.attack_chains[0]
    assert f"{c.chain_id}: {c.overall_severity} - {c.phase_count} phases" in out


def test_run_cli_basic_mode_never_prints_chains(captures, capsys, exports):
    a = m.run_cli(captures["attacks"], output="x.xlsx")
    assert a.config.enable_correlation is False
    assert "ATTACK CHAINS" not in capsys.readouterr().out


def test_run_cli_prints_attack_chains(captures, capsys, exports, monkeypatch):
    chain = types.SimpleNamespace(chain_id="CHAIN-1", overall_severity="CRITICAL", phase_count=3,
                                  ot_escalation_score=0.0)
    orig = OTAnalyzer.analyze_capture

    def fake(self, path, max_packets=None):
        orig(self, path, max_packets)
        self.attack_chains = [chain] * 7

    monkeypatch.setattr(OTAnalyzer, "analyze_capture", fake)
    m.run_cli(captures["benign"], output="r.xlsx", enable_advanced=True)
    out = capsys.readouterr().out
    assert "ATTACK CHAINS DETECTED: 7" in out
    assert out.count("CHAIN-1: CRITICAL - 3 phases") == 5  # only the first five are listed


def test_run_cli_progress_callback(captures, exports, monkeypatch):
    messages = []
    monkeypatch.setattr(m.logger, "info", lambda msg, *a, **k: messages.append(msg))
    a = m.run_cli(captures["benign"], output="r.xlsx")
    a.progress_callback(2000, 5000, "progress-2000")
    a.progress_callback(1500, 5000, "progress-1500")
    assert "progress-2000" in messages and "progress-1500" not in messages
    assert any(VERSION in msg for msg in messages)


def test_run_cli_analysis_failure_exits_1(tmp_path, exports):
    with pytest.raises(SystemExit) as exc:
        m.run_cli(str(tmp_path / "missing.pcap"))
    assert exc.value.code == 1
    assert exports == []


@pytest.mark.parametrize("output", ["explicit.xlsx", None])
def test_run_cli_export_failure_is_not_fatal(captures, monkeypatch, capsys, output, tmp_path):
    monkeypatch.chdir(tmp_path)

    def boom(self, p):
        raise PermissionError("read-only")

    monkeypatch.setattr(OTAnalyzer, "export_excel", boom)
    analyzer = m.run_cli(captures["benign"], output=output)
    assert isinstance(analyzer, OTAnalyzer)
    captured = capsys.readouterr()
    assert "Report exported" not in captured.out
    assert "PermissionError" in captured.err  # traceback printed


# --------------------------------------------------------------------------- main()

@pytest.mark.parametrize("argv", [[], ["--gui"]])
def test_main_launches_gui(monkeypatch, no_gui, argv):
    monkeypatch.setattr(sys, "argv", ["ot_pcap_analyzer", *argv])
    m.main()
    assert no_gui == ["gui"]


def test_main_cli_passes_arguments(monkeypatch, no_gui):
    seen = []
    monkeypatch.setattr(m, "run_cli", lambda *a, **k: seen.append((a, k)))
    monkeypatch.setattr(sys, "argv", ["prog", "--cli", "cap.pcap", "-o", "r.xlsx", "-m", "100",
                                      "--advanced", "--gui", "--rules", "a.yml", "--rules", "dir",
                                      "--no-behavior"])
    m.main()
    assert seen == [(("cap.pcap", "r.xlsx", 100, True),
                     {"rule_paths": ["a.yml", "dir"], "behavior": False})]
    assert no_gui == []  # --cli wins over --gui


def test_main_cli_defaults(monkeypatch, no_gui):
    seen = []
    monkeypatch.setattr(m, "run_cli", lambda *a, **k: seen.append((a, k)))
    monkeypatch.setattr(sys, "argv", ["prog", "--cli", "cap.pcap"])
    m.main()
    assert seen == [(("cap.pcap", None, None, False), {"rule_paths": [], "behavior": True})]


def test_main_cli_end_to_end(monkeypatch, captures, tmp_path, no_gui, capsys):
    out = tmp_path / "e2e.xlsx"
    monkeypatch.setattr(sys, "argv", ["prog", "--cli", captures["ot_protocols"], "--output", str(out)])
    m.main()
    assert out.exists()
    assert "ANALYSIS SUMMARY" in capsys.readouterr().out


def test_main_version(monkeypatch, capsys, no_gui):
    monkeypatch.setattr(sys, "argv", ["ot_pcap_analyzer", "--version"])
    with pytest.raises(SystemExit) as exc:
        m.main()
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"ot_pcap_analyzer {VERSION}"


@pytest.mark.parametrize("argv", [["--bogus"], ["--max-packets", "lots", "--cli", "x"], ["--cli"]])
def test_main_bad_arguments_exit_2(monkeypatch, capsys, no_gui, argv):
    monkeypatch.setattr(sys, "argv", ["prog", *argv])
    with pytest.raises(SystemExit) as exc:
        m.main()
    assert exc.value.code == 2
    assert "usage:" in capsys.readouterr().err
    assert no_gui == []


def test_dunder_main_imports_main():
    import ot_pcap_analyzer.__main__ as dm
    assert dm.main is m.main


# --------------------------------------------------------------------------- run_gui()

def test_run_gui_starts_gui_module(monkeypatch):
    started = []
    fake = types.ModuleType("ot_pcap_analyzer.gui")
    fake.run_gui = lambda: started.append(True)
    monkeypatch.setitem(sys.modules, "ot_pcap_analyzer.gui", fake)
    import ot_pcap_analyzer
    monkeypatch.setattr(ot_pcap_analyzer, "gui", fake, raising=False)
    m.run_gui()
    assert started == [True]


def test_run_gui_without_pyqt_exits_1(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "PyQt5.QtWidgets", None)  # forces ImportError
    with pytest.raises(SystemExit) as exc:
        m.run_gui()
    assert exc.value.code == 1
    assert "PyQt5 is not installed" in capsys.readouterr().out


def test_run_gui_startup_error_exits_1(monkeypatch, capsys):
    fake = types.ModuleType("ot_pcap_analyzer.gui")

    def broken():
        raise RuntimeError("no display")

    fake.run_gui = broken
    monkeypatch.setitem(sys.modules, "ot_pcap_analyzer.gui", fake)
    import ot_pcap_analyzer
    monkeypatch.setattr(ot_pcap_analyzer, "gui", fake, raising=False)
    with pytest.raises(SystemExit) as exc:
        m.run_gui()
    assert exc.value.code == 1
    assert "Could not start GUI. no display" in capsys.readouterr().out
