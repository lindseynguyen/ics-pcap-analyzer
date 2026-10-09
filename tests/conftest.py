"""Shared pytest fixtures: synthetic captures and cached analysis results."""
import logging
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pcap_factory  # noqa: E402

logging.getLogger("OT_PCAP_ANALYZER").setLevel(logging.ERROR)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Keep ~/.ot_pcap_analyzer (history DB, caches) out of the real home directory."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    os.makedirs(tmp_path / "home", exist_ok=True)


@pytest.fixture(scope="session")
def captures(tmp_path_factory):
    d = tmp_path_factory.mktemp("captures")
    return {
        name: str(getattr(pcap_factory, f"build_{name}")(d / f"{name}.pcap"))
        for name in ("benign", "ot_protocols", "attacks", "edge_cases")
    }


def _analyze(path, **cfg):
    from ot_pcap_analyzer.analyzer import OTAnalyzer
    from ot_pcap_analyzer.models import AnalyzerConfig
    a = OTAnalyzer(AnalyzerConfig(**cfg))
    a.analyze_capture(path)
    return a


@pytest.fixture(scope="session")
def analyzed(captures):
    """Analyzer instances (default config) for every synthetic capture, computed once."""
    return {name: _analyze(path) for name, path in captures.items()}


@pytest.fixture
def analyze():
    return _analyze
