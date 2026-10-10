"""The committed sample captures stay in sync with the factory and analyse as documented."""
from pathlib import Path

import pytest

import pcap_factory
from ot_pcap_analyzer import AnalyzerConfig, OTAnalyzer

SAMPLES = Path(__file__).resolve().parents[1] / "samples"

BUILDERS = {
    "benign_plant.pcap": pcap_factory.build_benign,
    "ot_protocols.pcap": pcap_factory.build_ot_protocols,
    "attack_scenarios.pcap": pcap_factory.build_attacks,
}


def _frames(path):
    # Byte-level hashes are not portable: scapy fills in missing destination MACs
    # from the host it runs on. Packet count and IP-layer content are.
    from scapy.all import IP, rdpcap
    return [(len(p), bytes(p[IP]) if IP in p else b"") for p in rdpcap(str(path))]


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_sample_matches_factory(name, tmp_path):
    committed = SAMPLES / name
    assert committed.exists(), f"missing samples/{name} - run scripts/generate_samples.py"
    fresh = BUILDERS[name](tmp_path / name)
    assert _frames(committed) == _frames(fresh), (
        f"samples/{name} is out of date - run scripts/generate_samples.py")


def _analyse(name):
    analyzer = OTAnalyzer(AnalyzerConfig(enable_correlation=True, enable_storyline=True))
    analyzer.analyze_capture(str(SAMPLES / name))
    return analyzer


def test_benign_sample_is_quiet():
    assert _analyse("benign_plant.pcap").get_summary()["ANOMALIES_DETECTED"] == 0


def test_attack_sample_produces_alerts_and_chain():
    summary = _analyse("attack_scenarios.pcap").get_summary()
    assert summary["ANOMALIES_DETECTED"] > 0
    assert summary["ATTACK_CHAINS"] >= 1
