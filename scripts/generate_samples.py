"""Regenerate the synthetic sample captures in samples/.

    python scripts/generate_samples.py

The captures are built by tests/pcap_factory.py, so they contain no real plant
traffic and are safe to share. Requires scapy (pip install -r requirements-dev.txt).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import pcap_factory  # noqa: E402

SAMPLES = {
    "benign_plant.pcap": pcap_factory.build_benign,
    "ot_protocols.pcap": pcap_factory.build_ot_protocols,
    "attack_scenarios.pcap": pcap_factory.build_attacks,
}


def main() -> None:
    out = ROOT / "samples"
    out.mkdir(exist_ok=True)
    for name, build in SAMPLES.items():
        build(out / name)
        print(f"wrote samples/{name}")


if __name__ == "__main__":
    main()
