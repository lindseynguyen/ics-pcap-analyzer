# Contributing to OT PCAP Analyzer

Thanks for your interest in improving the project! Every kind of contribution
helps: bug reports, false-positive reports, new protocol decoders, detection
rules, tests, documentation and GUI improvements.

## Ways to contribute

- **Report a bug or a false positive / missed detection** – open an issue using
  the templates. Include the command you ran, the version (`python -m
  ot_pcap_analyzer --version`) and, if possible, a *small, sanitised* capture
  that reproduces the problem.
- **Share test captures** – real OT traffic is the most valuable input for
  improving detection. Only share captures you are allowed to share, and remove
  or anonymise anything sensitive (public IPs, hostnames, credentials, process
  values). Public ICS datasets are also great references.
- **Add or improve a protocol decoder** – see "Adding a protocol" below.
- **Tune detection rules** – thresholds and patterns live in
  `ot_pcap_analyzer/constants.py`; detector logic in `detectors.py`.

## Development setup

```bash
git clone https://github.com/<you>/ics-pcap-analyzer.git
cd ics-pcap-analyzer
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen python -m pytest
```

## Pull request checklist

1. Create a branch from `main`; keep each PR focused on one change.
2. Add or update tests. Build synthetic traffic with the helpers in
   `tests/pcap_factory.py` (they use scapy) instead of committing captures.
   - New detection → a test that fires on the attack **and** a test that a
     benign variant stays quiet.
   - Bug fix → a regression test that fails without the fix.
3. Run the full suite and pyflakes:
   ```bash
   QT_QPA_PLATFORM=offscreen python -m pytest
   python -m pyflakes ot_pcap_analyzer tests
   ```
4. Keep the benign capture test green: a realistic benign capture must produce
   **zero** alerts (`tests/test_detection.py::test_benign_capture_has_no_alerts`).
5. Update `README.md` / `CHANGELOG.md` when behaviour or usage changes.
6. Do not commit captures, reports, databases or credentials (see `.gitignore`).

## Coding guidelines

- Python 3.10+, PEP 8 style, type hints where practical, English everywhere
  (code, comments, UI strings).
- Parsers must never raise on malformed input: return `None` and let the
  pipeline continue.
- Never mutate the shared tables in `constants.py` at runtime (copy lists first).
- Keep per-packet work O(1): use deques / running totals for sliding windows,
  `utils.cached_regex` for dynamic patterns. `tests/test_performance.py` guards
  against quadratic regressions.
- No outbound network calls except the opt-in threat-intelligence lookups, and
  never send private/internal addresses to third-party services.

## Adding a protocol

1. Write `ProtocolParser.parse_<proto>()` in `parsers.py` returning an `OTEvent`
   (function code/name, operation type, risk level, MITRE techniques).
2. If it runs over TCP, add a framer to `ot_stream.py` (`OT_TCP_FRAMERS`) so
   PDUs are reassembled, and register the parser in `OTAnalyzer._OT_TCP_PARSERS`.
3. Add the function-code table to `constants.py` and the protocol to `OTProtocol`.
4. Add payload builders to `tests/pcap_factory.py` and unit tests in
   `tests/test_parsers.py` / `tests/test_ot_stream.py`.

## Commit messages

Use short imperative subjects (e.g. "Add BACnet ReadRange decoding") and explain
the *why* in the body when it is not obvious.

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
