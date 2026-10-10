# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `samples/`: three ready-to-use synthetic captures (benign plant, every OT protocol,
  multi-stage attack) with expected results, plus `scripts/generate_samples.py`.
  `tests/test_samples.py` keeps them in sync with the generator and checks the
  documented results.
- Animated GUI demo `docs/demo.gif`, recorded by `scripts/make_demo_gif.py`.
- README quick start using the samples, extra badges and an OT/ICS audit checklist link.

### Changed
- CI: separate lint job with ruff (pyflakes rules, config in `pyproject.toml`) instead of
  grepping pyflakes output; tests now also smoke-test the CLI on the sample captures.
- Removed unused imports, duplicate imports and empty f-strings across the package.

## [1.2.0] - 2026-10-09

### Added
- Behaviour profiling (`detection/behavior.py`), on by default: learns the first
  30 % of a capture and reports `OT_NEW_MASTER`, `OT_NEW_DEVICE`, `OT_NEW_FUNCTION`,
  `OT_POLLING_DEVIATION` (polling stopped / storm) and `OT_VALUE_OUT_OF_RANGE`.
  Disable with `--no-behavior` or `AnalyzerConfig(enable_behavior_profiling=False)`.
- Custom detection rules (`detection/rules_engine.py`): YAML/JSON rules matching
  protocol, operation, IPs/CIDRs/MACs (with negation), ports, function codes,
  target regex, value limits and `details` fields, with thresholds, grouping and
  cooldown. Loaded from `--rules PATH` (repeatable) and `~/.ot_pcap_analyzer/rules`.
  Ten commented examples in `examples/rules/`.
- `OTEvent.details`: structured, protocol-independent facts (`op`, `target`,
  `value`, `is_request`…) for decoders and rules (`protocols/base.py`).

### Fixed
- The installed package now includes its sub-packages.

## [1.1.0] - 2026-10-09

### Added
- Light theme next to the dark theme, switchable from the sidebar (`Ctrl+D`);
  the choice is remembered. A central theme engine (`gui_style.py`) keeps every
  page, table, chart and graph consistent in both themes.
- Redesigned security overview: KPI tiles, alerts by severity, OT protocol and
  MITRE ATT&CK technique charts, capture facts and a high-severity alert list.
- Scan history page: search and period filter, per-scan details (severity
  breakdown, most frequent alerts, alerts and IOCs), comparison of two scans,
  "Analyze again", export / import, delete one / selected / all scans,
  automatic deletion after N days and an option to turn history off.
- `AnalysisDatabase`: `list_sessions`, `session_overview`, `compare_sessions`,
  `delete_sessions`, `delete_all_sessions`, `purge_older_than`, `storage_info`.
- README screenshots and virtual-environment install instructions.

### Changed
- Modern sidebar with SVG icons and grouped navigation; cleaner top bar.
- UI font is now a sans-serif system font (monospace only where useful).

### Fixed
- Unreadable sidebar labels and white table rows when the system palette was light.
- Translucent colours were drawn as dark blocks (Qt reads `#RRGGBBAA` as ARGB).
- Borders of cards were repeated around every label inside them.
- "Top MITRE techniques" on the dashboard was always empty.
- The history list never refreshed after an analysis, IOCs were never saved to
  history, and deleted history stayed recoverable inside the SQLite file
  (`secure_delete` + `VACUUM` now).
- The capture hash for history is no longer computed by reading the whole file into memory.

## [1.0.1] - 2026-10-09

### Security
- GUI: values taken from captures (descriptions, URLs, payload previews, IPs,
  threat-intel responses) are HTML-escaped before rich-text rendering, so a
  crafted capture cannot inject markup or spoof what the analyst sees.
- Excel report and IOC CSV export neutralise spreadsheet formulas
  (`=`, `+`, `-`, `@`... prefixes) to prevent CSV/formula injection.
- Threat intel: internal host names (`.local`, `.lan`, `.corp`, `.internal`,
  single-label names...) are never sent to VirusTotal; domains and hashes are
  validated before they are placed in an API URL. Browser lookups from the IOC
  panel URL-encode the value and skip private IP addresses.
- `api_keys.json` is written with owner-only permissions (0600); the data
  directory, threat-intel cache and history database directory are created 0700.
- Malformed `api_keys.json` files are ignored instead of crashing; local feed
  entries cannot inject extra lines.
- CI runs with read-only `GITHUB_TOKEN` permissions; Dependabot added for pip and
  GitHub Actions.

## [1.0.0] - 2026-10-09

First public release.

### Added
- Decoders for Modbus TCP/UDP, S7comm, DNP3, EtherNet/IP (CIP), IEC 60870-5-104,
  OPC UA, MQTT and BACnet/IP, with TCP stream reassembly of OT PDUs.
- PCAP / PCAPNG readers (both byte orders, ns timestamps, SPB/EPB), Ethernet,
  VLAN/QinQ, Linux cooked capture, raw IP, IPv4/IPv6 with extension headers.
- OT, IT, network and web attack detection; ICS malware behavioural signatures;
  optional Isolation-Forest outlier scoring per operation group.
- Attack-chain correlation, kill-chain threat scoring and attack storylines with
  MITRE ATT&CK for ICS / Enterprise mapping.
- IOC extraction (JSON/CSV), Excel reports, SQLite analysis history.
- Optional threat intelligence (local feeds, VirusTotal, AbuseIPDB).
- SOC-style PyQt5 GUI.
- pytest suite (480+ tests) with synthetic capture generation, CI workflow.
