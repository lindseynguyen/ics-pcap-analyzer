# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
