# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
