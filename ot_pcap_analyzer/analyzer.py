"""
OT PCAP Analyzer - Main Analyzer Engine
=======================================
Capture processing pipeline: link/IP/transport decoding, OT protocol dispatch,
correlation, storylines and reporting. Detection logic lives in detectors.py,
the baseline engine in baseline.py.
"""

import os
import re
import struct
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Callable, Any, Set, Tuple

import pandas as pd

from .version import VERSION
from .models import (
    OTEvent, OTAsset, SecurityAnomaly, AnalyzerConfig, AttackChain,
    AttackPhase, AttackStoryline
)
from .ot_stream import OTStreamReassembler, OT_TCP_FRAMERS
from .parsers import (
    iter_capture, ProtocolParser
)
from .utils import (
    ip4_to_str,
    ip6_to_str, mac_to_str, get_vendor, sha256_file,
    format_bytes, utc_str, logger
)

# Convenience re-exports
from .utils import normalize_timestamp, MAX_VALID_TIMESTAMP  # noqa: F401
from .detectors import EnhancedThreatDetector, HAS_SKLEARN  # noqa: F401
from .baseline import BaselineEngine  # noqa: F401
from .report_export import _excel_safe


class OTAnalyzer:
    """Enhanced OT/ICS traffic analyzer with advanced threat detection"""

    def __init__(self, config: AnalyzerConfig = None):
        self.config = config or AnalyzerConfig()

        # ProtocolParser keeps per-flow timing state at class level; reset it so
        # results don't depend on captures analyzed earlier in the same process.
        ProtocolParser._last_packet_time.clear()
        ProtocolParser._last_payload_value.clear()

        # Basic stats
        self.frames_total = 0
        self.packets_parsed = 0
        self.ts_first: Optional[float] = None
        self.ts_last: Optional[float] = None

        # Asset tracking
        self.assets: Dict[str, OTAsset] = {}

        # OT events
        self.ot_events: List[OTEvent] = []
        self.ot_event_counts: Counter = Counter()
        self.protocol_counts: Counter = Counter()
        self.function_counts: Dict[str, Counter] = defaultdict(Counter)
        self.ot_conversations: Counter = Counter()

        # Anomalies and threats
        self.anomalies: List[SecurityAnomaly] = []
        self.threat_detector = EnhancedThreatDetector()
        self.risk_events: Counter = Counter()
        self.mitre_techniques: Counter = Counter()

        # Timestamp correction tracking (to reduce log noise)
        self.timestamp_corrections = {'milliseconds': 0, 'microseconds': 0, 'invalid': 0}
        self.timestamp_warning_logged = False
        self.MAX_TIMESTAMP = 253402300799  # Year 9999-12-31

        # Per-direction reassembly of OT protocol PDUs over TCP
        self._ot_stream = OTStreamReassembler()

        # HTTP sessions already checked by detect_http_attacks()
        self._http_request_checked: Set[str] = set()

        # Anomaly deduplication state: key -> (first_ts, anomaly)
        self._anomaly_dedup_cache: Dict[Tuple[str, str, str], Tuple[float, SecurityAnomaly]] = {}
        self._anomaly_limit_logged = False

        # Baseline engine (if enabled)
        self.baseline_engine: Optional[BaselineEngine] = None
        if self.config.enable_baseline:
            self.baseline_engine = BaselineEngine(
                max_baselines=self.config.max_baselines,
                learning_period=self.config.baseline_learning_period
            )
            logger.info(f"Baseline learning enabled (period: {self.config.baseline_learning_period}s)")

        # Network stats
        self.ip_pair_bytes: Counter = Counter()
        self.endpoint_packets: Counter = Counter()
        self.port_counts: Counter = Counter()

        # TCP stats
        self.syn_count = 0
        self.rst_count = 0
        self.synack_ports: Dict[str, Set[int]] = defaultdict(set)

        # Control
        self.progress_callback: Optional[Callable[[int, int, str], None]] = None
        self.cancel_flag = False

        # File info
        self.capture_path = ""
        self.capture_sha256 = ""
        self.capture_size = 0

        # Sequence tracking
        self.sequence_counter = 0

        # Attack Chain Correlation & Storyline
        self.attack_chains: List[AttackChain] = []
        self.storylines: List[AttackStoryline] = []
        self._storyline_generator = None
        if self.config.enable_storyline or self.config.enable_correlation:
            from .storyline import AttackStorylineGenerator
            self._storyline_generator = AttackStorylineGenerator()

        # User-defined detection rules
        self._rule_engine = None
        if self.config.detect_anomalies:
            self._rule_engine = self._load_rule_engine()

        # OT Malware Detection & Advanced Threat Scoring
        self._malware_detector = None
        self._advanced_threat_detector = None
        try:
            from .ot_malware_signatures import OTMalwareDetector
            from .advanced_threat_detector import AdvancedThreatDetector
            self._malware_detector = OTMalwareDetector(enable_behavioral=True)
            self._advanced_threat_detector = AdvancedThreatDetector(enable_malware=True)
            logger.info("OT Malware Detection & Advanced Threat Scoring enabled")
        except ImportError as e:
            logger.warning(f"Advanced threat detection modules not available: {e}")

    def _load_rule_engine(self):
        """Custom rules from config.rule_paths and ~/.ot_pcap_analyzer/rules (None if no rules)."""
        from pathlib import Path
        from .detection.rules_engine import RuleEngine
        paths = []
        default_dir = Path.home() / ".ot_pcap_analyzer" / "rules"
        if self.config.load_default_rules and default_dir.is_dir():
            paths.append(default_dir)
        paths.extend(self.config.rule_paths or [])
        if not paths:
            return None
        try:
            engine = RuleEngine.from_paths(paths)
        except Exception as e:  # never let a rules problem stop the analysis
            logger.warning(f"Custom rules not loaded: {e}")
            return None
        if len(engine):
            logger.info(f"Loaded {len(engine)} custom detection rule(s)")
            return engine
        return None

    def _normalize_timestamp(self, ts: float) -> Optional[float]:
        """
        Normalize timestamp to valid Unix seconds format.
        Auto-corrects millisecond/microsecond timestamps with statistics tracking.

        Args:
            ts: Raw timestamp value

        Returns:
            Normalized timestamp in seconds, or None if invalid
        """
        if ts is None or ts < 0:
            return None

        original_ts = ts

        # Use standalone normalize_timestamp function
        normalized = normalize_timestamp(ts)

        # Track statistics if correction happened
        if normalized is None:
            self.timestamp_corrections['invalid'] += 1
        elif normalized != original_ts:
            # Determine correction type
            if original_ts > 1e15:
                self.timestamp_corrections['microseconds'] += 1
            elif original_ts > 1e12:
                self.timestamp_corrections['milliseconds'] += 1

                # Log only once
                if not self.timestamp_warning_logged:
                    logger.info(f"Auto-correcting millisecond timestamps (e.g., {original_ts:.2f} → {normalized:.2f})")
                    self.timestamp_warning_logged = True

        return normalized

    def analyze_capture(self, capture_file: str, max_packets: Optional[int] = None) -> None:
        """Main analysis entry point"""
        self.capture_path = capture_file
        self.capture_size = os.path.getsize(capture_file)
        self.capture_sha256 = sha256_file(capture_file)

        logger.info(f"Starting analysis: {capture_file}")
        logger.info(f"File size: {format_bytes(self.capture_size)}, SHA256: {self.capture_sha256[:16]}...")

        # Estimate total packets from file size (avoid reading entire file twice)
        # Average packet ~200-400 bytes including headers; use 300 as estimate
        estimated_total = max(self.capture_size // 300, 100)
        if max_packets:
            estimated_total = min(estimated_total, max_packets)

        if self.progress_callback:
            self.progress_callback(0, estimated_total, "Starting analysis...")

        logger.info(f"Estimated packets: ~{estimated_total:,} (file size based)")

        # Process packets - single pass (no pre-counting)
        processed = 0
        for rec in iter_capture(capture_file):
            if self.cancel_flag:
                logger.warning("Analysis cancelled by user")
                break

            self.frames_total += 1
            if max_packets and self.packets_parsed >= max_packets:
                break

            self.packets_parsed += 1
            ts = self._normalize_timestamp(float(rec.ts))
            if ts is None:
                continue

            if ts > 0:
                if self.ts_first is None:
                    self.ts_first = ts
                self.ts_last = ts

            self._process_frame(ts, rec.data, rec.linktype)

            processed += 1
            if self.progress_callback and processed % 200 == 0:
                # Use actual count as progress, cap estimate upward if needed
                display_total = max(estimated_total, processed + 100)
                self.progress_callback(processed, display_total, f"Analyzing packets... {processed:,}")

        # Parse incomplete PDUs still buffered at the end of the capture
        for (f_src, f_dst, f_sport, f_dport), tail in self._ot_stream.flush():
            port = self._ot_server_port(f_sport, f_dport)
            if port is not None:
                self.sequence_counter += 1
                event = self._OT_TCP_PARSERS[port](tail, self.ts_last or 0.0, f_src, f_dst,
                                                   f_sport, f_dport, self.sequence_counter)
                if event:
                    self._record_ot_event(event)

        # Post-processing
        logger.info("Running post-analysis tasks...")
        if self.progress_callback:
            self.progress_callback(processed, processed + 1, "Post-analysis: correlation & ML...")
        self._post_analysis()

        if self.progress_callback:
            self.progress_callback(processed, processed, "Analysis complete!")

        logger.info(f"Analysis complete: {self.packets_parsed:,} packets, "
                   f"{len(self.ot_events):,} OT events, {len(self.anomalies):,} anomalies")

        # Log timestamp correction summary if any were corrected
        if sum(self.timestamp_corrections.values()) > 0:
            ms_count = self.timestamp_corrections['milliseconds']
            us_count = self.timestamp_corrections['microseconds']
            invalid_count = self.timestamp_corrections['invalid']
            logger.info(f"Timestamp corrections: {ms_count:,} millisecond, {us_count:,} microsecond, "
                       f"{invalid_count:,} invalid (skipped)")

    def _process_frame(self, ts: float, frame: bytes, linktype: int) -> None:
        """Process single frame"""
        if linktype == 1:  # Ethernet
            self._process_ethernet(ts, frame)
        elif linktype == 113:  # Linux cooked capture v1 (SLL), e.g. tcpdump -i any
            if len(frame) >= 16:
                self._process_l3(ts, struct.unpack(">H", frame[14:16])[0], frame[16:], "", frame)
        elif linktype == 276:  # Linux cooked capture v2 (SLL2)
            if len(frame) >= 20:
                self._process_l3(ts, struct.unpack(">H", frame[0:2])[0], frame[20:], "", frame)
        elif linktype == 0:  # BSD loopback / NULL (4-byte host-order family)
            if len(frame) >= 5:
                self._process_ip(ts, frame[4:])
        elif linktype in (12, 14, 101, 228):  # Raw IP (DLT_RAW Linux=12, BSD=14, LINKTYPE_RAW=101, IPv4=228)
            self._process_ip(ts, frame)
        elif linktype == 229:  # Raw IPv6 only
            self._process_ipv6(ts, frame, "")

    def _process_ethernet(self, ts: float, frame: bytes) -> None:
        """Process Ethernet frame"""
        if len(frame) < 14:
            return

        src_mac = mac_to_str(frame[6:12])
        eth_type = struct.unpack(">H", frame[12:14])[0]
        offset = 14

        # Handle VLAN tags (802.1Q, 802.1ad QinQ, legacy 0x9100), possibly stacked
        while eth_type in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return
            eth_type = struct.unpack(">H", frame[offset + 2:offset + 4])[0]
            offset += 4

        self._process_l3(ts, eth_type, frame[offset:], src_mac, frame[:12] + frame[offset - 2:])

    def _process_l3(self, ts: float, eth_type: int, payload: bytes, src_mac: str,
                    untagged_frame: bytes) -> None:
        """Dispatch a layer-3 payload by EtherType.

        untagged_frame is an Ethernet-style frame (dst/src MAC + EtherType + payload)
        without VLAN tags, used by the ARP parser.
        """
        if eth_type == 0x0800:  # IPv4
            self._process_ipv4(ts, payload, src_mac)
        elif eth_type == 0x86DD:  # IPv6
            self._process_ipv6(ts, payload, src_mac)
        elif eth_type == 0x0806:  # ARP
            if len(untagged_frame) < 14:
                return
            if untagged_frame[12:14] != b"\x08\x06":
                # Cooked captures carry no Ethernet header: synthesize one
                untagged_frame = b"\x00" * 12 + b"\x08\x06" + payload
            self._process_arp(ts, untagged_frame)

    def _process_ip(self, ts: float, data: bytes) -> None:
        """Process raw IP packet"""
        if len(data) < 1:
            return
        version = (data[0] >> 4) & 0x0F
        if version == 4:
            self._process_ipv4(ts, data, "")
        elif version == 6:
            self._process_ipv6(ts, data, "")

    def _process_ipv4(self, ts: float, ip_data: bytes, src_mac: str) -> None:
        """Process IPv4 packet"""
        if len(ip_data) < 20:
            return

        ihl = (ip_data[0] & 0x0F) * 4
        if ihl < 20 or len(ip_data) < ihl:
            return

        total_len = struct.unpack(">H", ip_data[2:4])[0]
        # Strip Ethernet padding/trailers beyond the IP datagram (total_len == 0
        # happens with TSO offload captures: keep the captured data in that case)
        if ihl <= total_len < len(ip_data):
            ip_data = ip_data[:total_len]
        proto = ip_data[9]
        # Non-first fragments carry no transport header
        frag_offset = struct.unpack(">H", ip_data[6:8])[0] & 0x1FFF
        src_ip = ip4_to_str(ip_data[12:16])
        dst_ip = ip4_to_str(ip_data[16:20])

        # Track assets
        if self.config.track_assets:
            self._track_asset(src_ip, src_mac, ts, total_len)
            self._track_asset(dst_ip, "", ts, 0)

        # Update stats
        self.endpoint_packets[src_ip] += 1
        self.endpoint_packets[dst_ip] += 1
        self.ip_pair_bytes[(src_ip, dst_ip)] += total_len

        payload = ip_data[ihl:]
        if frag_offset:
            return

        if proto == 6:  # TCP
            self._process_tcp(ts, src_ip, dst_ip, payload)
        elif proto == 17:  # UDP
            self._process_udp(ts, src_ip, dst_ip, payload)

    def _process_ipv6(self, ts: float, ip_data: bytes, src_mac: str) -> None:
        """Process IPv6 packet"""
        if len(ip_data) < 40:
            return

        payload_len = struct.unpack(">H", ip_data[4:6])[0]
        next_header = ip_data[6]
        src_ip = ip6_to_str(ip_data[8:24])
        dst_ip = ip6_to_str(ip_data[24:40])

        payload = ip_data[40:]
        if 0 < payload_len < len(payload):
            payload = payload[:payload_len]  # strip link-layer padding

        # Walk common extension headers (hop-by-hop, routing, destination options)
        hops = 0
        while next_header in (0, 43, 60) and len(payload) >= 8 and hops < 8:
            next_header, ext_len = payload[0], (payload[1] + 1) * 8
            payload = payload[ext_len:]
            hops += 1
        if next_header == 44:  # Fragment header
            if len(payload) < 8 or (struct.unpack(">H", payload[2:4])[0] >> 3):
                return  # non-first fragment
            next_header, payload = payload[0], payload[8:]

        if self.config.track_assets:
            self._track_asset(src_ip, src_mac, ts, len(ip_data))
            self._track_asset(dst_ip, "", ts, 0)
        self.endpoint_packets[src_ip] += 1
        self.endpoint_packets[dst_ip] += 1
        self.ip_pair_bytes[(src_ip, dst_ip)] += len(ip_data)

        if next_header == 6:  # TCP
            self._process_tcp(ts, src_ip, dst_ip, payload)
        elif next_header == 17:  # UDP
            self._process_udp(ts, src_ip, dst_ip, payload)

    def _process_arp(self, ts: float, frame: bytes) -> None:
        """Process ARP packet for spoofing detection"""
        if not self.config.detect_anomalies:
            return

        arp_data = ProtocolParser.parse_arp(frame, ts)
        if arp_data:
            anomalies = self.threat_detector.detect_arp_spoofing(arp_data)
            for anomaly in anomalies:
                self._add_anomaly(anomaly, apply_baseline=False)

    def _process_tcp(self, ts: float, src_ip: str, dst_ip: str, tcp_data: bytes) -> None:
        """Process TCP segment with OT protocol detection"""
        if len(tcp_data) < 20:
            return

        src_port = struct.unpack(">H", tcp_data[0:2])[0]
        dst_port = struct.unpack(">H", tcp_data[2:4])[0]

        data_offset = ((tcp_data[12] >> 4) & 0x0F) * 4
        if data_offset < 20:
            return

        flags = tcp_data[13]
        syn = (flags & 0x02) != 0
        ack = (flags & 0x10) != 0
        rst = (flags & 0x04) != 0

        # Track TCP flags
        if syn:
            self.syn_count += 1
        if rst:
            self.rst_count += 1
        if syn and ack:
            self.synack_ports[src_ip].add(src_port)

        self.port_counts[("TCP", dst_port)] += 1

        # Track asset ports
        if src_ip in self.assets:
            self.assets[src_ip].ports_seen.add(src_port)
        if dst_ip in self.assets:
            self.assets[dst_ip].ports_seen.add(dst_port)

        # IT Layer Security Detection
        # Scan / admin-port / lateral-movement / beacon detectors count
        # CONNECTION ATTEMPTS, so they are fed only with initial SYNs. Feeding
        # every packet turned one SSH session into an "admin port attack", a
        # server's replies to client ports into a "port scan", and steady SCADA
        # polling into a "C2 beacon".
        if self.config.detect_anomalies and self.threat_detector:
            if rst:
                brute_anomaly = self.threat_detector.detect_brute_force(src_ip, dst_ip, dst_port, ts, is_failed=True)
                if brute_anomaly:
                    self._add_anomaly(brute_anomaly, apply_baseline=False)

            if syn and not ack:
                for detector in (self.threat_detector.detect_admin_port_attack,
                                 self.threat_detector.detect_lateral_movement,
                                 self.threat_detector.detect_port_scan,
                                 self.threat_detector.detect_c2_beacon):
                    anomaly = detector(src_ip, dst_ip, dst_port, ts)
                    if anomaly:
                        self._add_anomaly(anomaly, apply_baseline=False)

        # OT Protocol Detection
        tcp_payload = tcp_data[data_offset:]
        if len(tcp_payload) < 1:
            if flags & 0x07:  # SYN / FIN / RST: keep OT stream state in sync
                self._process_ot_tcp(ts, src_ip, dst_ip, src_port, dst_port, tcp_data, b"")
            return

        # Data Exfiltration Detection
        if self.config.detect_anomalies and len(tcp_payload) > 1000:
            exfil_anomaly = self.threat_detector.detect_data_exfiltration(
                src_ip, dst_ip, len(tcp_payload), ts
            )
            if exfil_anomaly:
                self._add_anomaly(exfil_anomaly, apply_baseline=False)

        # HTTP Attack Detection (cleartext HTTP ports only: 443/8443 carry TLS,
        # whose encrypted records cannot be parsed and only cost CPU)
        http_ports = {80, 8080, 8000, 8888}
        is_http_request = dst_port in http_ports
        is_http_response = src_port in http_ports and dst_port not in http_ports

        if self.config.detect_anomalies and (is_http_request or is_http_response):
            # Extract TCP sequence number for stream reassembly
            seq = struct.unpack(">I", tcp_data[4:8])[0] if len(tcp_data) >= 8 else 0

            if is_http_request:
                # ---- CLIENT -> SERVER (HTTP Request) ----
                # First add packet to session tracker and wait for complete HTTP
                stream_anomalies, decoded_payload = self.threat_detector.analyze_decoded_http_stream(
                    src_ip, dst_ip, src_port, dst_port, seq, tcp_payload, ts, flags
                )
                for anomaly in stream_anomalies:
                    self._add_anomaly(anomaly, apply_baseline=False)

                # Get session ID to check if we should do basic HTTP analysis
                session_id = self.threat_detector.http_session_tracker._make_session_id(
                    src_ip, dst_ip, src_port, dst_port
                )

                # Only run basic HTTP analysis when session is complete
                if self.threat_detector.http_session_tracker.is_http_complete(session_id):
                    # Check if already analyzed by the request-level detector.
                    # NOTE: analyze_decoded_http_stream() marks the session in the
                    # tracker's own analyzed set, so a separate set is required here;
                    # sharing it meant URI/header detections (SQLi, XSS, traversal,
                    # scanners...) never ran for complete requests.
                    if session_id not in self._http_request_checked:
                        if len(self._http_request_checked) > 200_000:
                            self._http_request_checked.clear()
                        self._http_request_checked.add(session_id)

                        # Get reassembled HTTP data for analysis
                        session_data = self.threat_detector.http_session_tracker.get_session_data(session_id)

                        if session_data and session_data.get('type') == 'request':
                            # Build http_data from reassembled session
                            http_data = {
                                'timestamp': ts,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'method': session_data.get('method', ''),
                                'uri': session_data.get('uri', ''),
                                'version': session_data.get('http_version', ''),
                                'headers': session_data.get('headers', {}),
                                'headers_raw': session_data.get('headers_raw', b'').decode('utf-8', errors='replace') if isinstance(session_data.get('headers_raw', b''), bytes) else session_data.get('headers_raw', ''),
                                'host': session_data.get('headers', {}).get('host', ''),
                                'user_agent': session_data.get('headers', {}).get('user-agent', ''),
                                'content_length': session_data.get('content_length', 0),
                                'content_type': session_data.get('headers', {}).get('content-type', ''),
                                # Use FULL reassembled body (not truncated from single packet)
                                'body': session_data.get('body_final', b'').decode('utf-8', errors='replace')[:16384] if isinstance(session_data.get('body_final', b''), bytes) else session_data.get('body_final', '')[:16384],
                                'raw_size': session_data.get('body_received_bytes', 0),
                                'operation_type': 'READ' if session_data.get('method') == 'GET' else 'WRITE',
                                'risk_level': 'LOW',
                            }

                            # Run detection with complete HTTP body
                            http_anomalies = self.threat_detector.detect_http_attacks(http_data)
                            for anomaly in http_anomalies:
                                self._add_anomaly(anomaly, apply_baseline=False)
                else:
                    # Session not complete - do quick check on current packet for obvious attacks
                    if tcp_payload[:4] in [b'GET ', b'POST', b'PUT ', b'HEAD', b'DELE', b'OPTI', b'PATC']:
                        http_data = ProtocolParser.parse_http_request(tcp_payload, ts, src_ip, dst_ip, src_port, dst_port)
                        if http_data:
                            # Only detect header-based attacks (don't rely on body for incomplete sessions)
                            http_data['body'] = ''  # Clear body to prevent false analysis
                            http_anomalies = self.threat_detector.detect_http_attacks(http_data)
                            for anomaly in http_anomalies:
                                self._add_anomaly(anomaly, apply_baseline=False)

            elif is_http_response:
                # ---- SERVER -> CLIENT (HTTP Response) ----
                # Track response status codes for behavioral analysis (e.g., directory brute-force)
                if tcp_payload[:5] in (b'HTTP/', b'http/'):
                    status_match = re.search(rb'HTTP/\d\.\d\s+(\d{3})', tcp_payload[:50])
                    if status_match:
                        status_code = int(status_match.group(1))
                        # dst_ip is the client (original attacker), src_ip is the server
                        bruteforce_anomaly = self.threat_detector.detect_directory_bruteforce(
                            client_ip=dst_ip, server_ip=src_ip, status_code=status_code,
                            server_port=src_port, ts=ts
                        )
                        if bruteforce_anomaly:
                            self._add_anomaly(bruteforce_anomaly, apply_baseline=False)

        # --- Post-Exploitation Stream Analysis (all TCP payloads) ---
        if self.config.detect_anomalies and len(tcp_payload) >= 10:
            post_exploit_anomalies = self.threat_detector.detect_post_exploitation_stream(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                tcp_payload=tcp_payload, ts=ts
            )
            for anomaly in post_exploit_anomalies:
                self._add_anomaly(anomaly, apply_baseline=False)

        self._process_ot_tcp(ts, src_ip, dst_ip, src_port, dst_port, tcp_data, tcp_payload)

    # TCP server port -> parser for OT protocols
    _OT_TCP_PARSERS = {
        502: ProtocolParser.parse_modbus_tcp,
        102: ProtocolParser.parse_s7comm,
        20000: ProtocolParser.parse_dnp3,
        44818: ProtocolParser.parse_enip,
        2404: ProtocolParser.parse_iec104,
        4840: ProtocolParser.parse_opc_ua,
        1883: ProtocolParser.parse_mqtt,
        # 8883 is MQTT over TLS: the payload is encrypted and cannot be parsed
        # (TLS records used to be decoded as bogus MQTT "CONNECT" packets).
    }

    def _ot_server_port(self, src_port: int, dst_port: int) -> Optional[int]:
        if dst_port in self._OT_TCP_PARSERS:
            return dst_port
        if src_port in self._OT_TCP_PARSERS:
            return src_port
        return None

    def _process_ot_tcp(self, ts: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                        tcp_data: bytes, tcp_payload: bytes) -> None:
        """Reassemble OT protocol PDUs from a TCP segment and record an event per PDU."""
        server_port = self._ot_server_port(src_port, dst_port)
        if server_port is None:
            return
        flags = tcp_data[13]
        seq = struct.unpack(">I", tcp_data[4:8])[0]
        pdus = self._ot_stream.feed(
            (src_ip, dst_ip, src_port, dst_port), seq, tcp_payload, OT_TCP_FRAMERS[server_port],
            syn=bool(flags & 0x02), fin_or_rst=bool(flags & 0x05))
        parser = self._OT_TCP_PARSERS[server_port]
        for pdu in pdus:
            self.sequence_counter += 1
            event = parser(pdu, ts, src_ip, dst_ip, src_port, dst_port, self.sequence_counter)
            if event:
                self._record_ot_event(event)

    def _process_udp(self, ts: float, src_ip: str, dst_ip: str, udp_data: bytes) -> None:
        """Process UDP datagram"""
        if len(udp_data) < 8:
            return

        src_port = struct.unpack(">H", udp_data[0:2])[0]
        dst_port = struct.unpack(">H", udp_data[2:4])[0]

        self.port_counts[("UDP", dst_port)] += 1

        udp_payload = udp_data[8:]
        if len(udp_payload) < 1:
            return

        # DNS Detection (port 53)
        if self.config.detect_anomalies and (dst_port == 53 or src_port == 53):
            dns_data = ProtocolParser.parse_dns(udp_payload, ts, src_ip, dst_ip, src_port, dst_port)
            if dns_data:
                dns_anomalies = self.threat_detector.detect_dns_tunneling(dns_data)
                for anomaly in dns_anomalies:
                    self._add_anomaly(anomaly, apply_baseline=False)

        self.sequence_counter += 1
        event = None

        # Modbus UDP (port 502)
        if dst_port == 502 or src_port == 502:
            event = ProtocolParser.parse_modbus_tcp(
                udp_payload, ts, src_ip, dst_ip, src_port, dst_port, self.sequence_counter)

        # DNP3 UDP (port 20000)
        elif dst_port == 20000 or src_port == 20000:
            event = ProtocolParser.parse_dnp3(
                udp_payload, ts, src_ip, dst_ip, src_port, dst_port, self.sequence_counter)

        # BACnet/IP (port 47808)
        elif dst_port == 47808 or src_port == 47808:
            event = ProtocolParser.parse_bacnet(
                udp_payload, ts, src_ip, dst_ip, src_port, dst_port, self.sequence_counter)

        if event:
            self._record_ot_event(event)

    def _track_asset(self, ip: str, mac: str, ts: float, byte_count: int) -> None:
        """Track network asset"""
        if ip not in self.assets:
            self.assets[ip] = OTAsset(
                ip=ip, mac=mac, vendor=get_vendor(mac) if mac else "",
                first_seen=ts, last_seen=ts, packet_count=1, byte_count=byte_count
            )
        else:
            asset = self.assets[ip]
            asset.last_seen = ts
            asset.packet_count += 1
            asset.byte_count += byte_count
            if mac and not asset.mac:
                asset.mac = mac
                asset.vendor = get_vendor(mac)

    def _record_ot_event(self, event: OTEvent) -> None:
        """Record OT event and update stats"""
        if len(self.ot_events) < self.config.max_ot_events:
            self.ot_events.append(event)

        proto_name = event.protocol.name
        self.protocol_counts[proto_name] += 1
        self.function_counts[proto_name][event.function_code] += 1
        self.risk_events[event.risk_level] += 1
        self.ot_conversations[(event.src_ip, event.dst_ip, proto_name)] += 1

        # Track MITRE techniques
        for tech in event.mitre_techniques:
            self.mitre_techniques[tech] += 1

        # Learn from event (if baseline enabled)
        if self.baseline_engine:
            self.baseline_engine.learn_from_event(event, current_time=event.timestamp)

        # Mark assets as OT devices
        for ip in [event.src_ip, event.dst_ip]:
            if ip in self.assets:
                self.assets[ip].is_ot_device = True
                self.assets[ip].protocols_seen.add(proto_name)

        # Anomaly detection
        if self.config.detect_anomalies:
            anomalies = [
                # Existing detections
                self.threat_detector.analyze_command_sequence(event),
                self.threat_detector.analyze_write_rate(event),
                self.threat_detector.analyze_payload_anomaly(event),
                # OT-specific advanced detections
                self.threat_detector.analyze_ot_replay_attack(event),
                self.threat_detector.analyze_firmware_manipulation(event),
                self.threat_detector.analyze_setpoint_manipulation(event),
                self.threat_detector.analyze_protocol_state_violation(event),
            ]
            for anomaly in anomalies:
                if anomaly:
                    self._add_anomaly(anomaly, related_event=event)

            # User-defined rules see every event (including ones not stored)
            if self._rule_engine is not None:
                for anomaly in self._rule_engine.evaluate(event):
                    self._add_anomaly(anomaly, related_event=event, apply_baseline=False)

    MAX_ANOMALIES = 100_000
    DEDUP_WINDOW = 60.0  # seconds within which identical alerts are merged

    def _add_anomaly(self, anomaly: Optional[SecurityAnomaly], related_event: Optional[OTEvent] = None,
                     apply_baseline: bool = True) -> bool:
        """
        Record an anomaly with deduplication.

        Identical alerts (same type, source and destination) within DEDUP_WINDOW
        seconds are merged into the first record: its ``evidence['occurrences']``
        and ``evidence['last_seen']`` are updated and its confidence grows
        slightly, instead of flooding the report with duplicates.

        Returns True if a new anomaly record was added.
        """
        if anomaly is None:
            return False

        if len(self.anomalies) >= self.MAX_ANOMALIES:
            if not self._anomaly_limit_logged:
                logger.warning(f"Anomaly limit ({self.MAX_ANOMALIES:,}) reached; further anomalies are dropped")
                self._anomaly_limit_logged = True
            return False

        # Baseline filtering (only meaningful for OT-event based anomalies)
        if apply_baseline and self.baseline_engine:
            should_report, adjusted_confidence = self.baseline_engine.is_anomalous(anomaly, related_event)
            if not should_report:
                return False
            anomaly.confidence = adjusted_confidence

        dedup_key = (anomaly.anomaly_type, anomaly.src_ip, anomaly.dst_ip)
        current_ts = anomaly.timestamp or 0.0
        cached = self._anomaly_dedup_cache.get(dedup_key)
        if cached is not None:
            first_ts, existing = cached
            if 0 <= current_ts - first_ts < self.DEDUP_WINDOW:
                if not isinstance(existing.evidence, dict):
                    existing.evidence = {"original_evidence": existing.evidence}
                existing.evidence["occurrences"] = existing.evidence.get("occurrences", 1) + 1
                existing.evidence["last_seen"] = current_ts
                existing.confidence = min(1.0, (existing.confidence or 0.0) + 0.02)
                if existing.evidence["occurrences"] > 10 and existing.severity == "MEDIUM":
                    existing.severity = "HIGH"
                return False

        self._anomaly_dedup_cache[dedup_key] = (current_ts, anomaly)
        if len(self._anomaly_dedup_cache) > 5000:
            threshold = current_ts - 600
            self._anomaly_dedup_cache = {k: v for k, v in self._anomaly_dedup_cache.items()
                                         if v[0] > threshold}

        self.anomalies.append(anomaly)

        # Track MITRE techniques from anomalies (not just OT events)
        for tech in getattr(anomaly, 'mitre_techniques', None) or []:
            if tech:
                self.mitre_techniques[tech] += 1

        return True

    def _post_analysis(self) -> None:
        """Post-processing after main analysis"""
        if self.config.use_ml and self.ot_events:
            self.threat_detector.train_ml_model(self.ot_events)
            for event, ml_anomaly in self.threat_detector.detect_ml_anomalies(self.ot_events):
                self._add_anomaly(ml_anomaly, related_event=event)

        # Behaviour profiling: compare the rest of the capture with its first part
        if self.config.detect_anomalies and self.config.enable_behavior_profiling and self.ot_events:
            try:
                from .detection.behavior import BehaviorProfiler
                profiler = BehaviorProfiler(learning_fraction=self.config.behavior_learning_fraction)
                for anomaly in profiler.analyze(self.ot_events):
                    self._add_anomaly(anomaly, apply_baseline=False)
            except Exception as e:
                logger.warning(f"Behaviour profiling failed: {e}")

        # OT Malware Detection
        if self._malware_detector and self.ot_events:
            logger.info("Running OT malware signature detection...")
            malware_count = 0
            for event in self.ot_events:
                result = self._malware_detector.analyze_event(event)
                if result and result.detected:
                    malware_count += 1
                    # Create anomaly from malware detection
                    anomaly = SecurityAnomaly(
                        timestamp=event.timestamp,
                        anomaly_type=f"OT_MALWARE_{result.malware_type.value if result.malware_type else 'UNKNOWN'}",
                        severity=result.severity,
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        protocol=event.protocol.name if hasattr(event.protocol, 'name') else str(event.protocol),
                        description=result.description,
                        evidence=result.evidence,
                        mitre_techniques=result.mitre_techniques,
                        confidence=result.confidence,
                        recommendation="; ".join(result.immediate_actions) if result.immediate_actions else "",
                    )
                    self._add_anomaly(anomaly, related_event=event)
            if malware_count > 0:
                logger.warning(f"OT malware detection: {malware_count} potential malware signatures detected!")

        # Advanced Threat Scoring
        if self._advanced_threat_detector and self.anomalies:
            logger.info("Running advanced threat scoring...")
            for anomaly in self.anomalies:
                self._advanced_threat_detector.add_anomaly(anomaly)
            # Also process OT events for behavioral analysis
            if self.ot_events:
                for event in self.ot_events:
                    self._advanced_threat_detector.process_ot_event(event)
            summary = self._advanced_threat_detector.get_summary()
            logger.info(f"Advanced threat scoring: {summary['total_ips_tracked']} IPs tracked, "
                       f"CRITICAL={summary['threat_level_distribution'].get('CRITICAL', 0)}, "
                       f"HIGH={summary['threat_level_distribution'].get('HIGH', 0)}")

        # Attack Chain Correlation & Storyline Generation
        if (self.config.enable_correlation or self.config.enable_storyline) and self.anomalies:
            logger.info(f"Starting attack chain correlation with {len(self.anomalies)} anomalies")
            self._correlate_attack_chains()
            logger.info(f"Attack chain correlation complete: {len(self.attack_chains)} chains created")

            if self.config.enable_storyline and self._storyline_generator:
                logger.info("Starting storyline generation")
                self._generate_storylines()
                logger.info(f"Storyline generation complete: {len(self.storylines)} storylines")
        else:
            if not self.anomalies:
                logger.warning("No anomalies detected - skipping attack chain correlation")
            elif not (self.config.enable_correlation or self.config.enable_storyline):
                logger.info("Attack chain correlation and storyline generation are disabled in config")

    def _correlate_attack_chains(self) -> None:
        """
        Correlate anomalies into attack chains.

        Optimized logic:
        1. Group anomalies by source IP (O(n) with dict)
        2. Pre-filter IPs with < 2 anomalies (early termination)
        3. Sort by timestamp (O(n log n) per IP)
        4. Detect attack phase progression with cached phase detection
        5. Create attack chains when multiple phases detected within time window
        """
        from .storyline import detect_attack_phase

        time_window = self.config.correlation_time_window
        max_chains = self.config.max_active_chains

        logger.debug(f"Correlation config: time_window={time_window}s, max_chains={max_chains}")

        # Group anomalies by source IP (Optimized with dict)
        ip_anomalies: Dict[str, List[SecurityAnomaly]] = defaultdict(list)
        for anomaly in self.anomalies:
            if anomaly.src_ip:
                ip_anomalies[anomaly.src_ip].append(anomaly)

        logger.debug(f"Initial grouping: {len(ip_anomalies)} unique source IPs")

        # Pre-filter: Remove IPs with < 2 anomalies (early termination)
        ip_anomalies = {ip: anomalies for ip, anomalies in ip_anomalies.items() if len(anomalies) >= 2}

        logger.info(f"Correlation: {len(ip_anomalies)} IPs with >= 2 anomalies (after filtering)")

        if len(ip_anomalies) == 0:
            logger.warning("No IPs with multiple anomalies - cannot build attack chains")
            return

        chain_counter = 0

        # Phase detection cache (avoid re-detecting same anomaly types)
        phase_cache: Dict[str, str] = {}

        for src_ip, anomalies_for_ip in ip_anomalies.items():
            if chain_counter >= max_chains:
                break

            # Sort by timestamp
            sorted_anomalies = sorted(anomalies_for_ip, key=lambda a: a.timestamp)

            # Detect phases (with caching to avoid redundant calls)
            phases_detected: List[Tuple[str, SecurityAnomaly]] = []
            for anomaly in sorted_anomalies:
                # Use cache for phase detection
                cache_key = anomaly.anomaly_type
                if cache_key not in phase_cache:
                    phase_cache[cache_key] = detect_attack_phase(anomaly) or ""

                phase_name = phase_cache[cache_key]
                if phase_name:
                    phases_detected.append((phase_name, anomaly))

            if len(phases_detected) < 2:
                continue

            # Group into chains based on time window
            current_chain_phases: List[Tuple[str, SecurityAnomaly]] = [phases_detected[0]]

            for i in range(1, len(phases_detected)):
                phase_name, anomaly = phases_detected[i]
                prev_phase_name, prev_anomaly = current_chain_phases[-1]

                time_diff = anomaly.timestamp - prev_anomaly.timestamp

                if time_diff <= time_window:
                    current_chain_phases.append((phase_name, anomaly))
                else:
                    # Finalize current chain if has >= 2 phases
                    if len(current_chain_phases) >= 2:
                        chain = self._build_attack_chain(
                            current_chain_phases, chain_counter, src_ip
                        )
                        if chain:
                            self.attack_chains.append(chain)
                            chain_counter += 1

                            # Early termination if max chains reached
                            if chain_counter >= max_chains:
                                logger.warning(f"Max attack chains ({max_chains}) reached, stopping correlation")
                                break

                    # Start new chain
                    current_chain_phases = [(phase_name, anomaly)]

            # Finalize last chain (if not already at limit)
            if len(current_chain_phases) >= 2 and chain_counter < max_chains:
                chain = self._build_attack_chain(
                    current_chain_phases, chain_counter, src_ip
                )
                if chain:
                    self.attack_chains.append(chain)
                    chain_counter += 1

        logger.info(f"Attack chain correlation: {len(self.attack_chains)} chains detected")

    def _build_attack_chain(
        self,
        phase_data: List[Tuple[str, SecurityAnomaly]],
        chain_index: int,
        primary_src_ip: str
    ) -> Optional[AttackChain]:
        """Build an AttackChain from correlated phase data."""
        from .storyline import create_attack_phase, get_phase_index
        from datetime import datetime

        if not phase_data:
            return None

        # Deduplicate phases (keep first occurrence of each phase type)
        seen_phases = {}
        for phase_name, anomaly in phase_data:
            if phase_name not in seen_phases:
                seen_phases[phase_name] = anomaly

        if len(seen_phases) < 2:
            return None

        # Sort phases by their MITRE index
        sorted_phases = sorted(
            seen_phases.items(),
            key=lambda x: get_phase_index(x[0])
        )

        # Build AttackPhase objects
        attack_phases = []
        for idx, (phase_name, anomaly) in enumerate(sorted_phases):
            phase = create_attack_phase(phase_name, anomaly, idx)
            attack_phases.append(phase)

        # Collect all IPs
        source_ips = set()
        target_ips = set()
        all_tactics = set()
        all_techniques = set()
        max_severity = "LOW"
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

        for phase_name, anomaly in phase_data:
            # Only add valid IPs (filter out None and empty strings)
            if anomaly.src_ip and anomaly.src_ip.strip():
                source_ips.add(anomaly.src_ip)
            if anomaly.dst_ip and anomaly.dst_ip.strip():
                target_ips.add(anomaly.dst_ip)

            all_techniques.update(anomaly.mitre_techniques)
            if severity_order.get(anomaly.severity, 0) > severity_order.get(max_severity, 0):
                max_severity = anomaly.severity

        # Debug: Log anomaly IPs before filtering
        logger.debug(f"[CHAIN BUILD] Phase data anomalies: {len(phase_data)}")
        for idx, (phase_name, anomaly) in enumerate(phase_data[:5]):  # First 5 for debugging
            logger.debug(f"  Anomaly {idx}: type={anomaly.anomaly_type}, src={anomaly.src_ip}, dst={anomaly.dst_ip}")

        # Safety check: If no target IPs found, infer from available data
        if not target_ips and source_ips:
            logger.warning(f"[CHAIN BUILD] No target_ips found, inferring from context")
            # Fallback 1: Use any IPs from assets that communicated with source_ips
            for src in source_ips:
                # Check conversation pairs
                for (s, d) in self.ot_conversations.keys():
                    if s == src and d and d.strip():
                        target_ips.add(d)
                    elif d == src and s and s.strip():
                        # Reverse direction also possible
                        target_ips.add(s)

            # Fallback 2: If still empty, use source_ips as targets (internal lateral movement)
            if not target_ips:
                logger.warning(f"[CHAIN BUILD] Using source_ips as target_ips (lateral movement scenario)")
                target_ips = source_ips.copy()

        # OT impact assessment
        ot_assets_at_risk = []
        has_ot_impact = False
        for ip in target_ips:
            asset = self.assets.get(ip)
            if asset and asset.is_ot_device:
                ot_assets_at_risk.append(ip)
                has_ot_impact = True

        # Calculate OT escalation score
        ot_escalation_score = self._calculate_ot_escalation(
            attack_phases, max_severity, ot_assets_at_risk
        )

        # Timestamps
        timestamps = [a.timestamp for _, a in phase_data]
        start_time = min(timestamps)
        end_time = max(timestamps)

        # Normalize timestamps before datetime conversion
        normalized_start = normalize_timestamp(start_time)
        if not normalized_start:
            # Fallback to using raw timestamp for ID if normalization fails
            logger.warning(f"Failed to normalize start_time {start_time}, using fallback chain ID")
            chain_id = f"CHAIN-UNKNOWN-{chain_index:03d}"
        else:
            # Chain ID with normalized timestamp
            ts_str = datetime.fromtimestamp(normalized_start).strftime("%Y%m%d%H%M%S")
            chain_id = f"CHAIN-{ts_str}-{chain_index:03d}"

        # Confidence based on phase count and progression
        confidence = min(1.0, 0.3 + len(attack_phases) * 0.15)

        chain = AttackChain(
            chain_id=chain_id,
            start_time=start_time,
            end_time=end_time,
            duration=end_time - start_time,
            source_ips=source_ips,
            target_ips=target_ips,
            phases=attack_phases,
            current_phase=attack_phases[-1].phase_name if attack_phases else "",
            phase_count=len(attack_phases),
            overall_severity=max_severity,
            confidence=confidence,
            total_events=len(phase_data),
            ot_assets_at_risk=ot_assets_at_risk,
            ot_escalation_score=ot_escalation_score,
            has_ot_impact=has_ot_impact,
            all_tactics=all_tactics,
            all_techniques=all_techniques,
            is_active=False,
            is_complete=True,
        )

        # Debug logging for attack chain creation
        logger.info(f"[ATTACK CHAIN] Created {chain_id}:")
        logger.info(f"  - Source IPs: {source_ips} (count: {len(source_ips)})")
        logger.info(f"  - Target IPs: {target_ips} (count: {len(target_ips)})")
        logger.info(f"  - Phases: {len(attack_phases)}, OT Impact: {has_ot_impact}")
        logger.info(f"  - OT Assets at Risk: {ot_assets_at_risk}")

        return chain

    def _calculate_ot_escalation(
        self,
        phases: List[AttackPhase],
        max_severity: str,
        ot_assets_at_risk: List[str]
    ) -> float:
        """
        Calculate OT escalation score (0.0 - 1.0).

        Factors:
        1. Network proximity (0.0 - 0.3): OT assets targeted
        2. Attack severity (0.0 - 0.3): Max severity level
        3. Attack progression (0.0 - 0.2): How far the attack advanced
        4. OT asset type (0.0 - 0.2): Type of OT device at risk
        """
        score = 0.0

        # Factor 1: Network proximity
        if ot_assets_at_risk:
            score += 0.3
        elif any(p.phase_name == "LATERAL_MOVEMENT" for p in phases):
            score += 0.2
        else:
            score += 0.1

        # Factor 2: Attack severity
        severity_scores = {"CRITICAL": 0.3, "HIGH": 0.2, "MEDIUM": 0.1, "LOW": 0.05}
        score += severity_scores.get(max_severity, 0.0)

        # Factor 3: Attack progression
        phase_names = [p.phase_name for p in phases]
        if "IMPACT" in phase_names:
            score += 0.2
        elif "LATERAL_MOVEMENT" in phase_names or "EXFILTRATION" in phase_names:
            score += 0.15
        elif "EXECUTION" in phase_names:
            score += 0.1
        elif "INITIAL_ACCESS" in phase_names:
            score += 0.05

        # Factor 4: OT asset type
        for ip in ot_assets_at_risk:
            asset = self.assets.get(ip)
            if asset:
                dtype = asset.device_type.upper()
                if dtype in ("PLC", "RTU"):
                    score += 0.2
                    break
                elif dtype in ("HMI", "SCADA"):
                    score += 0.15
                    break
                elif dtype == "HISTORIAN":
                    score += 0.1
                    break

        return min(score, 1.0)

    def _generate_storylines(self) -> None:
        """Generate storylines from attack chains."""
        if not self._storyline_generator:
            return

        max_storylines = self.config.max_storylines

        for chain in self.attack_chains[:max_storylines]:
            # Collect anomalies related to this chain
            chain_anomalies = []
            chain_src_ips = chain.source_ips
            chain_target_ips = chain.target_ips

            for anomaly in self.anomalies:
                if (anomaly.src_ip in chain_src_ips or
                    anomaly.dst_ip in chain_target_ips):
                    if chain.start_time <= anomaly.timestamp <= chain.end_time + 60:
                        chain_anomalies.append(anomaly)

            # Sort by timestamp
            chain_anomalies.sort(key=lambda a: a.timestamp)

            # Generate storyline
            storyline = self._storyline_generator.generate_storyline(
                chain=chain,
                anomalies=chain_anomalies[:50],
                ot_assets=self.assets,
            )

            chain.storyline_id = storyline.storyline_id
            self.storylines.append(storyline)

        logger.info(f"Storyline generation: {len(self.storylines)} storylines created")

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary"""
        duration = (self.ts_last - self.ts_first) if self.ts_first and self.ts_last else 0
        ot_assets = sum(1 for a in self.assets.values() if a.is_ot_device)
        critical_count = sum(1 for a in self.anomalies if a.severity == "CRITICAL")
        high_risk_events = self.risk_events.get("HIGH", 0) + self.risk_events.get("CRITICAL", 0)

        return {
            "VERSION": VERSION,
            "CAPTURE_FILE": os.path.basename(self.capture_path),
            "CAPTURE_SIZE": format_bytes(self.capture_size),
            "CAPTURE_SHA256": self.capture_sha256,
            "FRAMES_TOTAL": self.frames_total,
            "PACKETS_PARSED": self.packets_parsed,
            "DURATION_SEC": duration,
            "DURATION_STR": f"{int(duration//3600)}h {int((duration%3600)//60)}m {int(duration%60)}s",
            "TIME_START": utc_str(self.ts_first) if self.ts_first else "",
            "TIME_END": utc_str(self.ts_last) if self.ts_last else "",
            "OT_EVENTS_TOTAL": len(self.ot_events),
            "OT_PROTOCOLS": dict(self.protocol_counts),
            "ASSETS_DISCOVERED": len(self.assets),
            "OT_ASSETS": ot_assets,
            "ANOMALIES_DETECTED": len(self.anomalies),
            "CRITICAL_EVENTS": critical_count,
            "HIGH_RISK_EVENTS": high_risk_events,
            "MITRE_TECHNIQUES": len(self.mitre_techniques),
            "TOP_MITRE": dict(self.mitre_techniques.most_common(10)),
            "RISK_DISTRIBUTION": dict(self.risk_events),
            # Attack Chain & Storyline
            "ATTACK_CHAINS": len(self.attack_chains),
            "STORYLINES": len(self.storylines),
            "MAX_OT_ESCALATION": max(
                (c.ot_escalation_score for c in self.attack_chains), default=0.0
            ),
            # OT Malware & Advanced Threat Detection
            "MALWARE_DETECTIONS": self._malware_detector.detection_count if self._malware_detector else {},
            "ADVANCED_THREAT_SUMMARY": self._advanced_threat_detector.get_summary() if self._advanced_threat_detector else {},
        }

    def export_excel(self, output_path: str) -> None:
        """Export analysis results to Excel"""
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Summary sheet
            summary = self.get_summary()
            summary_df = pd.DataFrame([summary]).T
            summary_df.columns = ['Value']
            _excel_safe(summary_df).to_excel(writer, sheet_name='Summary')

            # OT Events sheet
            if self.ot_events:
                events_data = []
                for evt in self.ot_events[:50000]:
                    events_data.append({
                        'Timestamp': utc_str(evt.timestamp),
                        'Source IP': evt.src_ip,
                        'Dest IP': evt.dst_ip,
                        'Protocol': evt.protocol.name,
                        'Function': evt.function_name,
                        'Operation': evt.operation_type,
                        'Risk': evt.risk_level,
                        'MITRE': ', '.join(evt.mitre_techniques),
                        'Notes': evt.notes
                    })
                events_df = pd.DataFrame(events_data)
                _excel_safe(events_df).to_excel(writer, sheet_name='OT Events', index=False)

            # Assets sheet
            if self.assets:
                assets_data = []
                for asset in self.assets.values():
                    assets_data.append({
                        'IP': asset.ip,
                        'MAC': asset.mac,
                        'Vendor': asset.vendor,
                        'OT Device': asset.is_ot_device,
                        'Protocols': ', '.join(asset.protocols_seen),
                        'Packets': asset.packet_count,
                        'Bytes': format_bytes(asset.byte_count),
                        'First Seen': utc_str(asset.first_seen),
                        'Last Seen': utc_str(asset.last_seen)
                    })
                assets_df = pd.DataFrame(assets_data)
                _excel_safe(assets_df).to_excel(writer, sheet_name='Assets', index=False)

            # Anomalies sheet
            if self.anomalies:
                anomalies_data = []
                for a in self.anomalies[:10000]:
                    anomalies_data.append({
                        'Timestamp': utc_str(a.timestamp),
                        'Type': a.anomaly_type,
                        'Severity': a.severity,
                        'Source IP': a.src_ip,
                        'Dest IP': a.dst_ip,
                        'Protocol': a.protocol,
                        'Description': a.description,
                        'MITRE': ', '.join(a.mitre_techniques),
                        'Confidence': a.confidence,
                        'Recommendation': a.recommendation
                    })
                anomalies_df = pd.DataFrame(anomalies_data)
                _excel_safe(anomalies_df).to_excel(writer, sheet_name='Anomalies', index=False)

            # Decoded Payloads sheet
            if self.threat_detector.decoded_payloads:
                payloads_data = []
                for p in self.threat_detector.decoded_payloads[:1000]:
                    decode_chain = ' -> '.join([
                        f"{s.encoding}" for s in p.decode_steps if s.success
                    ]) if p.decode_steps else 'none'

                    payloads_data.append({
                        'Timestamp': utc_str(p.timestamp),
                        'Source IP': p.src_ip,
                        'Dest IP': p.dst_ip,
                        'Method': p.http_method,
                        'URI': p.http_uri[:100] if p.http_uri else '',
                        'Host': p.http_host,
                        'Content-Type': p.content_type,
                        'Detected Type': p.detected_type,
                        'Risk Level': p.risk_level,
                        'Decode Layers': p.total_layers,
                        'Decode Chain': decode_chain,
                        'Raw Size': p.raw_size,
                        'Final Size': p.final_size,
                        'SHA256': p.sha256_hash[:32] + '...' if p.sha256_hash else '',
                        'Patterns Matched': ', '.join(p.detection_patterns) if p.detection_patterns else '',
                        'Behavior Summary': p.behavior_summary[:200] if p.behavior_summary else '',
                        'Raw Preview': p.raw_preview[:100] if p.raw_preview else '',
                        'Final Preview': p.final_preview[:100] if p.final_preview else '',
                    })
                payloads_df = pd.DataFrame(payloads_data)
                _excel_safe(payloads_df).to_excel(writer, sheet_name='Decoded Payloads', index=False)

            # Attack Chains sheet
            if self.attack_chains:
                chains_data = []
                for chain in self.attack_chains:
                    phases_str = " -> ".join(p.phase_name for p in chain.phases)
                    chains_data.append({
                        'Chain ID': chain.chain_id,
                        'Start Time': utc_str(chain.start_time),
                        'End Time': utc_str(chain.end_time),
                        'Duration (s)': f"{chain.duration:.0f}",
                        'Source IPs': ', '.join(chain.source_ips),
                        'Target IPs': ', '.join(chain.target_ips),
                        'Phases': phases_str,
                        'Phase Count': chain.phase_count,
                        'Severity': chain.overall_severity,
                        'Confidence': f"{chain.confidence:.2f}",
                        'OT Escalation': f"{chain.ot_escalation_score:.2f}",
                        'OT Assets at Risk': ', '.join(chain.ot_assets_at_risk),
                        'Has OT Impact': chain.has_ot_impact,
                        'Total Events': chain.total_events,
                        'MITRE Techniques': ', '.join(chain.all_techniques),
                        'Storyline ID': chain.storyline_id,
                    })
                chains_df = pd.DataFrame(chains_data)
                _excel_safe(chains_df).to_excel(writer, sheet_name='Attack Chains', index=False)

            # Storylines sheet
            if self.storylines:
                storylines_data = []
                for s in self.storylines:
                    immediate = "; ".join(s.immediate_actions[:3])
                    storylines_data.append({
                        'Storyline ID': s.storyline_id,
                        'Chain ID': s.chain_id,
                        'Title': s.title,
                        'Attack Type': s.attack_type,
                        'Severity': s.severity,
                        'Production Risk': s.production_risk,
                        'Affected Assets': ', '.join(s.affected_assets),
                        'Confidence': f"{s.confidence:.2f}",
                        'Immediate Actions': immediate,
                        'Narrative': s.narrative[:500] if s.narrative else '',
                        'OT Impact': s.ot_impact_summary[:300] if s.ot_impact_summary else '',
                    })
                storylines_df = pd.DataFrame(storylines_data)
                _excel_safe(storylines_df).to_excel(writer, sheet_name='Storylines', index=False)

        logger.info(f"Excel report exported: {output_path}")

    # =========================================================================
    # Helper Methods for Advanced Threat Detection
    # =========================================================================

    def get_malware_detections(self) -> List[Dict[str, Any]]:
        """
        Get all OT malware detections.

        Returns:
            List of malware detection results
        """
        if not self._malware_detector:
            return []

        return [
            {
                "malware_type": d.malware_type.value if d.malware_type else "UNKNOWN",
                "signature_id": d.signature_id,
                "name": d.name,
                "severity": d.severity,
                "confidence": d.confidence,
                "evidence": d.evidence,
                "mitre_techniques": d.mitre_techniques,
                "immediate_actions": d.immediate_actions,

            }
            for d in self._malware_detector.detections
        ]

    def get_advanced_threat_scores(self, min_level: str = None) -> List[Dict[str, Any]]:
        """
        Get advanced threat scores for all tracked IPs.

        Args:
            min_level: Minimum threat level ("LOW", "MEDIUM", "HIGH", "CRITICAL")

        Returns:
            List of threat score summaries
        """
        if not self._advanced_threat_detector:
            return []

        scores = self._advanced_threat_detector.get_all_scores(min_level)
        return [
            {
                "ip": s.ip,
                "threat_level": s.threat_level,
                "total_score": round(s.total_score, 2),
                "normalized_score": round(s.normalized_score, 3),
                "phases_detected": [p.name for p in s.phase_progression],
                "current_phase": s.current_phase.name if s.current_phase else None,
                "predicted_next_phase": s.predicted_next_phase.name if s.predicted_next_phase else None,
                "has_ot_impact": s.has_ot_impact,
                "ot_assets_targeted": list(s.ot_assets_targeted),
                "malware_detected": len(s.malware_detections) > 0,
                "risk_assessment": s.risk_assessment,

            }
            for s in scores
        ]

    def get_critical_threat_ips(self) -> List[str]:
        """
        Get list of IPs with CRITICAL threat level.

        Returns:
            List of IP addresses
        """
        if not self._advanced_threat_detector:
            return []
        return self._advanced_threat_detector.get_critical_ips()

    def get_ot_targeting_ips(self) -> List[str]:
        """
        Get list of IPs targeting OT systems.

        Returns:
            List of IP addresses
        """
        if not self._advanced_threat_detector:
            return []
        return self._advanced_threat_detector.get_ot_targeting_ips()

    def get_threat_report(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed threat report for a specific IP.

        Args:
            ip: IP address to get report for

        Returns:
            Detailed threat report or None if IP not tracked
        """
        if not self._advanced_threat_detector:
            return None

        score = self._advanced_threat_detector.get_attack_score(ip)
        if not score:
            return None

        from .advanced_threat_detector import create_threat_report
        return create_threat_report(score)
