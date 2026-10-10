"""
OT PCAP Analyzer - Threat detectors
===================================
Rule-based and ML detection logic (IT, HTTP, DNS, ARP, OT protocol behaviour).
Re-exported by analyzer.py for convenience.
"""

import re
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Set, Tuple

import numpy as np

from .constants import (
    DNS_TUNNELING_INDICATORS, ARP_DETECTION_CONFIG, DATA_EXFIL_THRESHOLDS,
    C2_BEACON_INDICATORS, HTTP_SUSPICIOUS_PATTERNS, POST_EXPLOITATION_PATTERNS,
    get_attack_explanation
)
from .models import (
    OTEvent, SecurityAnomaly, SuspiciousPayload, NetworkBehavior, DecodedPayload,
    DecodeStep
)
from .parsers import (
    HTTPStreamDecoder, HTTPSessionTracker
)
from .utils import (
    cached_regex,
    format_bytes, entropy, logger
)
from .utils import normalize_timestamp

# Check for sklearn availability
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# =============================================================================


# =============================================================================
# ENHANCED THREAT DETECTOR
# =============================================================================

# Printable ASCII used to tell text payloads from binary/encrypted ones
_PRINTABLE_BYTES = bytes(range(0x20, 0x7F)) + b"\t\r\n"


class EnhancedThreatDetector:
    """
    Advanced threat detection with IT+OT layer analysis and ML.

    Design notes:
    - Enhanced confidence scoring to reduce false positives
    - Context-aware detection (time of day, frequency, baseline)
    - Whitelist support for known legitimate traffic
    - Attack-specific IOC extraction for better evaluation
    - Correlation between multiple detection signals
    """

    IT_ADMIN_PORTS = {
        22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
        5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS", 135: "RPC", 139: "NetBIOS"
    }

    # Confidence thresholds for reducing false positives
    CONFIDENCE_THRESHOLDS = {
        'CRITICAL': 0.85,  # High confidence required for critical alerts
        'HIGH': 0.75,
        'MEDIUM': 0.60,
        'LOW': 0.40,
    }

    # Minimum occurrences before alerting (reduces single-event false positives)
    MIN_OCCURRENCES = {
        'PORT_SCAN': 15,      # Increased from 10
        'BRUTE_FORCE': 5,
        'DNS_TUNNEL': 3,
        'HTTP_ATTACK': 2,
        'C2_BEACON': 5,       # Need multiple beacon intervals
    }

    def __init__(self):
        # OT-specific tracking
        self.command_sequences: Dict[Tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=100))
        self.write_rate_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.baseline_stats: Dict[str, Dict[str, float]] = {}

        # IT-specific tracking
        self.network_behaviors: Dict[str, NetworkBehavior] = {}
        self.port_scan_tracker: Dict[str, Set[Tuple[str, int, float]]] = defaultdict(set)
        self.admin_port_tracker: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
        self.brute_force_tracker: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)

        # Lateral Movement Detection
        self.smb_connection_tracker: Dict[str, Set[str]] = defaultdict(set)
        self.smb_connection_times: Dict[str, List[float]] = defaultdict(list)

        # Risk scoring
        self.ip_risk_scores: Dict[str, float] = defaultdict(float)
        self.ip_violations: Dict[str, List[Dict]] = defaultdict(list)
        self.ip_touched_ot: Dict[str, bool] = defaultdict(bool)

        # Scan trackers
        self.scan_tracker_fast = defaultdict(set)
        self.scan_tracker_slow = defaultdict(set)
        self.scan_start_time_fast = defaultdict(float)
        self.scan_start_time_slow = defaultdict(float)
        self.scan_alerted = defaultdict(bool)

        # ML model
        self.ml_model = None
        self.scaler = None
        if HAS_SKLEARN:
            self.ml_model = IsolationForest(contamination=0.01, random_state=42)
            self.scaler = StandardScaler()

        # DNS Tunneling Detection
        self.dns_query_tracker: Dict[str, List[Dict]] = defaultdict(list)
        self.dns_subdomain_tracker: Dict[str, Set[str]] = defaultdict(set)
        self.dns_txt_tracker: Dict[str, List[float]] = defaultdict(list)

        # ARP Spoofing Detection
        self.ip_mac_mapping: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        self.arp_packet_tracker: Dict[str, List[float]] = defaultdict(list)
        self.gratuitous_arp_tracker: Dict[str, List[float]] = defaultdict(list)

        # Data Exfiltration Tracking
        self.data_transfer_tracker: Dict[Tuple[str, str], deque] = defaultdict(deque)
        self._data_transfer_totals: Dict[Tuple[str, str], int] = {}
        self.hourly_data_tracker: Dict[Tuple[str, str, int], int] = defaultdict(int)

        # C2 Beacon Detection
        self.connection_intervals: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
        self.beacon_candidates: Dict[Tuple[str, str, int], Dict] = {}

        # HTTP Attack Detection
        self.http_requests_tracker: Dict[str, List[Dict]] = defaultdict(list)

        # Directory Brute-Force / Enumeration Detection
        # Tracks HTTP response status codes per client->server pair
        self._http_response_tracker: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._dir_bruteforce_alerted: Dict[str, float] = {}  # dedup: key -> last_alert_ts

        # False Positive Reduction: Whitelist and Context Tracking
        self.whitelisted_ips: Set[str] = set()  # Known legitimate IPs
        self.whitelisted_user_agents: Set[str] = set()  # Known legitimate scanners
        self.legitimate_patterns: Dict[str, int] = defaultdict(int)  # Track normal traffic patterns

        # Attack-specific IOC tracking for better extraction
        self.attack_iocs: Dict[str, List[Dict]] = defaultdict(list)  # attack_type -> [ioc_records]
        self.ioc_correlation: Dict[str, Set[str]] = defaultdict(set)  # ip -> {attack_types}

        # Duplicate detection: prevent same alert within time window
        self.recent_alerts: Dict[str, float] = {}  # alert_key -> last_timestamp
        self.alert_dedup_window = 60.0  # seconds

        # HTTP Stream Decoding (Enhanced)
        self.http_session_tracker = HTTPSessionTracker(session_timeout=300.0)
        self.http_stream_decoder = HTTPStreamDecoder()
        self.decoded_payloads: List[DecodedPayload] = []  # Store decoded payloads for forensics

        # Precompile post-exploitation regex patterns for performance
        self._post_exploit_compiled: Dict[str, List] = {}
        for category, config in POST_EXPLOITATION_PATTERNS.items():
            self._post_exploit_compiled[category] = [
                re.compile(p) for p in config.get('patterns', [])
            ]
        # One combined alternation per category: a single fast pre-check per
        # payload instead of running every pattern on every TCP segment.
        self._post_exploit_any: Dict[str, Any] = {}
        for category, config in POST_EXPLOITATION_PATTERNS.items():
            pats = config.get('patterns', [])
            if pats:
                try:
                    self._post_exploit_any[category] = re.compile(
                        b"|".join(b"(?:" + (p if isinstance(p, bytes) else p.encode()) + b")" for p in pats))
                except re.error:
                    pass
        # ... and one alternation across ALL categories, so the common case
        # (no shell activity at all) costs a single regex scan per payload.
        try:
            all_pats = [pp if isinstance(pp, bytes) else pp.encode()
                        for c in POST_EXPLOITATION_PATTERNS.values() for pp in c.get('patterns', [])]
            self._post_exploit_all = re.compile(b"|".join(b"(?:" + pp + b")" for pp in all_pats)) if all_pats else None
        except re.error:
            self._post_exploit_all = None

    def update_risk_score(self, ip: str, delta: float, reason: str, ts: float):
        """Update risk score for an IP with context-aware adjustment."""
        # Skip whitelisted IPs
        if ip in self.whitelisted_ips:
            return

        # Apply time-based decay for old violations
        self._decay_old_violations(ip, ts)

        # Context-aware adjustment: reduce delta if IP has legitimate history
        legitimate_count = self.legitimate_patterns.get(ip, 0)
        if legitimate_count > 100:  # IP has significant legitimate traffic
            delta = delta * 0.5  # Reduce impact

        self.ip_risk_scores[ip] = min(1.0, self.ip_risk_scores[ip] + delta)
        self.ip_violations[ip].append({
            "timestamp": ts,
            "reason": reason,
            "delta": delta,
            "type": reason.split('_')[0] if '_' in reason else reason
        })

        # Track IOC correlation
        self.ioc_correlation[ip].add(reason)

    def _decay_old_violations(self, ip: str, current_ts: float, decay_period: float = 3600.0):
        """Apply time-based decay to old violations (reduce score over time)."""
        if ip not in self.ip_violations:
            return

        violations = self.ip_violations[ip]
        decay_count = sum(1 for v in violations if current_ts - v.get('timestamp', 0) > decay_period)

        # Reduce risk score based on old violations
        if decay_count > 0 and self.ip_risk_scores[ip] > 0:
            decay_factor = min(decay_count * 0.01, 0.1)  # Max 10% decay
            self.ip_risk_scores[ip] = max(0, self.ip_risk_scores[ip] - decay_factor)

    def is_duplicate_alert(self, alert_key: str, ts: float) -> bool:
        """Check if this alert was recently generated (deduplication)."""
        if alert_key in self.recent_alerts:
            if ts - self.recent_alerts[alert_key] < self.alert_dedup_window:
                return True
        self.recent_alerts[alert_key] = ts
        return False

    def add_whitelist_ip(self, ip: str):
        """Add IP to whitelist (skip alerting for this IP)."""
        self.whitelisted_ips.add(ip)

    def track_legitimate_traffic(self, ip: str):
        """Track legitimate traffic pattern for false positive reduction."""
        self.legitimate_patterns[ip] += 1

    def extract_ioc_for_attack(self, attack_type: str, ioc_data: Dict) -> None:
        """Extract IOC for specific attack type for better evaluation."""
        self.attack_iocs[attack_type].append({
            **ioc_data,
            'extracted_at': ioc_data.get('timestamp', 0),
            'attack_type': attack_type,
        })

    def get_iocs_by_attack_type(self) -> Dict[str, List[Dict]]:
        """Get all IOCs grouped by attack type for evaluation."""
        return dict(self.attack_iocs)

    def analyze_command_sequence(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """Analyze command sequence for suspicious patterns"""
        key = (event.src_ip, event.dst_ip)
        seq = self.command_sequences[key]
        seq.append((event.timestamp, event.function_code, event.operation_type))

        if len(seq) < 3:
            return None

        recent = list(seq)[-10:]
        write_count = sum(1 for _, _, op in recent if op in ["WRITE", "CONTROL"])

        if write_count >= 7:
            time_span = recent[-1][0] - recent[0][0]
            if time_span < 5.0:
                return SecurityAnomaly(
                    timestamp=event.timestamp, anomaly_type="RAPID_WRITE_SEQUENCE",
                    severity="HIGH", src_ip=event.src_ip, dst_ip=event.dst_ip,
                    protocol=event.protocol.name,
                    description=f"Rapid write sequence: {write_count} writes in {time_span:.1f}s",
                    evidence={"write_count": write_count, "time_span": time_span},
                    mitre_techniques=["T0831", "T0833"], confidence=0.85,
                    recommendation="Verify whether this is normal operational behavior."
                )
        return None

    def analyze_write_rate(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """Analyze write rate for anomalies"""
        if event.operation_type not in ["WRITE", "CONTROL"]:
            return None

        key = f"{event.src_ip}:{event.dst_ip}:{event.protocol.name}"
        tracker = self.write_rate_tracker[key]
        tracker.append(event.timestamp)

        if len(tracker) < 20:
            return None

        one_min_ago = event.timestamp - 60
        recent_writes = sum(1 for ts in tracker if ts > one_min_ago)

        if key not in self.baseline_stats:
            if len(tracker) >= 100:
                all_rates = []
                for i in range(len(tracker) - 60):
                    window_end = tracker[i] + 60
                    count = sum(1 for ts in list(tracker)[i:] if ts <= window_end)
                    all_rates.append(count)
                if all_rates:
                    self.baseline_stats[key] = {
                        "mean": np.mean(all_rates),
                        "std": np.std(all_rates),
                        "max": np.max(all_rates)
                    }

        if key in self.baseline_stats:
            baseline = self.baseline_stats[key]
            threshold = baseline["mean"] + 3 * baseline["std"]
            if recent_writes > threshold and recent_writes > 30:
                return SecurityAnomaly(
                    timestamp=event.timestamp, anomaly_type="ABNORMAL_WRITE_RATE",
                    severity="HIGH", src_ip=event.src_ip, dst_ip=event.dst_ip,
                    protocol=event.protocol.name,
                    description=f"Write rate anomaly: {recent_writes} writes/min",
                    evidence={"current_rate": recent_writes, "baseline_mean": baseline["mean"]},
                    mitre_techniques=["T0831", "T0806"], confidence=0.80,
                    recommendation="Check automation scripts or other abnormal activity."
                )
        return None

    def analyze_payload_anomaly(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """Analyze payload for anomalies"""
        if event.payload_entropy > 7.5 and len(event.raw_data) > 20:
            return SecurityAnomaly(
                timestamp=event.timestamp, anomaly_type="HIGH_ENTROPY_PAYLOAD",
                severity="MEDIUM", src_ip=event.src_ip, dst_ip=event.dst_ip,
                protocol=event.protocol.name,
                description=f"High entropy payload: {event.payload_entropy:.2f}",
                evidence={"entropy": event.payload_entropy, "payload_size": len(event.raw_data)},
                mitre_techniques=["T0820", "T0851"], confidence=0.60,
                recommendation="Inspect the payload; it may be encrypted or obfuscated."
            )
        return None

    def analyze_ot_replay_attack(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """
        Detect OT protocol replay attacks.

        Indicators:
        - Identical transaction IDs in short time window
        - Repeated exact payloads from different sources
        - Timing patterns inconsistent with normal polling
        """
        # Only state-changing operations are interesting: identical read requests
        # are normal SCADA polling, and replaying a read has no process impact.
        if event.operation_type not in ("WRITE", "CONTROL", "CONFIG"):
            return None

        if not hasattr(self, '_replay_tracker'):
            self._replay_tracker: Dict[str, List[Tuple[float, str, int, int, bytes]]] = defaultdict(list)

        key = f"{event.protocol.name}:{event.dst_ip}"
        tracker = self._replay_tracker[key]

        trans_id = 0
        if "TransID=" in event.notes:
            try:
                trans_id = int(event.notes.split("TransID=")[1].split(",")[0])
            except (ValueError, IndexError):
                pass

        # Window in which an identical command is considered a replay
        REPLAY_WINDOW = 300.0
        current_ts = event.timestamp
        tracker[:] = [t for t in tracker if current_ts - t[0] < REPLAY_WINDOW]

        # An identical command (same bytes incl. transaction ID) seen again from a
        # DIFFERENT flow is a replay. Repeats within the same flow (same source
        # IP and port) are TCP retransmissions and are ignored.
        replay_detected = False
        original = None
        for ts, src_ip, src_port, tid, data in tracker:
            if (src_ip, src_port) == (event.src_ip, event.src_port):
                continue
            if data == event.raw_data and len(data) > 10:
                replay_detected = True
                original = (ts, src_ip, src_port)
                break

        tracker.append((current_ts, event.src_ip, event.src_port, trans_id, event.raw_data))
        if len(tracker) > 500:
            del tracker[:-500]

        if replay_detected:
            return SecurityAnomaly(
                timestamp=event.timestamp, anomaly_type="OT_REPLAY_ATTACK",
                severity="CRITICAL", src_ip=event.src_ip, dst_ip=event.dst_ip,
                protocol=event.protocol.name,
                description="Potential replay attack: identical OT command re-sent from a different connection",
                evidence={"trans_id": trans_id, "protocol": event.protocol.name,
                          "original_ts": original[0] if original else None,
                          "original_source": f"{original[1]}:{original[2]}" if original else None},
                mitre_techniques=["T0830", "T0855", "T0856"], confidence=0.75,
                recommendation="Verify the origin of the packets and check for man-in-the-middle activity."
            )
        return None

    def analyze_firmware_manipulation(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """
        Detect firmware upload/manipulation attempts.

        Critical operations:
        - S7Comm: Request Download, Download Block, End Download
        - Modbus: Function code 90 (Firmware Update)
        - ENIP/CIP: Firmware download services
        """
        firmware_indicators = []

        # S7Comm firmware operations
        if event.protocol.name == "S7COMM":
            if event.function_code in [0x1A, 0x1B, 0x1C]:  # Download sequence
                firmware_indicators.append("S7_DOWNLOAD_SEQUENCE")
            if "Download" in event.function_name:
                firmware_indicators.append("S7_FIRMWARE_DOWNLOAD")

        # Modbus firmware
        elif event.protocol.name == "MODBUS_TCP":
            if event.function_code == 90:
                firmware_indicators.append("MODBUS_FIRMWARE_UPDATE")
            # Check for device identification requests before firmware
            if event.function_code == 43:  # MEI
                firmware_indicators.append("MODBUS_MEI_RECON")

        # ENIP/CIP firmware
        elif event.protocol.name == "ENIP":
            if event.function_code == 0x52:  # Multiple Service Packet
                firmware_indicators.append("CIP_MULTI_SERVICE")

        # OPC UA firmware
        elif event.protocol.name == "OPC_UA":
            if "WriteRequest" in event.function_name:
                # Check for firmware-related node writes
                firmware_indicators.append("OPCUA_POTENTIAL_FIRMWARE")

        if firmware_indicators:
            return SecurityAnomaly(
                timestamp=event.timestamp, anomaly_type="OT_FIRMWARE_MANIPULATION",
                severity="CRITICAL", src_ip=event.src_ip, dst_ip=event.dst_ip,
                protocol=event.protocol.name,
                description=f"Firmware manipulation detected: {', '.join(firmware_indicators)}",
                evidence={"indicators": firmware_indicators, "function": event.function_name},
                mitre_techniques=["T0839", "T0857", "T0843"], confidence=0.90,
                recommendation="URGENT: Verify whether this firmware update activity is authorized."
            )
        return None

    def analyze_setpoint_manipulation(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """
        Detect suspicious setpoint/control parameter changes.

        Monitors:
        - Large value changes in short time
        - Values outside normal operating range
        - Multiple setpoint changes to same device
        """
        if event.operation_type not in ["WRITE", "CONTROL"]:
            return None
        # MQTT PUBLISH is periodic telemetry, not a setpoint write to a controller
        if event.protocol.name == "MQTT":
            return None

        if not hasattr(self, '_setpoint_tracker'):
            self._setpoint_tracker: Dict[str, List[Tuple[float, int, int]]] = defaultdict(list)

        key = f"{event.dst_ip}:{event.protocol.name}"
        tracker = self._setpoint_tracker[key]

        # Record this write
        tracker.append((event.timestamp, event.data_address, event.data_count))

        # Keep only last 5 minutes
        cutoff = event.timestamp - 300
        self._setpoint_tracker[key] = [(ts, addr, cnt) for ts, addr, cnt in tracker if ts > cutoff]

        # Analyze patterns
        recent = self._setpoint_tracker[key]

        # Check for rapid setpoint changes (more than 10 in 1 minute)
        one_min_ago = event.timestamp - 60
        recent_writes = [(ts, addr, cnt) for ts, addr, cnt in recent if ts > one_min_ago]

        if len(recent_writes) > 10:
            # Check if targeting same address range (more suspicious)
            addresses = [addr for _, addr, _ in recent_writes]
            unique_addresses = len(set(addresses))

            if unique_addresses < len(addresses) * 0.5:  # Many writes to same addresses
                return SecurityAnomaly(
                    timestamp=event.timestamp, anomaly_type="OT_SETPOINT_MANIPULATION",
                    severity="HIGH", src_ip=event.src_ip, dst_ip=event.dst_ip,
                    protocol=event.protocol.name,
                    description=f"Rapid setpoint changes: {len(recent_writes)} writes in 1 min to {unique_addresses} addresses",
                    evidence={"write_count": len(recent_writes), "unique_addresses": unique_addresses,
                              "sample_addresses": addresses[:5]},
                    mitre_techniques=["T0831", "T0836", "T0833"], confidence=0.80,
                    recommendation="Review operating procedures - this may be an attack or an automation error."
                )
        return None

    def analyze_protocol_state_violation(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """
        Detect protocol state machine violations.

        Checks:
        - Commands sent without proper session establishment
        - Invalid command sequences
        - Response without request
        """
        if not hasattr(self, '_protocol_state'):
            self._protocol_state: Dict[str, Dict] = defaultdict(lambda: {"state": "IDLE", "last_ts": 0})

        key = f"{event.src_ip}:{event.dst_ip}:{event.protocol.name}"
        state = self._protocol_state[key]

        violation = None

        # S7Comm state validation
        if event.protocol.name == "S7COMM":
            if state["state"] == "IDLE":
                if event.function_code not in [0xF0, 0x00]:  # Setup or CPU Services
                    if event.operation_type in ["WRITE", "CONTROL"]:
                        violation = "S7_WRITE_WITHOUT_SETUP"

            # Update state. Setup Communication establishes the session; any
            # other non-modifying S7 exchange also proves an existing session
            # (captures frequently start in the middle of a connection).
            if event.function_code == 0xF0 or event.operation_type not in ["WRITE", "CONTROL"]:
                state["state"] = "CONNECTED"

        # IEC 104 state validation
        elif event.protocol.name == "IEC_104":
            if "U-Frame" in (event.notes or ""):  # U-format frames are marked in notes
                if "STARTDT" in event.function_name:
                    state["state"] = "ACTIVE"
                elif "STOPDT" in event.function_name:
                    if state["state"] != "ACTIVE":
                        violation = "IEC104_STOP_WITHOUT_START"
            elif event.operation_type == "CONTROL" and state["state"] != "ACTIVE":
                violation = "IEC104_CONTROL_WITHOUT_STARTDT"

        # DNP3 state validation
        elif event.protocol.name == "DNP3":
            if event.function_code == 0x04:  # Operate (Select-Before-Operate)
                # Operate must follow a Select (0x03). Direct Operate (0x05/0x06)
                # is legitimately sent without a Select.
                if state.get("last_func") not in [0x03, 0x04]:
                    violation = "DNP3_OPERATE_WITHOUT_SELECT"
            state["last_func"] = event.function_code

        state["last_ts"] = event.timestamp

        if violation:
            return SecurityAnomaly(
                timestamp=event.timestamp, anomaly_type="OT_PROTOCOL_STATE_VIOLATION",
                severity="HIGH", src_ip=event.src_ip, dst_ip=event.dst_ip,
                protocol=event.protocol.name,
                description=f"Protocol state violation: {violation}",
                evidence={"violation_type": violation, "current_state": state["state"]},
                mitre_techniques=["T0855", "T0831"], confidence=0.70,
                recommendation="Check the OT application - this may be an attack or a misconfiguration."
            )
        return None

    def detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> Optional[SecurityAnomaly]:
        """
        Detect port scanning behavior with improved false positive reduction.

        Improvements:
        - Higher thresholds to reduce false positives from legitimate services
        - Check for sequential vs random port patterns (scanners often sequential)
        - Consider destination diversity (scanning many hosts vs single host)
        - Deduplication to prevent alert spam
        """
        # Skip whitelisted IPs
        if src_ip in self.whitelisted_ips:
            self.track_legitimate_traffic(src_ip)
            return None

        # Fast scan (10 second window)
        if ts - self.scan_start_time_fast[src_ip] > 10:
            self.scan_tracker_fast[src_ip] = set()
            self.scan_start_time_fast[src_ip] = ts
            self.scan_alerted[f"{src_ip}_fast"] = False

        self.scan_tracker_fast[src_ip].add(dst_port)

        # Slow scan (5 minute window)
        if ts - self.scan_start_time_slow[src_ip] > 300:
            self.scan_tracker_slow[src_ip] = set()
            self.scan_start_time_slow[src_ip] = ts
            self.scan_alerted[f"{src_ip}_slow"] = False

        self.scan_tracker_slow[src_ip].add(dst_port)

        fast_ports = len(self.scan_tracker_fast[src_ip])
        # Increased threshold from 20 to 25, check for pattern
        if fast_ports > 25 and not self.scan_alerted.get(f"{src_ip}_fast"):
            # Mark as alerted FIRST to prevent repeated sort on every packet
            self.scan_alerted[f"{src_ip}_fast"] = True

            # Deduplication check
            alert_key = f"SCAN_FAST_{src_ip}"
            if self.is_duplicate_alert(alert_key, ts):
                return None

            # Check for sequential pattern (more likely to be a scan)
            ports_list = sorted(self.scan_tracker_fast[src_ip])
            sequential_count = sum(1 for i in range(len(ports_list)-1) if ports_list[i+1] - ports_list[i] == 1)
            is_sequential = sequential_count > fast_ports * 0.3  # 30% sequential = scan

            # Adjust confidence based on pattern
            confidence = 0.95 if is_sequential else 0.75
            severity = "HIGH" if is_sequential else "MEDIUM"

            self.update_risk_score(src_ip, 0.3, "FAST_PORT_SCAN", ts)

            # Extract IOC for this attack
            self.extract_ioc_for_attack("PORT_SCAN", {
                'ip': src_ip, 'ports': list(ports_list)[:20], 'timestamp': ts,
                'pattern': 'sequential' if is_sequential else 'random'
            })

            return SecurityAnomaly(
                timestamp=ts, anomaly_type="IT_PORT_SCAN_FAST", severity=severity,
                src_ip=src_ip, dst_ip="Multiple", protocol="TCP/UDP",
                description=f"Fast port scan from {src_ip} ({fast_ports} ports in 10s, {'sequential' if is_sequential else 'random'} pattern)",
                evidence={"ports_scanned": fast_ports, "time_window": "10 seconds",
                          "pattern": "sequential" if is_sequential else "random",
                          "sample_ports": ports_list[:10]},
                mitre_techniques=["T1046", "T0841"], confidence=confidence,
                recommendation="Isolate this host and check for malware. Pattern: " + ("sequential (very likely a scanner)" if is_sequential else "random (may be a legitimate application)")
            )

        slow_ports = len(self.scan_tracker_slow[src_ip])
        # Increased threshold from 50 to 60
        if slow_ports > 60 and not self.scan_alerted.get(f"{src_ip}_slow"):
            # Mark as alerted FIRST to prevent repeated processing on every packet
            self.scan_alerted[f"{src_ip}_slow"] = True

            alert_key = f"SCAN_SLOW_{src_ip}"
            if self.is_duplicate_alert(alert_key, ts):
                return None
            self.update_risk_score(src_ip, 0.25, "SLOW_PORT_SCAN", ts)

            # Extract IOC
            self.extract_ioc_for_attack("PORT_SCAN", {
                'ip': src_ip, 'ports': sorted(list(self.scan_tracker_slow[src_ip]))[:30],
                'timestamp': ts, 'pattern': 'slow'
            })

            return SecurityAnomaly(
                timestamp=ts, anomaly_type="IT_PORT_SCAN_SLOW", severity="MEDIUM",
                src_ip=src_ip, dst_ip="Multiple", protocol="TCP/UDP",
                description=f"Slow port scan from {src_ip} ({slow_ports} ports in 5min)",
                evidence={"ports_scanned": slow_ports, "time_window": "5 minutes"},
                mitre_techniques=["T1046", "T0841"], confidence=0.80,
                recommendation="Check engineering workstations or operator PCs. A slow scan may be caused by an application running in the background."
            )
        return None

    def detect_admin_port_attack(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> Optional[SecurityAnomaly]:
        """Detect attacks on IT admin ports"""
        if dst_port not in self.IT_ADMIN_PORTS:
            return None

        key = (src_ip, dst_ip, dst_port)
        self.admin_port_tracker[key].append(ts)
        self.admin_port_tracker[key] = [t for t in self.admin_port_tracker[key] if t > ts - 300]

        count = len(self.admin_port_tracker[key])
        port_name = self.IT_ADMIN_PORTS[dst_port]

        if count > 10:
            severity = "CRITICAL" if dst_port in [23, 3389] else "HIGH"
            return SecurityAnomaly(
                timestamp=ts, anomaly_type=f"IT_ADMIN_PORT_ATTACK_{port_name.upper()}",
                severity=severity, src_ip=src_ip, dst_ip=dst_ip, protocol="TCP",
                description=f"High {port_name} connection rate: {count} in 5min",
                evidence={"port": dst_port, "port_name": port_name, "connection_count": count},
                mitre_techniques=["T1110", "T1021"], confidence=0.85,
                recommendation=f"Investigate {port_name} connections from {src_ip}."
            )
        return None

    def detect_brute_force(self, src_ip: str, dst_ip: str, dst_port: int,
                           ts: float, is_failed: bool = True) -> Optional[SecurityAnomaly]:
        """Detect brute force attacks"""
        if not is_failed:
            return None

        key = (src_ip, dst_ip, dst_port)
        self.brute_force_tracker[key].append(ts)
        self.brute_force_tracker[key] = [t for t in self.brute_force_tracker[key] if t > ts - 60]

        count = len(self.brute_force_tracker[key])

        if count > 5:
            port_name = self.IT_ADMIN_PORTS.get(dst_port, f"port {dst_port}")
            return SecurityAnomaly(
                timestamp=ts, anomaly_type="IT_BRUTE_FORCE", severity="HIGH",
                src_ip=src_ip, dst_ip=dst_ip, protocol="TCP",
                description=f"Brute force attack on {port_name}: {count} failed attempts in 60s",
                evidence={"port": dst_port, "failed_count": count, "time_window": "60s"},
                mitre_techniques=["T1110"], confidence=0.90,
                recommendation="Block the source IP and check the targeted accounts."
            )
        return None

    def detect_lateral_movement(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> Optional[SecurityAnomaly]:
        """Detect lateral movement (SMB spreading)"""
        if dst_port not in [445, 139, 135]:
            return None

        self.smb_connection_tracker[src_ip].add(dst_ip)
        self.smb_connection_times[src_ip].append(ts)
        self.smb_connection_times[src_ip] = [t for t in self.smb_connection_times[src_ip] if t > ts - 300]

        unique_targets = len(self.smb_connection_tracker[src_ip])

        if unique_targets > 5:
            return SecurityAnomaly(
                timestamp=ts, anomaly_type="IT_LATERAL_MOVEMENT_SMB", severity="CRITICAL",
                src_ip=src_ip, dst_ip="Multiple", protocol="SMB",
                description=f"SMB lateral movement: {src_ip} connecting to {unique_targets} targets",
                evidence={"targets_count": unique_targets, "targets": list(self.smb_connection_tracker[src_ip])[:10]},
                mitre_techniques=["T1021.002", "T1570"], confidence=0.88,
                recommendation="Isolate the source host and check for malware/ransomware."
            )
        return None

    # =========================================================================
    # IT DETECTION METHODS
    # =========================================================================

    def detect_dns_tunneling(self, dns_data: Dict[str, Any]) -> List[SecurityAnomaly]:
        """Detect DNS tunneling attempts"""
        anomalies = []
        src_ip = dns_data['src_ip']
        ts = dns_data['timestamp']

        for query in dns_data.get('queries', []):
            qname = query.get('name', '')
            qtype = query.get('type', 0)

            if not qname or '.' not in qname:
                continue

            # Extract subdomain
            parts = qname.split('.')
            if len(parts) > 2:
                subdomain = '.'.join(parts[:-2])
                domain = '.'.join(parts[-2:])
            else:
                subdomain = ""
                domain = qname

            # Track subdomain diversity
            self.dns_subdomain_tracker[f"{src_ip}:{domain}"].add(subdomain)

            # Track TXT queries
            if qtype == 16:  # TXT record
                self.dns_txt_tracker[src_ip].append(ts)
                self.dns_txt_tracker[src_ip] = [t for t in self.dns_txt_tracker[src_ip] if t > ts - 60]

                txt_count = len(self.dns_txt_tracker[src_ip])
                if txt_count > DNS_TUNNELING_INDICATORS['txt_query_rate_threshold']:
                    anomalies.append(SecurityAnomaly(
                        timestamp=ts, anomaly_type="DNS_TUNNEL_TXT_ABUSE",
                        severity="HIGH", src_ip=src_ip, dst_ip=dns_data['dst_ip'],
                        protocol="DNS",
                        description=f"High TXT query rate: {txt_count} queries/min from {src_ip}",
                        evidence={"txt_count": txt_count, "domain": domain},
                        mitre_techniques=["T1071.004"], confidence=0.85,
                        recommendation="Inspect the host; malware may be using DNS for C2."
                    ))

            # Check: Long subdomain
            if len(subdomain) > DNS_TUNNELING_INDICATORS['long_subdomain_threshold']:
                anomalies.append(SecurityAnomaly(
                    timestamp=ts, anomaly_type="DNS_TUNNEL_LONG_QUERY",
                    severity="HIGH", src_ip=src_ip, dst_ip=dns_data['dst_ip'],
                    protocol="DNS",
                    description=f"Long DNS subdomain ({len(subdomain)} chars): {subdomain[:50]}...",
                    evidence={"subdomain_length": len(subdomain), "domain": domain},
                    mitre_techniques=["T1071.004", "T1048.003"], confidence=0.80,
                    recommendation="Review DNS traffic from this host."
                ))

            # Check: High entropy subdomain
            if subdomain and len(subdomain) > 10:
                subdomain_entropy = entropy(subdomain.encode())
                if subdomain_entropy > DNS_TUNNELING_INDICATORS['high_entropy_threshold']:
                    anomalies.append(SecurityAnomaly(
                        timestamp=ts, anomaly_type="DNS_TUNNEL_ENTROPY",
                        severity="CRITICAL", src_ip=src_ip, dst_ip=dns_data['dst_ip'],
                        protocol="DNS",
                        description=f"High entropy DNS subdomain: {subdomain_entropy:.2f}",
                        evidence={"entropy": subdomain_entropy, "subdomain": subdomain[:30]},
                        mitre_techniques=["T1071.004", "T1048.003"], confidence=0.90,
                        recommendation="WARNING: Possible DNS tunneling/exfiltration. Investigate immediately!"
                    ))

            # Check: Too many unique subdomains
            unique_count = len(self.dns_subdomain_tracker[f"{src_ip}:{domain}"])
            if unique_count > DNS_TUNNELING_INDICATORS['unique_subdomain_threshold']:
                anomalies.append(SecurityAnomaly(
                    timestamp=ts, anomaly_type="DNS_TUNNEL_SUBDOMAIN_DIVERSITY",
                    severity="CRITICAL", src_ip=src_ip, dst_ip=dns_data['dst_ip'],
                    protocol="DNS",
                    description=f"Excessive subdomain diversity: {unique_count} unique subdomains for {domain}",
                    evidence={"unique_subdomains": unique_count, "domain": domain},
                    mitre_techniques=["T1071.004", "T1048.003"], confidence=0.95,
                    recommendation="DNS tunneling is almost certain. Isolate the host immediately!"
                ))

        return anomalies

    def detect_arp_spoofing(self, arp_data: Dict[str, Any]) -> List[SecurityAnomaly]:
        """Detect ARP spoofing/poisoning attacks"""
        anomalies = []
        ts = arp_data['timestamp']
        sender_ip = arp_data['sender_ip']
        sender_mac = arp_data['sender_mac']

        # Track IP-MAC mapping changes
        self.ip_mac_mapping[sender_ip].append((sender_mac, ts))
        self.ip_mac_mapping[sender_ip] = [
            (mac, t) for mac, t in self.ip_mac_mapping[sender_ip]
            if t > ts - 300
        ]

        # Get unique MACs for this IP
        recent_macs = set(mac for mac, _ in self.ip_mac_mapping[sender_ip])

        # Check for MAC address change (potential spoofing)
        if len(recent_macs) > ARP_DETECTION_CONFIG['mac_ip_change_threshold']:
            anomalies.append(SecurityAnomaly(
                timestamp=ts, anomaly_type="ARP_SPOOFING_DETECTED",
                severity="CRITICAL", src_ip=sender_ip, dst_ip="Network",
                protocol="ARP",
                description=f"ARP spoofing detected: IP {sender_ip} has {len(recent_macs)} different MACs",
                evidence={"ip": sender_ip, "macs": list(recent_macs)},
                mitre_techniques=["T1557.002", "T1040"], confidence=0.92,
                recommendation="A MITM attack may be in progress. Isolate the network segment!"
            ))
            self.update_risk_score(sender_ip, 0.5, "ARP_SPOOFING", ts)

        # Track gratuitous ARP
        if arp_data.get('is_gratuitous', False):
            self.gratuitous_arp_tracker[sender_ip].append(ts)
            self.gratuitous_arp_tracker[sender_ip] = [
                t for t in self.gratuitous_arp_tracker[sender_ip] if t > ts - 60
            ]

            grat_count = len(self.gratuitous_arp_tracker[sender_ip])
            if grat_count > ARP_DETECTION_CONFIG['gratuitous_arp_threshold']:
                anomalies.append(SecurityAnomaly(
                    timestamp=ts, anomaly_type="GRATUITOUS_ARP_ABUSE",
                    severity="HIGH", src_ip=sender_ip, dst_ip="Network",
                    protocol="ARP",
                    description=f"Gratuitous ARP abuse: {grat_count} in 60s from {sender_ip}",
                    evidence={"count": grat_count, "ip": sender_ip, "mac": sender_mac},
                    mitre_techniques=["T1557.002"], confidence=0.85,
                    recommendation="Check whether this is a new device or a MITM attack."
                ))

        # Track ARP storm
        self.arp_packet_tracker[sender_ip].append(ts)
        self.arp_packet_tracker[sender_ip] = [
            t for t in self.arp_packet_tracker[sender_ip] if t > ts - 10
        ]

        arp_count = len(self.arp_packet_tracker[sender_ip])
        if arp_count > ARP_DETECTION_CONFIG['arp_storm_threshold']:
            anomalies.append(SecurityAnomaly(
                timestamp=ts, anomaly_type="ARP_STORM",
                severity="HIGH", src_ip=sender_ip, dst_ip="Network",
                protocol="ARP",
                description=f"ARP storm: {arp_count} packets in 10s from {sender_ip}",
                evidence={"count": arp_count, "ip": sender_ip},
                mitre_techniques=["T1557.002"], confidence=0.80,
                recommendation="May be MITM preparation or a network fault."
            ))

        return anomalies

    def detect_data_exfiltration(self, src_ip: str, dst_ip: str,
                                  bytes_transferred: int, ts: float) -> Optional[SecurityAnomaly]:
        """Detect potential data exfiltration"""
        key = (src_ip, dst_ip)

        # Track transfer
        # Sliding 10-minute window kept as a deque with a running total (O(1) per packet)
        window = self.data_transfer_tracker[key]
        window.append((ts, bytes_transferred))
        running = self._data_transfer_totals.get(key, 0) + bytes_transferred
        while window and window[0][0] <= ts - 600:
            running -= window.popleft()[1]
        self._data_transfer_totals[key] = running

        # Calculate total in window
        total_bytes = running

        # Track hourly totals
        hour = int(ts // 3600)
        hourly_key = (src_ip, dst_ip, hour)
        self.hourly_data_tracker[hourly_key] += bytes_transferred

        # Check for large single transfer
        if bytes_transferred > DATA_EXFIL_THRESHOLDS['large_transfer_bytes']:
            self.update_risk_score(src_ip, 0.3, "LARGE_DATA_TRANSFER", ts)
            return SecurityAnomaly(
                timestamp=ts, anomaly_type="DATA_EXFIL_LARGE_TRANSFER",
                severity="CRITICAL", src_ip=src_ip, dst_ip=dst_ip,
                protocol="TCP",
                description=f"Large data transfer: {format_bytes(bytes_transferred)} to {dst_ip}",
                evidence={"bytes": bytes_transferred, "total_10min": total_bytes},
                mitre_techniques=["T1041", "T1048"], confidence=0.85,
                recommendation="Verify that this is legitimate activity."
            )

        # Check for unusual hours
        from datetime import datetime

        # Normalize timestamp (auto-correct milliseconds/microseconds)
        ts = normalize_timestamp(ts)
        if ts is None:
            return None

        try:
            hour_of_day = datetime.fromtimestamp(ts).hour
        except (ValueError, OSError) as e:
            logger.warning(f"Failed to convert timestamp {ts} to datetime: {e}")
            return None

        is_unusual_hour = (hour_of_day >= DATA_EXFIL_THRESHOLDS['unusual_hour_start'] or
                          hour_of_day < DATA_EXFIL_THRESHOLDS['unusual_hour_end'])

        if is_unusual_hour and total_bytes > 10_000_000:
            return SecurityAnomaly(
                timestamp=ts, anomaly_type="DATA_EXFIL_UNUSUAL_HOURS",
                severity="HIGH", src_ip=src_ip, dst_ip=dst_ip,
                protocol="TCP",
                description=f"Data transfer at unusual hour ({hour_of_day}:00): {format_bytes(total_bytes)}",
                evidence={"bytes": total_bytes, "hour": hour_of_day},
                mitre_techniques=["T1048"], confidence=0.75,
                recommendation="Investigate activity outside of business hours."
            )

        # Check hourly threshold
        hourly_total = self.hourly_data_tracker[hourly_key]
        if hourly_total > DATA_EXFIL_THRESHOLDS['cumulative_threshold_hour']:
            return SecurityAnomaly(
                timestamp=ts, anomaly_type="DATA_EXFIL_CUMULATIVE",
                severity="CRITICAL", src_ip=src_ip, dst_ip=dst_ip,
                protocol="TCP",
                description=f"Cumulative data exceeds threshold: {format_bytes(hourly_total)}/hour",
                evidence={"hourly_bytes": hourly_total},
                mitre_techniques=["T1041", "T1048"], confidence=0.90,
                recommendation="Serious data leak. Investigate immediately!"
            )

        return None

    def detect_c2_beacon(self, src_ip: str, dst_ip: str, dst_port: int,
                          ts: float) -> Optional[SecurityAnomaly]:
        """Detect C2 beacon patterns based on connection timing"""
        key = (src_ip, dst_ip, dst_port)

        # Track connection timestamps (cap at 50 entries - only need recent for beacon analysis)
        timestamps = self.connection_intervals[key]
        timestamps.append(ts)
        if len(timestamps) > 50:
            # Keep only the last 30 entries (O(1) amortized)
            self.connection_intervals[key] = timestamps[-30:]
            timestamps = self.connection_intervals[key]

        n_ts = len(timestamps)
        min_count = C2_BEACON_INDICATORS['min_beacon_count']

        # Need minimum connections for beacon detection
        if n_ts < min_count:
            return None

        # Only analyze every 5th entry to reduce computation
        if n_ts % 5 != 0:
            return None

        # Use the available entries for analysis
        recent = timestamps

        # Calculate intervals between connections
        intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]

        if not intervals:
            return None

        # Calculate statistics (native Python - avoids numpy overhead for small arrays)
        n = len(intervals)
        mean_interval = sum(intervals) / n
        variance = sum((x - mean_interval) ** 2 for x in intervals) / n
        std_interval = variance ** 0.5

        # Check for regular beacon
        if mean_interval > 0:
            coefficient_of_variation = std_interval / mean_interval

            # Check if within beacon interval ranges
            is_beacon_interval = any(
                low <= mean_interval <= high
                for low, high in C2_BEACON_INDICATORS['beacon_interval_ranges']
            )

            # Very regular interval - likely C2 beacon
            if coefficient_of_variation < C2_BEACON_INDICATORS['regular_interval_tolerance'] and is_beacon_interval:
                self.update_risk_score(src_ip, 0.4, "C2_BEACON_DETECTED", ts)
                return SecurityAnomaly(
                    timestamp=ts, anomaly_type="C2_BEACON_REGULAR",
                    severity="CRITICAL", src_ip=src_ip, dst_ip=dst_ip,
                    protocol="TCP",
                    description=f"C2 beacon detected: {len(timestamps)} connections at ~{mean_interval:.0f}s intervals",
                    evidence={
                        "connection_count": len(timestamps),
                        "mean_interval": float(mean_interval),
                        "std_interval": float(std_interval),
                        "port": dst_port
                    },
                    mitre_techniques=["T1071", "T1573"], confidence=0.92,
                    recommendation="Isolate the host immediately and check for malware!"
                )

            # Beacon with jitter
            elif coefficient_of_variation < C2_BEACON_INDICATORS['jitter_threshold'] and is_beacon_interval:
                return SecurityAnomaly(
                    timestamp=ts, anomaly_type="C2_BEACON_JITTER",
                    severity="HIGH", src_ip=src_ip, dst_ip=dst_ip,
                    protocol="TCP",
                    description=f"Possible C2 beacon with jitter: ~{mean_interval:.0f}s avg (cv={coefficient_of_variation:.2f})",
                    evidence={
                        "connection_count": len(timestamps),
                        "mean_interval": float(mean_interval),
                        "cv": float(coefficient_of_variation),
                        "port": dst_port
                    },
                    mitre_techniques=["T1071", "T1573"], confidence=0.75,
                    recommendation="Review traffic to this IP."
                )

        return None

    def detect_post_exploitation_stream(self, src_ip: str, dst_ip: str,
                                         src_port: int, dst_port: int,
                                         tcp_payload: bytes, ts: float) -> List[SecurityAnomaly]:
        """
        Detect post-exploitation activity in TCP stream content.

        Scans TCP payload for indicators of:
        - Active shell sessions (reverse shell, webshell)
        - Credential theft (/etc/shadow, password exposure)
        - Privilege escalation (SUID exploitation, sudo abuse)
        - Internal reconnaissance (system/network enumeration)
        - Lateral movement (su, ssh to internal hosts)
        - Data exfiltration via shell

        Args:
            src_ip, dst_ip: IP addresses
            src_port, dst_port: Ports
            tcp_payload: Raw TCP payload bytes
            ts: Timestamp

        Returns:
            List of SecurityAnomaly objects for detected post-exploitation activity
        """
        anomalies = []

        # Only scan payloads with meaningful content (skip tiny packets)
        if len(tcp_payload) < 10:
            return anomalies

        # Limit scan to first 8KB to avoid performance issues on large transfers
        scan_data = tcp_payload[:8192]
        # Shell sessions are text. Skip clearly binary/encrypted payloads
        # (TLS, OT protocols, file transfers): >30% non-printable bytes.
        # bytes.translate runs in C, so this check is far cheaper than the regexes.
        if len(scan_data.translate(None, _PRINTABLE_BYTES)) > len(scan_data) * 0.3:
            return anomalies
        if self._post_exploit_all is not None and not self._post_exploit_all.search(scan_data):
            return anomalies

        for category, config in POST_EXPLOITATION_PATTERNS.items():
            any_pat = self._post_exploit_any.get(category)
            if any_pat is not None and not any_pat.search(scan_data):
                continue
            compiled_patterns = self._post_exploit_compiled.get(category, [])
            severity = config.get('severity', 'MEDIUM')
            mitre = config.get('mitre', [])
            desc_text = config.get('desc', '')

            for compiled_pat in compiled_patterns:
                try:
                    match = compiled_pat.search(scan_data)
                    if match:
                        matched_text = match.group(0).decode('utf-8', errors='replace')

                        # Dedup: direction-independent key with longer window for attack chains
                        ip_pair = tuple(sorted([src_ip, dst_ip]))
                        dedup_key = f"POST_EXPLOIT_{category}_{ip_pair[0]}_{ip_pair[1]}"
                        if dedup_key in self.recent_alerts:
                            if ts - self.recent_alerts[dedup_key] < 300:  # 5-min window for post-exploit
                                break  # Skip this category
                        self.recent_alerts[dedup_key] = ts

                        # Extract context around the match for evidence
                        start = max(0, match.start() - 40)
                        end = min(len(scan_data), match.end() + 80)
                        context = scan_data[start:end].decode('utf-8', errors='replace')
                        context = context.replace('\r', '\\r').replace('\n', '\\n')

                        anomalies.append(SecurityAnomaly(
                            timestamp=ts,
                            anomaly_type=f"POST_EXPLOIT_{category}",
                            severity=severity,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            protocol="TCP",
                            description=(
                                f"Post-exploitation activity [{category}]: "
                                f"'{matched_text[:60]}' detected in TCP stream "
                                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                            ),
                            evidence={
                                "category": category,
                                "matched_pattern": matched_text[:100],
                                "context": context[:200],
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "payload_size": len(tcp_payload),
                            },
                            mitre_techniques=mitre,
                            confidence=0.90,
                            recommendation=(
                                f"1. ISOLATE hosts {src_ip} and {dst_ip} IMMEDIATELY\n"
                                f"2. Review all sessions to/from these IPs\n"
                                f"3. Collect forensic evidence before cleanup\n"
                                f"4. Review the attack timeline and lateral movement\n"
                                f"5. Report to the Incident Response team"
                            ),
                        ))
                        break  # One match per category is enough
                except re.error:
                    continue

        return anomalies

    def detect_directory_bruteforce(self, client_ip: str, server_ip: str,
                                     status_code: int, server_port: int,
                                     ts: float) -> Optional[SecurityAnomaly]:
        """
        Detect directory brute-force / enumeration attacks by analyzing HTTP response patterns.

        Triggers when a single client receives many 404/403 responses from a server
        in a short time window - a strong indicator of tools like Gobuster, DirBuster,
        DIRB, ffuf, feroxbuster, dirsearch, etc.
        """
        tracker_key = f"{client_ip}->{server_ip}:{server_port}"

        # O(1) incremental counters per window (reset every 120 seconds)
        counters = self._http_response_tracker.get(tracker_key)
        if counters is None or ts - counters['window_start'] > 120:
            # Start new window
            counters = {'window_start': ts, 'total': 0, 'error': 0, 'not_found': 0}
            self._http_response_tracker[tracker_key] = counters

        counters['total'] += 1
        error_codes = {400, 401, 403, 404, 405, 500}
        if status_code in error_codes:
            counters['error'] += 1
            if status_code == 404:
                counters['not_found'] += 1

        total_responses = counters['total']
        error_count = counters['error']
        not_found_count = counters['not_found']

        # Need minimum responses before analyzing
        if total_responses < 20:
            return None

        # Calculate error ratio
        error_ratio = error_count / total_responses

        # Directory brute-force indicators
        is_bruteforce = False
        confidence = 0.0
        severity = "MEDIUM"

        if not_found_count >= 30 and error_ratio > 0.7:
            is_bruteforce = True
            confidence = 0.92
            severity = "HIGH"
        elif not_found_count >= 15 and error_ratio > 0.6:
            is_bruteforce = True
            confidence = 0.80
            severity = "MEDIUM"

        if not is_bruteforce:
            return None

        # Dedup: only alert once per 120s per client->server pair
        if tracker_key in self._dir_bruteforce_alerted:
            last_alert = self._dir_bruteforce_alerted[tracker_key]
            if ts - last_alert < 120:
                return None
        self._dir_bruteforce_alerted[tracker_key] = ts

        # Calculate request rate
        time_span = ts - counters['window_start']
        rate = total_responses / max(time_span, 0.1)

        return SecurityAnomaly(
            timestamp=ts,
            anomaly_type="HTTP_DIRECTORY_BRUTEFORCE",
            severity=severity,
            src_ip=client_ip,
            dst_ip=server_ip,
            protocol="HTTP",
            description=(
                f"Directory brute-force detected: {not_found_count} 404s out of "
                f"{total_responses} responses in 120s ({error_ratio:.0%} errors, "
                f"{rate:.1f} req/s)"
            ),
            evidence={
                "total_responses": total_responses,
                "404_count": not_found_count,
                "error_count": error_count,
                "error_ratio": round(error_ratio, 3),
                "rate_per_second": round(rate, 2),
                "time_window": "120s",
                "server_port": server_port,
                "likely_tools": "Gobuster, DirBuster, DIRB, ffuf, dirsearch, feroxbuster",
            },
            mitre_techniques=["T1595.003", "T1083"],  # Active Scanning: Wordlist, File and Directory Discovery
            confidence=confidence,
            recommendation=(
                f"1. BLOCK IP {client_ip} at the WAF/Firewall\n"
                f"2. Review access logs from this IP\n"
                f"3. Review directories/files that were discovered (200 OK responses)\n"
                f"4. Enable rate limiting on the web server\n"
                f"5. Configure the WAF to block directory enumeration"
            ),
            behavior=f"IP {client_ip} is brute-forcing directories on {server_ip}:{server_port} at {rate:.1f} req/s",
            danger=(
                "This is an automated directory brute-force attack. "
                "The attacker uses a wordlist to find hidden files/directories on the web server. "
                "If sensitive files are found (config, backup, admin panel), this can lead to compromise."
            ),
            attack_scenario=(
                "The attacker uses tools such as Gobuster/DirBuster to enumerate directories on the web server. "
                "The goal is to find unprotected files/directories (admin panels, backup files, "
                "config files, hidden APIs). This is the Reconnaissance stage of the kill chain."
            ),
            risk_assessment=f"{severity} - Currently in the Active Scanning / Reconnaissance stage",
            ot_impact=(
                "If the web server is an HMI/SCADA web interface, the attacker may discover "
                "control endpoints, API documentation, or backup configurations. "
                "This can lead to unauthorized access to OT systems."
            ),
            remediation_steps=(
                f"1. Block IP {client_ip} at the firewall/WAF immediately\n"
                f"2. Review access logs to identify URLs that returned 200 OK\n"
                f"3. Remove or protect any sensitive files that were discovered\n"
                f"4. Configure rate limiting (e.g., 10 req/s per IP)\n"
                f"5. Enable WAF rules against directory brute-force\n"
                f"6. Report to the SOC team to monitor this IP"
            ),
        )

    def detect_http_attacks(self, http_data: Dict[str, Any]) -> List[SecurityAnomaly]:
        """
        Detect HTTP-based attacks including WebShells, obfuscation, and file uploads.

        This method uses the CONFIGURABLE rule-based system from HTTP_SUSPICIOUS_PATTERNS.
        To add new detection patterns: simply add to HTTP_SUSPICIOUS_PATTERNS in constants.py.
        No code change needed here - patterns are automatically processed.

        Enhanced features:
        - Detailed attack explanations for user understanding
        - Suspicious payload extraction for forensics
        - HTTP behavior heuristics (rapid requests, recon)
        """
        import re
        import hashlib
        anomalies = []
        detected_types = set()  # Avoid duplicate alerts

        src_ip = http_data['src_ip']
        dst_ip = http_data['dst_ip']
        src_port = http_data.get('src_port', 0)
        dst_port = http_data.get('dst_port', 80)
        ts = http_data['timestamp']
        uri = http_data.get('uri', '')
        user_agent = http_data.get('user_agent', '')
        body = http_data.get('body', '')
        headers_raw = http_data.get('headers_raw', '')
        method = http_data.get('method', '')
        content_type = http_data.get('content_type', '')

        # Combine all searchable content (for comprehensive detection)
        search_targets = [
            ('uri', uri),
            ('body', body),
            ('headers', headers_raw),
        ]
        # Also match URL-decoded forms (attackers routinely percent-encode
        # payloads, e.g. ";cat%20/etc/passwd"); decode twice for double-encoding.
        from urllib.parse import unquote_plus
        for name, raw in (('uri', uri), ('body', body if 'urlencoded' in content_type.lower() or not content_type else '')):
            decoded = raw
            for _ in range(2):
                try:
                    nxt = unquote_plus(decoded)
                except Exception:
                    break
                if nxt == decoded:
                    break
                decoded = nxt
            if decoded and decoded != raw:
                search_targets.append((name, decoded))

        def create_anomaly_with_explanation(
            attack_type: str, config: dict, evidence: dict,
            target_name: str, matched_content: str, pattern: str
        ) -> SecurityAnomaly:
            """Helper to create anomaly with full explanation and payload extraction"""
            # Get detailed explanation
            explanation = get_attack_explanation(attack_type)

            # Determine confidence
            confidence = 0.85
            if 'OBFUSCATION' in attack_type:
                confidence = 0.80
            if 'WEBSHELL' in attack_type and target_name == 'body':
                confidence = 0.90

            # Extract suspicious payload for forensics
            extracted_payload = None
            if target_name == 'body' and body and ('WEBSHELL' in attack_type or 'OBFUSCATION' in attack_type):
                payload_bytes = body[:2048].encode('utf-8', errors='replace')
                payload_hash = hashlib.sha256(payload_bytes).hexdigest()
                extracted_payload = SuspiciousPayload(
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="HTTP",
                    payload_type=attack_type,
                    payload_data=payload_bytes[:1024],  # Limit size
                    payload_preview=body[:200].replace('\n', '\\n'),
                    detection_reason=f"Pattern matched: {pattern}",
                    sha256_hash=payload_hash,
                )

            # Pass through threat_analysis from http_data if present
            threat_analysis = http_data.get('threat_analysis', None)

            # Prefer detected_threats from threat_analysis to build a more specific anomaly_type
            final_anomaly_type = f"HTTP_{attack_type}"
            if threat_analysis and threat_analysis.get('detected_threats'):
                # Use the first threat from threat_analysis
                primary_threat = threat_analysis['detected_threats'][0]
                final_anomaly_type = f"HTTP_{primary_threat}"

            return SecurityAnomaly(
                timestamp=ts,
                anomaly_type=final_anomaly_type,
                severity=config['severity'],
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="HTTP",
                description=f"HTTP {attack_type}: pattern found in {target_name}",
                evidence=evidence,
                mitre_techniques=config.get('mitre', []),
                confidence=confidence,
                recommendation=explanation.get('remediation', f"Investigate source {src_ip} and block if necessary."),
                # Enhanced explanation fields
                behavior=explanation.get('behavior', ''),
                danger=explanation.get('danger', ''),
                attack_scenario=explanation.get('scenario', ''),
                risk_assessment=explanation.get('risk_level', ''),
                ot_impact=explanation.get('ot_impact', ''),
                remediation_steps=explanation.get('remediation', ''),
                extracted_payload=extracted_payload,
                # New field: threat_analysis
                threat_analysis=threat_analysis,
            )

        # =====================================================================
        # PATTERN-BASED DETECTION (Configurable rules from constants.py)
        # =====================================================================
        for attack_type, config in HTTP_SUSPICIOUS_PATTERNS.items():
            if attack_type in detected_types:
                continue

            patterns = config.get('patterns', [])
            if not patterns:
                continue

            # Special handling for User-Agent patterns
            if attack_type == "SUSPICIOUS_USER_AGENT":
                for pattern in patterns:
                    if cached_regex(pattern, re.IGNORECASE).search(user_agent):
                        detected_types.add(attack_type)

                        # Extract specific tool name for detailed alerting
                        tool_name = "Unknown Scanner"
                        tool_purpose = "vulnerability scanning"
                        ua_lower = user_agent.lower()

                        if "gobuster" in ua_lower:
                            tool_name = "Gobuster"
                            tool_purpose = "directory/DNS brute-forcing"
                        elif "dirb" in ua_lower:
                            tool_name = "DIRB"
                            tool_purpose = "web content scanner"
                        elif "nikto" in ua_lower:
                            tool_name = "Nikto"
                            tool_purpose = "web server vulnerability scanning"
                        elif "sqlmap" in ua_lower:
                            tool_name = "SQLMap"
                            tool_purpose = "SQL injection exploitation"
                        elif "nmap" in ua_lower:
                            tool_name = "Nmap"
                            tool_purpose = "network port scanning"
                        elif "masscan" in ua_lower:
                            tool_name = "Masscan"
                            tool_purpose = "high-speed port scanning"
                        elif "wfuzz" in ua_lower or "w3af" in ua_lower:
                            tool_name = "Wfuzz/W3AF"
                            tool_purpose = "web application fuzzing"
                        elif "burp" in ua_lower or "suite" in ua_lower:
                            tool_name = "Burp Suite"
                            tool_purpose = "web penetration testing"
                        elif "metasploit" in ua_lower:
                            tool_name = "Metasploit"
                            tool_purpose = "exploitation framework"
                        elif "acunetix" in ua_lower:
                            tool_name = "Acunetix"
                            tool_purpose = "automated vulnerability scanning"
                        elif "nessus" in ua_lower:
                            tool_name = "Nessus"
                            tool_purpose = "vulnerability assessment"
                        elif "nuclei" in ua_lower:
                            tool_name = "Nuclei"
                            tool_purpose = "vulnerability scanning"
                        elif "zap" in ua_lower or "owasp" in ua_lower:
                            tool_name = "OWASP ZAP"
                            tool_purpose = "web application security testing"

                        explanation = get_attack_explanation(attack_type)
                        anomalies.append(SecurityAnomaly(
                            timestamp=ts, anomaly_type=f"HTTP_{attack_type}",
                            severity=config['severity'], src_ip=src_ip, dst_ip=dst_ip,
                            protocol="HTTP",
                            description=f"⚠️ SCANNING TOOL DETECTED: {tool_name} - {tool_purpose}",
                            evidence={"user_agent": user_agent, "pattern": pattern, "tool_name": tool_name, "tool_purpose": tool_purpose},
                            mitre_techniques=config.get('mitre', []), confidence=0.95,
                            recommendation=f"BLOCK THIS IP IMMEDIATELY! {tool_name} is a dedicated attack tool.",
                            behavior=f"HTTP request from {tool_name} - User-Agent: {user_agent[:80]}",
                            danger=f"THIS IS AN ATTACK TOOL! {tool_name} is used for {tool_purpose}. The attacker is actively scanning the system for vulnerabilities.",
                            attack_scenario=f"The attacker is using {tool_name} to automatically scan for and discover vulnerabilities in the system. This is the first step before the actual attack.",
                            risk_assessment="HIGH - Currently in the active reconnaissance stage",
                            ot_impact=f"The attacker is scanning OT system web interfaces for vulnerabilities. {tool_name} may uncover weaknesses to exploit in later attacks.",
                            remediation_steps=f"1. BLOCK IP {src_ip} AT THE FIREWALL IMMEDIATELY\n2. Review all access logs from this IP\n3. Review the scanned endpoints\n4. Increase monitoring of traffic from this IP\n5. Report to the SOC/security team",
                        ))
                        break
                continue

            # Special handling for Header Anomaly patterns
            if attack_type == "HEADER_ANOMALY":
                for pattern in patterns:
                    if cached_regex(pattern, re.IGNORECASE | re.MULTILINE).search(headers_raw):
                        detected_types.add(attack_type)
                        anomalies.append(SecurityAnomaly(
                            timestamp=ts, anomaly_type=f"HTTP_{attack_type}",
                            severity=config['severity'], src_ip=src_ip, dst_ip=dst_ip,
                            protocol="HTTP",
                            description="HTTP header anomaly detected",
                            evidence={"headers": headers_raw[:200], "pattern": pattern},
                            mitre_techniques=config.get('mitre', []), confidence=0.75,
                            recommendation="Review HTTP traffic from this IP.",
                            behavior=f"HTTP headers contain abnormal content: {pattern}",
                            danger="Header manipulation may indicate an attack tool or malware.",
                            attack_scenario="The attacker may be attempting to bypass security controls.",
                            risk_assessment="MEDIUM - Header anomaly requires investigation",
                            ot_impact="May be a bot/crawler scanning OT web interfaces.",
                            remediation_steps="1. Review header patterns\n2. Block if malicious\n3. Update WAF rules",
                        ))
                        break
                continue

            # Optional per-rule restrictions (see HTTP_SUSPICIOUS_PATTERNS):
            #   'methods': only evaluate for these HTTP methods
            #   'targets': only search these parts of the request (uri/body/headers)
            allowed_methods = config.get('methods')
            if allowed_methods and method.upper() not in allowed_methods:
                continue
            allowed_targets = config.get('targets', ('uri', 'body', 'headers'))
            rule_targets = search_targets
            if attack_type == "SSRF_ATTACK":
                # SSRF indicators only matter inside URL-like parameter values,
                # not in Host/Referer headers or arbitrary text.
                url_values = " ".join(re.findall(
                    r'(?:^|[?&=;,\s"\'])((?:[a-z][a-z0-9+.-]*:)?//[^&\s"\']+)', uri + "&" + body, re.IGNORECASE))
                rule_targets = [('uri', url_values)]

            # Check all search targets for other attack patterns
            for target_name, target_content in rule_targets:
                if attack_type in detected_types:
                    break
                if not target_content or target_name not in allowed_targets:
                    continue

                for pattern in patterns:
                    try:
                        if cached_regex(pattern, re.IGNORECASE).search(target_content):
                            detected_types.add(attack_type)

                            # Customize evidence based on attack type
                            evidence = {"pattern": pattern, "found_in": target_name, "method": method}
                            if target_name == 'uri':
                                evidence["uri"] = uri[:300]
                            elif target_name == 'body':
                                evidence["body_snippet"] = body[:200]
                            elif target_name == 'headers':
                                evidence["headers"] = headers_raw[:200]

                            anomaly = create_anomaly_with_explanation(
                                attack_type, config, evidence, target_name, target_content, pattern
                            )
                            anomalies.append(anomaly)
                            break
                    except re.error:
                        continue

        # =====================================================================
        # BEHAVIOR-BASED HEURISTICS (Additional detection logic)
        # =====================================================================

        # Heuristic 1: Rapid HTTP requests (potential scanning/brute force)
        # Higher threshold, check for scan patterns, deduplication
        http_key = f"{src_ip}:{dst_ip}:{dst_port}"
        if not hasattr(self, '_http_request_tracker'):
            self._http_request_tracker = defaultdict(list)

        self._http_request_tracker[http_key].append(ts)
        # Keep only last 60 seconds
        self._http_request_tracker[http_key] = [
            t for t in self._http_request_tracker[http_key] if t > ts - 60
        ]

        request_count = len(self._http_request_tracker[http_key])

        # Increase threshold from 50 to 80 to reduce false positives
        # Web apps can legitimately make many requests (AJAX, polling, etc.)
        if request_count > 80 and "HTTP_RAPID_REQUESTS" not in detected_types:
            # Check for deduplication
            alert_key = f"HTTP_RAPID_{src_ip}_{dst_ip}"
            if not self.is_duplicate_alert(alert_key, ts):
                detected_types.add("HTTP_RAPID_REQUESTS")

                # Extract IOC for evaluation
                self.extract_ioc_for_attack("HTTP_SCAN", {
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': dst_port,
                    'request_count': request_count, 'timestamp': ts,
                    'uri_sample': uri[:100] if uri else ''
                })

                # Adjust confidence based on request pattern
                # Scanners often have very even timing, legitimate apps have bursts
                confidence = 0.75 if request_count > 150 else 0.60
                severity = "HIGH" if request_count > 150 else "MEDIUM"

                anomalies.append(SecurityAnomaly(
                    timestamp=ts, anomaly_type="HTTP_RAPID_REQUESTS",
                    severity=severity, src_ip=src_ip, dst_ip=dst_ip,
                    protocol="HTTP",
                    description=f"Rapid HTTP requests: {request_count} requests in 60s",
                    evidence={"request_count": request_count, "time_window": "60s", "threshold": 80},
                    mitre_techniques=["T1595", "T1110"], confidence=confidence,
                    recommendation="Check whether this is a scanner or brute force. Note: some legitimate web apps can generate many requests.",
                    behavior=f"Detected {request_count} HTTP requests from {src_ip} within 60 seconds.",
                    danger="This may be an automated scanner or a brute force attack. However, the context should be verified.",
                    attack_scenario="Tools such as dirbuster or gobuster scanning for files/directories.",
                    risk_assessment=f"{severity} - Determine whether this is an authorized scan",
                    ot_impact="HMI/SCADA web interfaces may be the target.",
                    remediation_steps="1. Rate limiting\n2. Block if not authorized\n3. Review WAF logs\n4. Check whether it is a legitimate application",
                ))

        # Heuristic 2: Suspicious HTTP method for OT
        if method in ['PUT', 'DELETE', 'CONNECT'] and "HTTP_DANGEROUS_METHOD" not in detected_types:
            detected_types.add("HTTP_DANGEROUS_METHOD")
            anomalies.append(SecurityAnomaly(
                timestamp=ts, anomaly_type="HTTP_DANGEROUS_METHOD",
                severity="HIGH", src_ip=src_ip, dst_ip=dst_ip,
                protocol="HTTP",
                description=f"Potentially dangerous HTTP method: {method}",
                evidence={"method": method, "uri": uri[:200]},
                mitre_techniques=["T1190"], confidence=0.75,
                recommendation="Check whether this method is actually required.",
                behavior=f"HTTP {method} request to {uri[:50]}",
                danger=f"The {method} method can be used to upload malicious files or delete data.",
                attack_scenario="The attacker may be attempting to upload a webshell or modify data.",
                risk_assessment="HIGH - This method is usually not required for OT web interfaces",
                ot_impact="Could upload malware or modify OT configuration.",
                remediation_steps=f"1. Disable {method} method\n2. Whitelist allowed methods\n3. Review server config",
            ))

        # Heuristic 3: Suspicious file extensions in URI
        suspicious_extensions = ['.bak', '.old', '.config', '.conf', '.sql', '.db', '.env', '.git']
        for ext in suspicious_extensions:
            if ext in uri.lower() and "HTTP_SENSITIVE_FILE_ACCESS" not in detected_types:
                detected_types.add("HTTP_SENSITIVE_FILE_ACCESS")
                anomalies.append(SecurityAnomaly(
                    timestamp=ts, anomaly_type="HTTP_SENSITIVE_FILE_ACCESS",
                    severity="MEDIUM", src_ip=src_ip, dst_ip=dst_ip,
                    protocol="HTTP",
                    description=f"Attempt to access sensitive file: {uri[:100]}",
                    evidence={"uri": uri[:300], "extension": ext},
                    mitre_techniques=["T1083", "T1005"], confidence=0.75,
                    recommendation="Check whether the file is exposed.",
                    behavior=f"Request to a file with extension {ext}",
                    danger="This may be an exposed backup, config, or source code file.",
                    attack_scenario="The attacker is searching for sensitive files to gather information.",
                    risk_assessment="MEDIUM - Information disclosure risk",
                    ot_impact="OT config files may contain credentials and network information.",
                    remediation_steps="1. Block access to sensitive files\n2. Remove unnecessary files\n3. Review web server config",
                ))
                break

        # Update risk score for critical detections
        critical_attacks = [a for a in anomalies if a.severity == "CRITICAL"]
        if critical_attacks:
            self.update_risk_score(src_ip, 0.4, f"HTTP_CRITICAL_ATTACK_{len(critical_attacks)}", ts)

        return anomalies

    def analyze_decoded_http_stream(self, src_ip: str, dst_ip: str, src_port: int,
                                     dst_port: int, seq: int, tcp_payload: bytes,
                                     ts: float, tcp_flags: int = 0) -> Tuple[List[SecurityAnomaly], Optional[DecodedPayload]]:
        """
        Analyze HTTP traffic with full TCP stream reassembly and multi-layer decoding.

        IMPROVED: Only analyzes when HTTP message is COMPLETE (headers + full body).
        This fixes issues with multi-packet HTTP where body is split across packets.

        This method:
        1. Adds TCP segments to the session tracker for reassembly
        2. Checks if HTTP message is complete (Content-Length satisfied or chunked complete)
        3. Only then extracts and decodes complete HTTP messages
        4. Analyzes decoded payloads for malicious content
        5. Returns anomalies with full decode explanation

        Args:
            src_ip, dst_ip: IP addresses
            src_port, dst_port: Ports
            seq: TCP sequence number
            tcp_payload: TCP payload bytes
            ts: Timestamp
            tcp_flags: TCP flags

        Returns:
            Tuple of (anomalies list, decoded payload if suspicious)
        """

        anomalies = []
        decoded_payload = None

        # Add segment to session tracker
        self.http_session_tracker.add_packet(
            src_ip, dst_ip, src_port, dst_port, seq, tcp_payload, ts, tcp_flags
        )

        # Clean up old sessions periodically
        if len(self.http_session_tracker.sessions) > 1000:
            self.http_session_tracker.cleanup_old_sessions(ts)

        # Get session ID
        session_id = self.http_session_tracker._make_session_id(src_ip, dst_ip, src_port, dst_port)

        # Only analyze when HTTP message is complete
        # This prevents analyzing partial bodies split across packets
        if not self.http_session_tracker.is_http_complete(session_id):
            # Not complete yet - wait for more packets
            return anomalies, None

        # Check if already analyzed (avoid duplicate processing)
        if session_id in self.http_session_tracker.analyzed_sessions:
            return anomalies, None

        # Mark as analyzed
        self.http_session_tracker.mark_analyzed(session_id)

        # Now get complete session data
        session_data = self.http_session_tracker.get_session_data(session_id)

        if not session_data or session_data.get('type') not in ['request', 'response']:
            return anomalies, None

        # Extract payload with full decode explanation
        payload_info = self.http_stream_decoder.extract_payload_with_explanation(session_data)

        # Check if we have decoded content worth analyzing
        final_payload = payload_info.get('final_payload', b'')
        if not final_payload or len(final_payload) < 10:
            return anomalies, None

        # Build decode steps for model
        decode_steps = []
        for step in payload_info.get('decode_steps', []):
            decode_steps.append(DecodeStep(
                layer=step.get('layer', 0),
                encoding=step.get('encoding', ''),
                input_preview=step.get('input_preview', '')[:100] if isinstance(step.get('input_preview'), str) else '',
                output_preview=step.get('output_preview', '')[:100] if isinstance(step.get('output_preview'), str) else '',
                input_size=step.get('input_size', 0),
                output_size=step.get('output_size', 0),
                success=step.get('success', False),
                error=step.get('error', ''),
            ))

        # Create DecodedPayload for forensics if suspicious
        if payload_info.get('detected_type') != 'UNKNOWN' or payload_info.get('total_layers', 0) > 0:
            decoded_payload = DecodedPayload(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_payload=payload_info.get('raw_payload', b'')[:4096],
                raw_size=payload_info.get('raw_size', 0),
                raw_preview=payload_info.get('raw_preview', '')[:200],
                final_payload=final_payload[:8192],
                final_size=payload_info.get('final_size', 0),
                final_preview=payload_info.get('final_preview', '')[:200],
                decode_steps=decode_steps,
                total_layers=payload_info.get('total_layers', 0),
                http_method=session_data.get('method', ''),
                http_uri=session_data.get('uri', ''),
                http_host=session_data.get('headers', {}).get('host', ''),
                content_type=payload_info.get('content_type', ''),
                content_encoding=session_data.get('content_encoding', ''),
                transfer_encoding='chunked' if session_data.get('is_chunked') else '',
                detected_type=payload_info.get('detected_type', ''),
                detection_patterns=payload_info.get('detection_patterns', []),
                risk_level=payload_info.get('risk_level', 'LOW'),
                sha256_hash=payload_info.get('sha256_hash', ''),
                behavior_summary=payload_info.get('behavior_summary', ''),
            )

            # Store for forensics
            if len(self.decoded_payloads) < 10000:
                self.decoded_payloads.append(decoded_payload)

        # Generate anomalies based on decoded content
        detected_type = payload_info.get('detected_type', '')
        risk_level = payload_info.get('risk_level', 'LOW')
        detection_patterns = payload_info.get('detection_patterns', [])
        decode_explanation = payload_info.get('decode_explanation', [])

        if detected_type in ['WEBSHELL', 'ELF_BINARY', 'PE_BINARY'] or risk_level in ['CRITICAL', 'HIGH']:
            # Get detailed explanation
            explanation = get_attack_explanation(detected_type)

            # Build evidence with decode chain
            evidence = {
                'detected_type': detected_type,
                'patterns_matched': detection_patterns,
                'decode_layers': len(decode_steps),
                'decode_chain': decode_explanation,
                'final_size': payload_info.get('final_size', 0),
                'sha256': payload_info.get('sha256_hash', ''),
                'method': session_data.get('method', ''),
                'uri': session_data.get('uri', '')[:200],
            }

            # Create anomaly with full explanation
            severity = "CRITICAL" if risk_level == "CRITICAL" else "HIGH"
            anomaly_type = f"HTTP_DECODED_{detected_type}"

            anomaly = SecurityAnomaly(
                timestamp=ts,
                anomaly_type=anomaly_type,
                severity=severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="HTTP",
                description=f"Malicious payload detected after {len(decode_steps)} decode layers: {detected_type}",
                evidence=evidence,
                mitre_techniques=["T1505.003", "T1027"] if 'WEBSHELL' in detected_type else ["T1027"],
                confidence=0.90 if len(decode_steps) > 0 else 0.85,
                recommendation=explanation.get('remediation', 'Investigate and isolate the system immediately.'),
                behavior=payload_info.get('behavior_summary', explanation.get('behavior', '')),
                danger=explanation.get('danger', ''),
                attack_scenario=explanation.get('scenario', ''),
                risk_assessment=explanation.get('risk_level', ''),
                ot_impact=explanation.get('ot_impact', ''),
                remediation_steps=explanation.get('remediation', ''),
                extracted_payload=SuspiciousPayload(
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="HTTP",
                    payload_type=detected_type,
                    payload_data=final_payload[:1024],
                    payload_preview=payload_info.get('final_preview', '')[:200],
                    detection_reason=f"Detected as {detected_type} after decoding {len(decode_steps)} layers",
                    sha256_hash=payload_info.get('sha256_hash', ''),
                ) if detected_type != 'UNKNOWN' else None,
            )

            anomalies.append(anomaly)
            self.update_risk_score(src_ip, 0.5, f"HTTP_DECODED_{detected_type}", ts)

        # Check for multi-layer obfuscation (suspicious even without detection)
        if len(decode_steps) >= 3:
            anomalies.append(SecurityAnomaly(
                timestamp=ts,
                anomaly_type="HTTP_MULTILAYER_ENCODING",
                severity="HIGH",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="HTTP",
                description=f"Multi-layer encoded payload: {len(decode_steps)} decode layers applied",
                evidence={
                    'decode_layers': len(decode_steps),
                    'decode_chain': decode_explanation,
                    'final_size': payload_info.get('final_size', 0),
                },
                mitre_techniques=["T1027", "T1140"],
                confidence=0.80,
                recommendation="Multi-layer encoding is typically only seen in malware. Investigate thoroughly.",
                behavior=f"Payload was decoded through {len(decode_steps)} layers: {', '.join(decode_explanation)}",
                danger="Multi-layer encoding is a detection-evasion technique used by advanced malware.",
                attack_scenario="The attacker uses multiple encoding layers to bypass AV/WAF/IDS.",
                risk_assessment="HIGH - Indicator of an APT or advanced malware",
                ot_impact="OT malware (Industroyer, Triton) often uses complex obfuscation.",
                remediation_steps="1. Collect a sample\n2. Contact the security vendor\n3. Full incident response",
            ))

        return anomalies, decoded_payload

    @staticmethod
    def _ml_features(evt: OTEvent) -> List[float]:
        """Feature vector for the Isolation Forest.

        Raw port numbers are deliberately NOT used: ephemeral client ports are
        random and made every new TCP connection look like an outlier.
        """
        server_ports = {502, 102, 20000, 44818, 2404, 4840, 1883, 8883, 47808}
        return [
            evt.threat_score, evt.payload_entropy, len(evt.raw_data), evt.data_count,
            1 if evt.operation_type == "WRITE" else 0,
            1 if evt.operation_type == "CONTROL" else 0,
            1 if evt.dst_port in server_ports else 0,   # request direction
            min(evt.time_since_last_packet, 3600.0), min(evt.payload_change_rate, 1e6),
        ]

    ML_MIN_TRAIN_EVENTS = 100
    ML_MAX_TRAIN_EVENTS = 50_000     # fit on a random sample: fast and sufficient for iForest
    ML_MAX_SCORED_EVENTS = 200_000   # score at most the most recent N events
    ML_MIN_GROUP_SIZE = 20           # only judge operations seen at least this often

    def train_ml_model(self, events: List[OTEvent]):
        """Train the Isolation Forest on (a sample of) OT events."""
        self._ml_trained = False
        if not HAS_SKLEARN or self.ml_model is None or len(events) < self.ML_MIN_TRAIN_EVENTS:
            return

        sample = events
        if len(events) > self.ML_MAX_TRAIN_EVENTS:
            idx = np.random.default_rng(42).choice(len(events), self.ML_MAX_TRAIN_EVENTS, replace=False)
            sample = [events[i] for i in idx]

        X = np.array([self._ml_features(evt) for evt in sample], dtype=float)
        X_scaled = self.scaler.fit_transform(X)
        self.ml_model.fit(X_scaled)
        # Only report clear outliers: well below the lowest 1% of training scores
        train_scores = self.ml_model.score_samples(X_scaled)
        self._ml_score_threshold = float(np.percentile(train_scores, 1)) - 0.05
        self._ml_group_stats = {}
        self._ml_trained = True
        logger.info(f"ML model trained on {len(sample)} events")

    def detect_ml_anomalies(self, events: List[OTEvent]) -> List[Tuple[OTEvent, SecurityAnomaly]]:
        """Score events in one vectorized batch and return statistical outliers.

        An event is reported only when it is an outlier both globally and
        *within its own operation group* (protocol + function code). Rare
        one-off operations (session setup, STARTDT ...) and frequent identical
        operations therefore never trigger; those cases are covered by the
        rule-based detectors. Results are informational (severity LOW).
        """
        if not getattr(self, '_ml_trained', False) or not events:
            return []
        events = events[-self.ML_MAX_SCORED_EVENTS:]
        try:
            X = self.scaler.transform(np.array([self._ml_features(e) for e in events], dtype=float))
            scores = self.ml_model.score_samples(X)
        except Exception as e:
            logger.debug(f"ML scoring error: {e}")
            return []

        groups: Dict[Tuple[str, int], List[int]] = defaultdict(list)
        for i, evt in enumerate(events):
            groups[(evt.protocol.name, evt.function_code)].append(i)

        results = []
        for key, idxs in groups.items():
            if len(idxs) < self.ML_MIN_GROUP_SIZE:
                continue
            g = scores[idxs]
            median = float(np.median(g))
            mad = float(np.median(np.abs(g - median)))
            cutoff = min(self._ml_score_threshold, median - max(0.05, 4.0 * mad))
            self._ml_group_stats[key] = (median, mad, cutoff)
            for i in idxs:
                # time_since_last_packet == 0 marks the first packet of a flow
                # (no timing history): its timing features are not comparable.
                if scores[i] < cutoff and events[i].time_since_last_packet > 0:
                    results.append((events[i], self._ml_anomaly(events[i], float(scores[i]), median)))
        return results

    def _ml_anomaly(self, event: OTEvent, score: float, group_median: float) -> SecurityAnomaly:
        desc = (f"Statistical outlier for {event.protocol.name} '{event.function_name}' "
                f"(ML score {score:.3f}, typical {group_median:.3f})")
        return SecurityAnomaly(
            timestamp=event.timestamp, anomaly_type="ML_ANOMALY", severity="LOW",
            src_ip=event.src_ip, dst_ip=event.dst_ip, protocol=event.protocol.name,
            description=desc, evidence={"ml_score": score, "group_median_score": group_median,
                      "function": event.function_name},
            mitre_techniques=list(event.mitre_techniques), confidence=0.5,
            recommendation="Informational: compare this event with other instances of the same operation."
        )

    def predict_anomaly(self, event: OTEvent) -> Optional[SecurityAnomaly]:
        """Score a single event (kept for API compatibility; prefer detect_ml_anomalies)."""
        if not getattr(self, '_ml_trained', False):
            return None
        stats = getattr(self, '_ml_group_stats', {}).get((event.protocol.name, event.function_code))
        if stats is None:
            return None
        try:
            X = self.scaler.transform(np.array([self._ml_features(event)], dtype=float))
            score = float(self.ml_model.score_samples(X)[0])
        except Exception as e:
            logger.debug(f"ML prediction error: {e}")
            return None
        median, _, cutoff = stats
        return self._ml_anomaly(event, score, median) if score < cutoff else None

    def get_ip_risk_profile(self, ip: str) -> Dict[str, Any]:
        """Get risk profile for an IP"""
        return {
            'ip': ip,
            'risk_score': self.ip_risk_scores.get(ip, 0),
            'touched_ot': self.ip_touched_ot.get(ip, False),
            'violation_count': len(self.ip_violations.get(ip, [])),
            'violations': self.ip_violations.get(ip, [])[-10:],
            'smb_targets': list(self.smb_connection_tracker.get(ip, set()))[:10],
            'threat_level': self._calculate_threat_level(ip)
        }

    def _calculate_threat_level(self, ip: str) -> str:
        """Calculate overall threat level for an IP"""
        score = self.ip_risk_scores.get(ip, 0)
        touched_ot = self.ip_touched_ot.get(ip, False)

        if score >= 0.7 and touched_ot:
            return "CRITICAL"
        elif score >= 0.5 or (score >= 0.3 and touched_ot):
            return "HIGH"
        elif score >= 0.2:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "NONE"
