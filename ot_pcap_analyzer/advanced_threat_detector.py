"""
OT PCAP Analyzer - Advanced Threat Detector
==============================================
Enhanced threat detection with multi-stage scoring and kill chain analysis.

Features:
- Multi-stage attack scoring (combines signals from multiple phases)
- Kill chain progression tracking
- OT-specific threat scoring
- Integration with OT malware signatures
- Enhanced baseline learning
- Attack probability prediction

Usage:
    from advanced_threat_detector import AdvancedThreatDetector

    detector = AdvancedThreatDetector()
    detector.process_event(ot_event)
    score = detector.get_attack_score(src_ip)
    prediction = detector.predict_next_phase(src_ip)

NOTE: This module EXTENDS existing functionality without modifying it.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum, auto
from collections import deque, defaultdict
import math
from datetime import datetime

# Import existing modules
from .models import SecurityAnomaly, OTEvent, OTAsset
from .ot_malware_signatures import OTMalwareDetector, MalwareDetectionResult


# =============================================================================
# KILL CHAIN PHASES (MITRE ATT&CK for ICS)
# =============================================================================

class KillChainPhase(Enum):
    """Kill chain phases based on MITRE ATT&CK for ICS"""
    RECONNAISSANCE = 0       # TA0043 - Information gathering
    RESOURCE_DEVELOPMENT = 1 # TA0042 - Building attack infrastructure
    INITIAL_ACCESS = 2       # TA0001 - Getting into the network
    EXECUTION = 3            # TA0002 - Running malicious code
    PERSISTENCE = 4          # TA0003 - Maintaining access
    PRIVILEGE_ESCALATION = 5 # TA0004 - Getting higher privileges
    DEFENSE_EVASION = 6      # TA0005 - Avoiding detection
    CREDENTIAL_ACCESS = 7    # TA0006 - Stealing credentials
    DISCOVERY = 8            # TA0007 - Understanding the environment
    LATERAL_MOVEMENT = 9     # TA0008 - Moving through network
    COLLECTION = 10          # TA0009 - Gathering target data
    COMMAND_AND_CONTROL = 11 # TA0011 - Communicating with compromised systems
    EXFILTRATION = 12        # TA0010 - Stealing data
    IMPACT = 13              # TA0040 - Disrupting operations (OT-specific)


# Mapping from anomaly types to kill chain phases
ANOMALY_TO_PHASE: Dict[str, KillChainPhase] = {
    # Reconnaissance
    "IT_PORT_SCAN_FAST": KillChainPhase.RECONNAISSANCE,
    "IT_PORT_SCAN_SLOW": KillChainPhase.RECONNAISSANCE,
    "HTTP_RAPID_REQUESTS": KillChainPhase.RECONNAISSANCE,
    "HTTP_SUSPICIOUS_USER_AGENT": KillChainPhase.RECONNAISSANCE,
    "HTTP_DIRECTORY_BRUTEFORCE": KillChainPhase.RECONNAISSANCE,
    "HTTP_HTTP_SCANNER_DETECTION": KillChainPhase.RECONNAISSANCE,
    "OT_DEVICE_DISCOVERY": KillChainPhase.RECONNAISSANCE,

    # Initial Access
    "IT_BRUTE_FORCE": KillChainPhase.INITIAL_ACCESS,
    "IT_ADMIN_PORT_ATTACK_SSH": KillChainPhase.INITIAL_ACCESS,
    "IT_ADMIN_PORT_ATTACK_RDP": KillChainPhase.INITIAL_ACCESS,
    "IT_ADMIN_PORT_ATTACK_TELNET": KillChainPhase.INITIAL_ACCESS,
    "HTTP_SQL_INJECTION": KillChainPhase.INITIAL_ACCESS,
    "HTTP_PATH_TRAVERSAL": KillChainPhase.INITIAL_ACCESS,

    # Execution
    "HTTP_WEBSHELL": KillChainPhase.EXECUTION,
    "HTTP_WEBSHELL_CMD": KillChainPhase.EXECUTION,
    "HTTP_DECODED_WEBSHELL": KillChainPhase.EXECUTION,
    "HTTP_COMMAND_INJECTION": KillChainPhase.EXECUTION,

    # Persistence
    "HTTP_WEBSHELL_UPLOAD": KillChainPhase.PERSISTENCE,

    # Lateral Movement
    "IT_LATERAL_MOVEMENT_SMB": KillChainPhase.LATERAL_MOVEMENT,

    # Command and Control
    "C2_BEACON_REGULAR": KillChainPhase.COMMAND_AND_CONTROL,
    "C2_BEACON_JITTER": KillChainPhase.COMMAND_AND_CONTROL,
    "DNS_TUNNEL_ENTROPY": KillChainPhase.COMMAND_AND_CONTROL,
    "DNS_TUNNEL_SUBDOMAIN_DIVERSITY": KillChainPhase.COMMAND_AND_CONTROL,

    # Exfiltration
    "DATA_EXFIL_LARGE_TRANSFER": KillChainPhase.EXFILTRATION,
    "DATA_EXFIL_CUMULATIVE": KillChainPhase.EXFILTRATION,
    "DNS_TUNNEL_TXT_ABUSE": KillChainPhase.EXFILTRATION,

    # Post-Exploitation (detected from TCP stream content)
    "POST_EXPLOIT_SHELL_SESSION": KillChainPhase.EXECUTION,
    "POST_EXPLOIT_CREDENTIAL_EXPOSURE": KillChainPhase.CREDENTIAL_ACCESS,
    "POST_EXPLOIT_SENSITIVE_FILE_READ": KillChainPhase.COLLECTION,
    "POST_EXPLOIT_PRIVILEGE_ESCALATION": KillChainPhase.PRIVILEGE_ESCALATION,
    "POST_EXPLOIT_LATERAL_MOVEMENT_CREDS": KillChainPhase.LATERAL_MOVEMENT,
    "POST_EXPLOIT_INTERNAL_RECON": KillChainPhase.DISCOVERY,
    "POST_EXPLOIT_SHELL_DATA_EXFIL": KillChainPhase.EXFILTRATION,

    # Impact (OT-specific)
    "RAPID_WRITE_SEQUENCE": KillChainPhase.IMPACT,
    "ABNORMAL_WRITE_RATE": KillChainPhase.IMPACT,
    "OT_PLC_STOP": KillChainPhase.IMPACT,
    "OT_FIRMWARE_UPDATE": KillChainPhase.IMPACT,
    "OT_PROGRAM_DOWNLOAD": KillChainPhase.IMPACT,
    "ARP_SPOOFING_DETECTED": KillChainPhase.IMPACT,
}


# =============================================================================
# THREAT SCORE WEIGHTS
# =============================================================================

@dataclass
class ThreatScoreWeights:
    """Configurable weights for threat scoring"""
    # Base weights by severity
    severity_weights: Dict[str, float] = field(default_factory=lambda: {
        "CRITICAL": 1.0,
        "HIGH": 0.7,
        "MEDIUM": 0.4,
        "LOW": 0.2,
    })

    # Kill chain progression multiplier (later phases = more dangerous)
    phase_multipliers: Dict[KillChainPhase, float] = field(default_factory=lambda: {
        KillChainPhase.RECONNAISSANCE: 0.3,
        KillChainPhase.RESOURCE_DEVELOPMENT: 0.4,
        KillChainPhase.INITIAL_ACCESS: 0.6,
        KillChainPhase.EXECUTION: 0.8,
        KillChainPhase.PERSISTENCE: 0.85,
        KillChainPhase.PRIVILEGE_ESCALATION: 0.9,
        KillChainPhase.DEFENSE_EVASION: 0.7,
        KillChainPhase.CREDENTIAL_ACCESS: 0.75,
        KillChainPhase.DISCOVERY: 0.5,
        KillChainPhase.LATERAL_MOVEMENT: 0.85,
        KillChainPhase.COLLECTION: 0.7,
        KillChainPhase.COMMAND_AND_CONTROL: 0.9,
        KillChainPhase.EXFILTRATION: 0.95,
        KillChainPhase.IMPACT: 1.0,
    })

    # OT impact bonus (additional weight for OT-related threats)
    ot_impact_bonus: float = 0.3

    # Malware detection bonus
    malware_detection_bonus: float = 0.5

    # Time decay factor (reduce score for old events)
    time_decay_hours: float = 24.0


# =============================================================================
# ATTACK SCORE DATA STRUCTURES
# =============================================================================

@dataclass
class PhaseEvidence:
    """Evidence for a specific kill chain phase"""
    phase: KillChainPhase
    anomalies: List[SecurityAnomaly] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    count: int = 0
    max_severity: str = "LOW"
    confidence: float = 0.0


@dataclass
class AttackScore:
    """Comprehensive attack score for an IP"""
    ip: str
    total_score: float = 0.0
    normalized_score: float = 0.0  # 0.0 - 1.0

    # Phase breakdown
    phases_detected: Dict[KillChainPhase, PhaseEvidence] = field(default_factory=dict)
    current_phase: Optional[KillChainPhase] = None
    phase_progression: List[KillChainPhase] = field(default_factory=list)

    # OT specific
    ot_assets_targeted: Set[str] = field(default_factory=set)
    ot_impact_score: float = 0.0
    has_ot_impact: bool = False

    # Malware detection
    malware_detections: List[MalwareDetectionResult] = field(default_factory=list)
    malware_score: float = 0.0

    # Timing
    first_activity: float = 0.0
    last_activity: float = 0.0
    duration: float = 0.0

    # Assessment
    threat_level: str = "LOW"
    risk_assessment: str = ""

    # Prediction
    predicted_next_phase: Optional[KillChainPhase] = None
    next_phase_probability: float = 0.0


# =============================================================================
# ADVANCED THREAT DETECTOR
# =============================================================================

class AdvancedThreatDetector:
    """
    Advanced threat detector with multi-stage scoring and kill chain analysis.

    Features:
    - Tracks attack progression through kill chain phases
    - Calculates comprehensive threat scores
    - Predicts next attack phase
    - Integrates with OT malware detection
    - Provides actionable recommendations

    Usage:
        detector = AdvancedThreatDetector()

        # Process events
        for anomaly in anomalies:
            detector.add_anomaly(anomaly)

        for event in ot_events:
            detector.process_ot_event(event)

        # Get scores
        score = detector.get_attack_score("10.0.0.1")
        all_scores = detector.get_all_scores()

        # Get predictions
        prediction = detector.predict_next_phase("10.0.0.1")
    """

    def __init__(self, weights: ThreatScoreWeights = None, enable_malware: bool = True):
        """
        Initialize advanced threat detector.

        Args:
            weights: Custom threat score weights
            enable_malware: Enable OT malware signature detection
        """
        self.weights = weights or ThreatScoreWeights()
        self.enable_malware = enable_malware

        # Tracking per IP
        self.ip_scores: Dict[str, AttackScore] = {}
        self.ip_anomalies: Dict[str, List[SecurityAnomaly]] = defaultdict(list)
        self.ip_ot_events: Dict[str, deque] = defaultdict(deque)

        # OT malware detector
        self.malware_detector = OTMalwareDetector() if enable_malware else None

        # Statistics
        self.total_anomalies_processed = 0
        self.total_events_processed = 0

        # Time tracking
        self.current_time: float = 0.0

    def add_anomaly(self, anomaly: SecurityAnomaly) -> Optional[AttackScore]:
        """
        Add anomaly and update attack score.

        Args:
            anomaly: SecurityAnomaly to process

        Returns:
            Updated AttackScore for the source IP
        """
        src_ip = anomaly.src_ip
        self.total_anomalies_processed += 1
        self.current_time = max(self.current_time, anomaly.timestamp)

        # Track anomaly
        self.ip_anomalies[src_ip].append(anomaly)

        # Keep only recent anomalies (24 hours)
        cutoff = self.current_time - (self.weights.time_decay_hours * 3600)
        self.ip_anomalies[src_ip] = [
            a for a in self.ip_anomalies[src_ip]
            if a.timestamp > cutoff
        ]

        # Determine kill chain phase
        phase = self._get_phase_for_anomaly(anomaly)

        # Update or create score
        if src_ip not in self.ip_scores:
            self.ip_scores[src_ip] = AttackScore(
                ip=src_ip,
                first_activity=anomaly.timestamp,
            )

        score = self.ip_scores[src_ip]
        score.last_activity = anomaly.timestamp
        score.duration = score.last_activity - score.first_activity

        # Update phase evidence
        if phase:
            if phase not in score.phases_detected:
                score.phases_detected[phase] = PhaseEvidence(
                    phase=phase,
                    first_seen=anomaly.timestamp,
                )

            evidence = score.phases_detected[phase]
            evidence.anomalies.append(anomaly)
            evidence.last_seen = anomaly.timestamp
            evidence.count += 1
            evidence.confidence = max(evidence.confidence, anomaly.confidence)

            # Update max severity
            severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            if severity_order.get(anomaly.severity, 0) > severity_order.get(evidence.max_severity, 0):
                evidence.max_severity = anomaly.severity

            # Track phase progression
            if phase not in score.phase_progression:
                score.phase_progression.append(phase)

            score.current_phase = phase

        # Check OT impact
        if "OT" in anomaly.anomaly_type or "MODBUS" in anomaly.protocol or "S7" in anomaly.protocol:
            score.has_ot_impact = True
            if anomaly.dst_ip:
                score.ot_assets_targeted.add(anomaly.dst_ip)

        # Recalculate total score
        self._calculate_score(score)

        return score

    def process_ot_event(self, event: OTEvent) -> Optional[MalwareDetectionResult]:
        """
        Process OT event for malware detection.

        Args:
            event: OTEvent to process

        Returns:
            MalwareDetectionResult if malware detected
        """
        self.total_events_processed += 1
        self.current_time = max(self.current_time, event.timestamp)

        src_ip = event.src_ip
        recent = self.ip_ot_events[src_ip]
        recent.append(event)

        # Keep only recent events (O(1) amortized eviction)
        cutoff = self.current_time - (self.weights.time_decay_hours * 3600)
        while recent and recent[0].timestamp <= cutoff:
            recent.popleft()

        # Malware detection
        malware_result = None
        if self.malware_detector:
            malware_result = self.malware_detector.analyze_event(event)

            if malware_result and malware_result.detected:
                # Update score with malware detection
                if src_ip not in self.ip_scores:
                    self.ip_scores[src_ip] = AttackScore(
                        ip=src_ip,
                        first_activity=event.timestamp,
                    )

                score = self.ip_scores[src_ip]
                score.malware_detections.append(malware_result)
                score.has_ot_impact = True
                score.ot_assets_targeted.add(event.dst_ip)

                # Recalculate
                self._calculate_score(score)

        return malware_result

    def analyze_behavioral_patterns(self, src_ip: str) -> List[MalwareDetectionResult]:
        """
        Analyze behavioral patterns for a specific IP.

        Args:
            src_ip: Source IP to analyze

        Returns:
            List of malware detection results
        """
        if not self.malware_detector or src_ip not in self.ip_ot_events:
            return []

        events = list(self.ip_ot_events[src_ip])
        return self.malware_detector.analyze_behavioral_pattern(events, src_ip)

    def _get_phase_for_anomaly(self, anomaly: SecurityAnomaly) -> Optional[KillChainPhase]:
        """Map anomaly to kill chain phase."""
        anomaly_type = anomaly.anomaly_type

        # Direct mapping
        if anomaly_type in ANOMALY_TO_PHASE:
            return ANOMALY_TO_PHASE[anomaly_type]

        # Pattern matching
        for pattern, phase in ANOMALY_TO_PHASE.items():
            if pattern in anomaly_type:
                return phase

        # Default mappings by keywords
        type_lower = anomaly_type.lower()
        if "scan" in type_lower or "discovery" in type_lower or "enum" in type_lower:
            return KillChainPhase.RECONNAISSANCE
        elif "brute" in type_lower or "access" in type_lower:
            return KillChainPhase.INITIAL_ACCESS
        elif "webshell" in type_lower or "exec" in type_lower or "command" in type_lower:
            return KillChainPhase.EXECUTION
        elif "lateral" in type_lower or "smb" in type_lower:
            return KillChainPhase.LATERAL_MOVEMENT
        elif "c2" in type_lower or "beacon" in type_lower:
            return KillChainPhase.COMMAND_AND_CONTROL
        elif "exfil" in type_lower or "tunnel" in type_lower:
            return KillChainPhase.EXFILTRATION
        elif "write" in type_lower or "stop" in type_lower or "firmware" in type_lower:
            return KillChainPhase.IMPACT

        return None

    def _calculate_score(self, score: AttackScore):
        """Calculate comprehensive attack score."""
        total = 0.0

        # Phase-based scoring
        for phase, evidence in score.phases_detected.items():
            phase_score = 0.0

            # Base score from severity
            severity_weight = self.weights.severity_weights.get(evidence.max_severity, 0.2)
            phase_score += severity_weight * evidence.count

            # Phase multiplier
            phase_mult = self.weights.phase_multipliers.get(phase, 0.5)
            phase_score *= phase_mult

            # Confidence factor
            phase_score *= evidence.confidence

            total += phase_score

        # Kill chain progression bonus
        # More phases = more sophisticated attack
        if len(score.phase_progression) >= 3:
            total *= 1.2
        if len(score.phase_progression) >= 5:
            total *= 1.3

        # OT impact bonus
        if score.has_ot_impact:
            ot_bonus = total * self.weights.ot_impact_bonus
            score.ot_impact_score = ot_bonus
            total += ot_bonus

        # Malware detection bonus
        if score.malware_detections:
            malware_bonus = 0.0
            for detection in score.malware_detections:
                if detection.severity == "CRITICAL":
                    malware_bonus += 1.0
                elif detection.severity == "HIGH":
                    malware_bonus += 0.7
            malware_bonus *= self.weights.malware_detection_bonus
            score.malware_score = malware_bonus
            total += malware_bonus

        # Time decay
        if self.current_time > 0 and score.last_activity > 0:
            age_hours = (self.current_time - score.last_activity) / 3600
            decay_factor = math.exp(-age_hours / self.weights.time_decay_hours)
            total *= decay_factor

        score.total_score = total

        # Normalize to 0-1 range (using sigmoid-like function)
        score.normalized_score = min(1.0, total / (total + 5.0))

        # Determine threat level
        if score.normalized_score >= 0.8 or score.malware_detections:
            score.threat_level = "CRITICAL"
        elif score.normalized_score >= 0.6:
            score.threat_level = "HIGH"
        elif score.normalized_score >= 0.3:
            score.threat_level = "MEDIUM"
        else:
            score.threat_level = "LOW"

        # Generate assessment
        self._generate_assessment(score)

        # Predict next phase
        self._predict_next_phase(score)

    def _generate_assessment(self, score: AttackScore):
        """Generate human-readable risk assessment."""
        phases_str = ", ".join([p.name for p in score.phase_progression])

        if score.threat_level == "CRITICAL":
            score.risk_assessment = (
                f"CRITICAL THREAT: Active multi-stage attack detected from {score.ip}. "
                f"Attack has progressed through {len(score.phase_progression)} phases: {phases_str}. "
                f"{'OT systems are targeted. ' if score.has_ot_impact else ''}"
                f"{'Known OT malware signatures detected. ' if score.malware_detections else ''}"
                f"Immediate isolation recommended."
            )
        elif score.threat_level == "HIGH":
            score.risk_assessment = (
                f"HIGH THREAT: Significant attack activity from {score.ip}. "
                f"Detected phases: {phases_str}. "
                f"{'OT impact possible. ' if score.has_ot_impact else ''}"
                f"Investigation and containment recommended."
            )
        elif score.threat_level == "MEDIUM":
            score.risk_assessment = (
                f"MEDIUM THREAT: Suspicious activity from {score.ip}. "
                f"Detected phases: {phases_str}. "
                f"Monitoring recommended."
            )
        else:
            score.risk_assessment = (
                f"LOW THREAT: Minor suspicious activity from {score.ip}. "
                f"Continue monitoring."
            )

    def _predict_next_phase(self, score: AttackScore):
        """Predict the likely next attack phase."""
        if not score.phase_progression:
            score.predicted_next_phase = KillChainPhase.RECONNAISSANCE
            score.next_phase_probability = 0.5
            return

        current = score.current_phase

        # Common attack progressions
        progression_map = {
            KillChainPhase.RECONNAISSANCE: (KillChainPhase.INITIAL_ACCESS, 0.8),
            KillChainPhase.INITIAL_ACCESS: (KillChainPhase.EXECUTION, 0.7),
            KillChainPhase.EXECUTION: (KillChainPhase.PERSISTENCE, 0.6),
            KillChainPhase.PERSISTENCE: (KillChainPhase.LATERAL_MOVEMENT, 0.7),
            KillChainPhase.PRIVILEGE_ESCALATION: (KillChainPhase.LATERAL_MOVEMENT, 0.8),
            KillChainPhase.LATERAL_MOVEMENT: (KillChainPhase.COLLECTION, 0.6),
            KillChainPhase.COLLECTION: (KillChainPhase.EXFILTRATION, 0.7),
            KillChainPhase.COMMAND_AND_CONTROL: (KillChainPhase.IMPACT, 0.6),
            KillChainPhase.DISCOVERY: (KillChainPhase.LATERAL_MOVEMENT, 0.7),
        }

        # OT-specific: if OT is targeted, likely heading for IMPACT
        if score.has_ot_impact and current != KillChainPhase.IMPACT:
            score.predicted_next_phase = KillChainPhase.IMPACT
            score.next_phase_probability = 0.8
            return

        if current in progression_map:
            score.predicted_next_phase, score.next_phase_probability = progression_map[current]
        else:
            # Default: predict IMPACT for unknown/late phases
            score.predicted_next_phase = KillChainPhase.IMPACT
            score.next_phase_probability = 0.5

    def get_attack_score(self, ip: str) -> Optional[AttackScore]:
        """Get attack score for a specific IP."""
        return self.ip_scores.get(ip)

    def get_all_scores(self, min_threat_level: str = None) -> List[AttackScore]:
        """
        Get all attack scores.

        Args:
            min_threat_level: Minimum threat level to include ("LOW", "MEDIUM", "HIGH", "CRITICAL")

        Returns:
            List of AttackScore objects sorted by total_score descending
        """
        scores = list(self.ip_scores.values())

        if min_threat_level:
            level_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            min_level = level_order.get(min_threat_level, 0)
            scores = [s for s in scores if level_order.get(s.threat_level, 0) >= min_level]

        return sorted(scores, key=lambda s: s.total_score, reverse=True)

    def get_critical_ips(self) -> List[str]:
        """Get list of IPs with CRITICAL threat level."""
        return [ip for ip, score in self.ip_scores.items() if score.threat_level == "CRITICAL"]

    def get_ot_targeting_ips(self) -> List[str]:
        """Get list of IPs targeting OT systems."""
        return [ip for ip, score in self.ip_scores.items() if score.has_ot_impact]

    def get_summary(self) -> Dict[str, Any]:
        """Get detector summary statistics."""
        scores = list(self.ip_scores.values())

        return {
            "total_ips_tracked": len(self.ip_scores),
            "total_anomalies_processed": self.total_anomalies_processed,
            "total_events_processed": self.total_events_processed,
            "threat_level_distribution": {
                "CRITICAL": sum(1 for s in scores if s.threat_level == "CRITICAL"),
                "HIGH": sum(1 for s in scores if s.threat_level == "HIGH"),
                "MEDIUM": sum(1 for s in scores if s.threat_level == "MEDIUM"),
                "LOW": sum(1 for s in scores if s.threat_level == "LOW"),
            },
            "ot_targeting_ips": len([s for s in scores if s.has_ot_impact]),
            "malware_detections": sum(len(s.malware_detections) for s in scores),
            "top_threats": [
                {
                    "ip": s.ip,
                    "score": round(s.total_score, 2),
                    "threat_level": s.threat_level,
                    "phases": len(s.phase_progression),
                    "ot_impact": s.has_ot_impact,
                }
                for s in sorted(scores, key=lambda x: x.total_score, reverse=True)[:10]
            ],
        }

    def reset(self):
        """Reset all tracking data."""
        self.ip_scores.clear()
        self.ip_anomalies.clear()
        self.ip_ot_events.clear()
        self.total_anomalies_processed = 0
        self.total_events_processed = 0
        self.current_time = 0.0

        if self.malware_detector:
            self.malware_detector.reset()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_threat_report(score: AttackScore) -> Dict[str, Any]:
    """
    Create detailed threat report for an AttackScore.

    Args:
        score: AttackScore to report on

    Returns:
        Dictionary containing full threat report
    """
    return {
        "ip": score.ip,
        "threat_level": score.threat_level,
        "total_score": round(score.total_score, 2),
        "normalized_score": round(score.normalized_score, 3),

        "timeline": {
            "first_activity": datetime.fromtimestamp(score.first_activity).isoformat() if score.first_activity else None,
            "last_activity": datetime.fromtimestamp(score.last_activity).isoformat() if score.last_activity else None,
            "duration_seconds": round(score.duration, 1),
        },

        "kill_chain_analysis": {
            "phases_detected": [p.name for p in score.phase_progression],
            "current_phase": score.current_phase.name if score.current_phase else None,
            "phase_count": len(score.phase_progression),
            "predicted_next_phase": score.predicted_next_phase.name if score.predicted_next_phase else None,
            "next_phase_probability": round(score.next_phase_probability, 2),
        },

        "ot_impact": {
            "has_ot_impact": score.has_ot_impact,
            "ot_impact_score": round(score.ot_impact_score, 2),
            "ot_assets_targeted": list(score.ot_assets_targeted),
        },

        "malware_analysis": {
            "malware_detected": len(score.malware_detections) > 0,
            "malware_score": round(score.malware_score, 2),
            "detections": [
                {
                    "malware_type": d.malware_type.value if d.malware_type else None,
                    "name": d.name,
                    "confidence": round(d.confidence, 2),
                }
                for d in score.malware_detections
            ],
        },

        "assessment": score.risk_assessment,
        "recommendations": _get_recommendations(score),
    }


def _get_recommendations(score: AttackScore) -> List[str]:
    """Generate English recommendations based on threat score."""
    recs = []

    if score.threat_level == "CRITICAL":
        recs.append("IMMEDIATE: Isolate the source IP from the network")
        recs.append("IMMEDIATE: Alert SOC and incident response team")
        if score.has_ot_impact:
            recs.append("IMMEDIATE: Isolate affected OT network segment")
            recs.append("IMMEDIATE: Verify OT device integrity and configurations")
        if score.malware_detections:
            recs.append("IMMEDIATE: Collect forensic evidence before remediation")
            recs.append("Contact ICS-CERT or relevant authority")

    elif score.threat_level == "HIGH":
        recs.append("Investigate source IP activity in detail")
        recs.append("Consider blocking at firewall/IPS")
        if score.has_ot_impact:
            recs.append("Increase monitoring on OT network segment")
            recs.append("Verify OT device access controls")

    elif score.threat_level == "MEDIUM":
        recs.append("Continue monitoring source IP")
        recs.append("Review access logs for the source IP")
        recs.append("Consider adding to watchlist")

    else:
        recs.append("Log and monitor")

    return recs
