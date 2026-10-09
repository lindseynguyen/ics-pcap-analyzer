"""
OT PCAP Analyzer - Data Models
==============================
All dataclasses for packets, events, assets, anomalies, and network behavior.
"""

from dataclasses import dataclass, field
from typing import List, Set, Dict, Any

from .constants import OTProtocol


@dataclass
class PacketRecord:
    """Raw packet record from PCAP file"""
    ts: float
    data: bytes
    linktype: int


@dataclass
class OTEvent:
    """Enhanced OT event with threat intelligence"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: OTProtocol
    function_code: int
    function_name: str
    operation_type: str
    risk_level: str
    unit_id: int = 0
    data_address: int = 0
    data_count: int = 0
    raw_data: bytes = field(default_factory=bytes)
    notes: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    payload_entropy: float = 0.0
    sequence_id: int = 0
    time_since_last_packet: float = 0.0
    payload_change_rate: float = 0.0
    # Structured, protocol-independent facts used by the detection rules
    # (see ot_pcap_analyzer/protocols/base.py for the common keys).
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OTAsset:
    """Enhanced asset tracking"""
    ip: str
    mac: str = ""
    vendor: str = ""
    protocols_seen: Set[str] = field(default_factory=set)
    ports_seen: Set[int] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    is_ot_device: bool = False
    device_type: str = "Unknown"
    firmware_version: str = ""
    communication_pairs: Set[str] = field(default_factory=set)
    baseline_behavior: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SuspiciousPayload:
    """Extracted suspicious payload for forensic analysis"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_type: str          # e.g., "WEBSHELL", "ENCODED", "BINARY"
    payload_data: bytes        # Raw payload (limited size)
    payload_preview: str       # Human-readable preview
    detection_reason: str      # Why this was flagged
    sha256_hash: str = ""      # Hash for IOC


@dataclass
class SecurityAnomaly:
    """Security anomaly detection result with detailed explanation"""
    timestamp: float
    anomaly_type: str
    severity: str
    src_ip: str
    dst_ip: str
    protocol: str
    description: str
    evidence: Dict[str, Any]
    mitre_techniques: List[str]
    confidence: float
    recommendation: str

    # Enhanced explanation fields (optional, for user understanding)
    behavior: str = ""                 # What was observed
    danger: str = ""                   # Why it's dangerous
    attack_scenario: str = ""          # Possible attack scenario
    risk_assessment: str = ""          # Overall risk assessment
    ot_impact: str = ""                # Impact on OT/ICS systems
    remediation_steps: str = ""        # Detailed remediation steps

    # Payload extraction (optional, for forensics)
    extracted_payload: SuspiciousPayload = None

    # Deep HTTP analysis result (dict, optional)
    threat_analysis: dict = None


@dataclass
class DecodeStep:
    """Single decode step in multi-layer decoding"""
    layer: int                      # Layer number (1 = outermost)
    encoding: str                   # Encoding type: "gzip", "base64", "hex", "url", etc.
    input_preview: str              # Preview of input (first 100 chars)
    output_preview: str             # Preview of output (first 100 chars)
    input_size: int                 # Input size in bytes
    output_size: int                # Output size in bytes
    success: bool                   # Whether decode was successful
    error: str = ""                 # Error message if failed


@dataclass
class DecodedPayload:
    """
    Decoded HTTP payload with full decode chain explanation.

    Used for forensic analysis of suspicious HTTP content that may be
    encoded/compressed in multiple layers (e.g., base64 -> gzip -> webshell).
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    # Original data
    raw_payload: bytes              # Original raw payload from PCAP
    raw_size: int                   # Original size
    raw_preview: str                # Human-readable preview of raw data

    # Decoded data
    final_payload: bytes            # Final decoded payload
    final_size: int                 # Final size after decoding
    final_preview: str              # Human-readable preview of final data

    # Decode chain
    decode_steps: List[DecodeStep] = field(default_factory=list)  # Step-by-step decode
    total_layers: int = 0           # Total decode layers applied

    # HTTP context
    http_method: str = ""           # GET, POST, etc.
    http_uri: str = ""              # Request URI
    http_host: str = ""             # Host header
    content_type: str = ""          # Content-Type header
    content_encoding: str = ""      # Content-Encoding header
    transfer_encoding: str = ""     # Transfer-Encoding header

    # Detection results
    detected_type: str = ""         # What was detected: "WEBSHELL", "SCRIPT", "BINARY", etc.
    detection_patterns: List[str] = field(default_factory=list)  # Patterns matched
    risk_level: str = "LOW"         # LOW, MEDIUM, HIGH, CRITICAL
    sha256_hash: str = ""           # Hash of final payload for IOC

    # Behavior explanation (for user)
    behavior_summary: str = ""      # What this payload appears to do


@dataclass
class HTTPStreamData:
    """
    Reassembled HTTP stream data from TCP segments.

    Represents a complete HTTP request or response reconstructed
    from multiple TCP packets.
    """
    stream_id: str                  # Unique stream identifier (src:port -> dst:port)
    direction: str                  # "REQUEST" or "RESPONSE"

    # Timing
    start_time: float               # First packet timestamp
    end_time: float                 # Last packet timestamp

    # Endpoints
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    # HTTP Headers
    http_version: str = ""
    method: str = ""                # For requests
    uri: str = ""                   # For requests
    status_code: int = 0            # For responses
    status_text: str = ""           # For responses
    headers: Dict[str, str] = field(default_factory=dict)

    # Body
    body_raw: bytes = field(default_factory=bytes)      # Raw body (may be chunked/encoded)
    body_decoded: bytes = field(default_factory=bytes)  # Decoded body
    body_complete: bool = False     # Whether body is complete

    # Transfer info
    content_length: int = 0
    is_chunked: bool = False
    content_encoding: str = ""      # gzip, deflate, br

    # Reassembly info
    total_segments: int = 0
    missing_segments: int = 0
    retransmissions: int = 0


@dataclass
class NetworkBehavior:
    """Network behavior tracking for IT/OT correlation"""
    ip: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    protocols_used: Set[str] = field(default_factory=set)
    ports_contacted: Set[int] = field(default_factory=set)
    destinations: Set[str] = field(default_factory=set)
    avg_packet_size: float = 0.0
    packet_rate: float = 0.0  # packets per second
    is_scanner: bool = False
    is_server: bool = False
    risk_score: float = 0.0


# =============================================================================
# ATTACK CHAIN & STORYLINE MODELS
# =============================================================================

@dataclass
class AttackPhase:
    """
    A single phase in an attack chain.

    Phases follow MITRE ATT&CK:
    - RECONNAISSANCE: Information gathering
    - INITIAL_ACCESS: Initial access
    - EXECUTION: Malicious code execution
    - PERSISTENCE: Maintaining access
    - PRIVILEGE_ESCALATION: Privilege escalation
    - LATERAL_MOVEMENT: Lateral movement
    - COLLECTION: Data collection
    - EXFILTRATION: Data exfiltration
    - IMPACT: Impact/sabotage
    """
    phase_name: str                      # "RECONNAISSANCE", "INITIAL_ACCESS", etc.
    phase_index: int                     # Order (0-8)
    timestamp: float                     # Phase start time
    end_time: float = 0.0                # Phase end time

    # Events belonging to this phase
    event_ids: List[int] = field(default_factory=list)
    event_count: int = 0

    # MITRE mapping
    mitre_tactics: List[str] = field(default_factory=list)   # TA0001, TA0002, etc.
    mitre_techniques: List[str] = field(default_factory=list)  # T1046, T1190, etc.

    # Description
    description: str = ""

    # Phase severity
    severity: str = "MEDIUM"             # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class AttackChain:
    """
    Attack chain correlated from multiple events.

    An attack chain consists of multiple phases linked by time
    and attack logic (e.g. Recon -> Initial Access -> Execution -> Lateral Movement).
    """
    chain_id: str                        # Unique ID (e.g. "CHAIN-20250128143522-001")
    start_time: float                    # Attack chain start time
    end_time: float                      # Last event time
    duration: float = 0.0                # Total duration (seconds)

    # Involved IPs
    source_ips: Set[str] = field(default_factory=set)    # Attacking source IPs
    target_ips: Set[str] = field(default_factory=set)    # Targeted IPs

    # Attack phases
    phases: List[AttackPhase] = field(default_factory=list)
    current_phase: str = ""              # Current phase
    phase_count: int = 0                 # Number of phases traversed

    # Overall assessment
    overall_severity: str = "MEDIUM"     # CRITICAL/HIGH/MEDIUM/LOW
    confidence: float = 0.0              # 0.0 - 1.0
    total_events: int = 0                # Total events in the chain

    # OT Impact
    ot_assets_at_risk: List[str] = field(default_factory=list)   # OT devices that may be affected
    ot_escalation_score: float = 0.0     # 0.0 - 1.0 (risk to OT)
    has_ot_impact: bool = False          # Whether OT is impacted

    # Aggregated MITRE mapping
    all_tactics: Set[str] = field(default_factory=set)
    all_techniques: Set[str] = field(default_factory=set)

    # Status
    is_active: bool = True               # Attack chain still ongoing
    is_complete: bool = False            # Finished (all phases detected)

    # Storyline reference (generated later)
    storyline_id: str = ""


@dataclass
class AttackStoryline:
    """
    Storyline output for the OT operator.

    Produces a narrative understandable by OT operators (not security experts).
    Includes: timeline, impact assessment, remediation checklist.
    """
    storyline_id: str                    # Unique ID
    chain_id: str                        # Reference to AttackChain

    # Narrative
    title: str = ""                      # Title
    narrative: str = ""                  # Detailed description

    # Timeline summary
    timeline_summary: str = ""           # Timeline summary
    key_events: List[Dict[str, Any]] = field(default_factory=list)  # [{time, event, significance}]

    # OT Impact assessment
    ot_impact_summary: str = ""
    affected_assets: List[str] = field(default_factory=list)
    production_risk: str = "NONE"        # "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"

    # Remediation checklist
    immediate_actions: List[str] = field(default_factory=list)     # Do immediately
    short_term_actions: List[str] = field(default_factory=list)    # Within 24h
    long_term_actions: List[str] = field(default_factory=list)     # Within 1 week

    # Emergency contacts
    emergency_contacts: List[str] = field(default_factory=list)

    # Metadata
    generated_at: float = 0.0
    confidence: float = 0.0

    # Attack classification
    attack_type: str = ""                # e.g. "WEBSHELL_TO_OT", "C2_BEACON_IN_OT"
    severity: str = "MEDIUM"

    # Enhanced Threat Assessment
    threat_level: str = ""               # Threat level assessment
    technical_description: str = ""      # Technical details of threat
    business_impact: str = ""            # Business impact analysis
    threat_indicators: List[str] = field(default_factory=list)  # IOCs
    attacker_objectives: List[str] = field(default_factory=list)  # Likely goals

    # User Guidance
    detection_guidance: str = ""         # How to detect this threat
    investigation_steps: str = ""        # Investigation checklist
    prevention_tips: str = ""            # Prevention recommendations


@dataclass
class CommunicationBaseline:
    """
    Baseline for a communication pair.

    Used to learn the normal behavior of the OT network,
    in order to detect anomalies and reduce false positives.
    """
    src_ip: str
    dst_ip: str
    protocol: str                        # "MODBUS", "S7COMM", "HTTP", etc.
    baseline_id: str = ""                # Unique ID (auto-generated if empty)

    # Port information
    src_port: int = 0
    dst_port: int = 0

    # Timing patterns
    avg_interval: float = 0.0            # Average time between packets (seconds)
    std_interval: float = 0.0            # Standard deviation
    min_interval: float = 0.0
    max_interval: float = 0.0

    # Volume patterns
    avg_packets_per_hour: float = 0.0
    avg_bytes_per_hour: float = 0.0
    max_packets_per_hour: float = 0.0
    max_bytes_per_hour: float = 0.0

    # Function patterns (for OT protocols)
    normal_function_codes: Set[int] = field(default_factory=set)
    normal_operations: Set[str] = field(default_factory=set)

    # Time patterns
    active_hours: Set[int] = field(default_factory=set)   # Usual active hours (0-23)
    active_days: Set[int] = field(default_factory=set)    # Days of week (0=Mon, 6=Sun)

    # Learning metadata
    samples_count: int = 0
    first_seen: float = 0.0
    last_updated: float = 0.0
    is_stable: bool = False              # Whether enough has been learned


@dataclass
class WhitelistRule:
    """
    Manual whitelist rule.

    Allows the operator to define legitimate communication patterns
    to reduce false positives.
    """
    rule_id: str
    name: str = ""
    description: str = ""

    # Matching patterns
    src_ip_pattern: str = ""             # "10.0.1.*" or exact IP
    dst_ip_pattern: str = ""
    protocol: str = ""                   # "MODBUS", "S7COMM", "*" for any
    src_port_pattern: str = ""           # "502", "*", "1000-2000"
    dst_port_pattern: str = ""

    # Function code filter (for OT)
    function_codes: List[int] = field(default_factory=list)  # Empty = all allowed

    # Time restrictions
    allowed_hours: List[int] = field(default_factory=list)   # Empty = always
    allowed_days: List[int] = field(default_factory=list)    # Empty = always

    # Metadata
    enabled: bool = True
    created_by: str = ""
    created_at: float = 0.0
    expires_at: float = 0.0              # 0 = never expires

    # Confidence adjustment
    confidence_reduction: float = 0.3    # Reduce anomaly confidence when the rule matches


@dataclass
class AnalyzerConfig:
    """Configuration for OT Analyzer"""
    max_events: int = 1000000
    max_ot_events: int = 500000
    detect_anomalies: bool = True
    track_assets: bool = True
    use_ml: bool = True
    enable_deep_inspection: bool = True
    use_scapy: bool = True
    scapy_session_analysis: bool = True

    # Attack Chain Correlation (enabled by default for better analysis)
    enable_correlation: bool = True          # Attack chain correlation
    correlation_time_window: float = 1800.0  # 30 minutes
    max_active_chains: int = 1000            # Max chains to track

    # Baseline Learning (default OFF)
    enable_baseline: bool = False            # Baseline learning
    baseline_learning_period: float = 86400.0  # 24 hours
    max_baselines: int = 10000               # Max communication pairs

    # Storyline Generation (enabled by default for better analysis)
    enable_storyline: bool = True            # Storyline generation
    max_storylines: int = 100                # Max storylines to keep

    # Behaviour profiling (new talkers / function codes, polling, value ranges)
    enable_behavior_profiling: bool = True
    behavior_learning_fraction: float = 0.3  # share of the capture used to learn "normal"

    # User-defined detection rules (YAML/JSON files or directories)
    rule_paths: List[str] = field(default_factory=list)
    load_default_rules: bool = True          # also load ~/.ot_pcap_analyzer/rules

    def __post_init__(self):
        """Validate configuration parameters"""
        # Validate positive integers
        if self.max_events <= 0:
            raise ValueError(f"max_events must be positive, got {self.max_events}")
        if self.max_ot_events <= 0:
            raise ValueError(f"max_ot_events must be positive, got {self.max_ot_events}")
        if self.max_active_chains <= 0:
            raise ValueError(f"max_active_chains must be positive, got {self.max_active_chains}")
        if self.max_baselines <= 0:
            raise ValueError(f"max_baselines must be positive, got {self.max_baselines}")
        if self.max_storylines <= 0:
            raise ValueError(f"max_storylines must be positive, got {self.max_storylines}")

        # Validate positive floats
        if self.correlation_time_window <= 0:
            raise ValueError(f"correlation_time_window must be positive, got {self.correlation_time_window}")
        if self.baseline_learning_period <= 0:
            raise ValueError(f"baseline_learning_period must be positive, got {self.baseline_learning_period}")
        if not 0 < self.behavior_learning_fraction < 1:
            raise ValueError(
                f"behavior_learning_fraction must be between 0 and 1, got {self.behavior_learning_fraction}")

