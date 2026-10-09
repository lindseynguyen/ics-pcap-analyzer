"""
OT PCAP Analyzer - IOC (Indicators of Compromise) Models
=========================================================
Data models for IOC extraction and export.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class IOCRecord:
    """
    Unified IOC record for display and export.

    Represents a single Indicator of Compromise (IOC) extracted from PCAP analysis.
    Supports multiple IOC types: IP addresses, file hashes, domains, URLs, and MITRE techniques.
    """

    # Core IOC data
    ioc_type: str  # "IP", "HASH", "DOMAIN", "URL", "MITRE_TECHNIQUE"
    value: str  # The actual IOC value (IP address, hash, domain, etc.)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW

    # Temporal information
    first_seen: float  # Unix timestamp of first detection
    last_seen: float  # Unix timestamp of last detection
    occurrences: int  # Number of times this IOC was detected

    # Context and relationships
    context: str  # Attack chain ID, anomaly type, or source
    associated_ips: List[str] = field(default_factory=list)  # Related IP addresses

    # Descriptions
    description: str = ""  # English explanation of what this IOC indicates

    # Type-specific metadata
    risk_score: float = 0.0  # For IPs: risk score from analyzer (0.0-1.0)
    techniques: List[str] = field(default_factory=list)  # For MITRE: associated technique IDs

    # Additional metadata
    protocol: str = ""  # Network protocol (TCP, UDP, HTTP, etc.)
    port: int = 0  # Port number (for network IOCs)
    payload_preview: str = ""  # Preview of associated payload (for hashes)

    def to_dict(self) -> dict:
        """Convert IOCRecord to dictionary for JSON export."""
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "severity": self.severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "context": self.context,
            "associated_ips": self.associated_ips,
            "description": self.description,
            "risk_score": self.risk_score,
            "techniques": self.techniques,
            "protocol": self.protocol,
            "port": self.port,
            "payload_preview": self.payload_preview,
        }

    def to_csv_row(self) -> List[str]:
        """Convert IOCRecord to CSV row (list of strings)."""
        return [
            self.ioc_type,
            self.value,
            self.severity,
            f"{self.risk_score:.2f}",
            f"{self.first_seen:.2f}",
            f"{self.last_seen:.2f}",
            str(self.occurrences),
            self.context,
            ";".join(self.associated_ips) if self.associated_ips else "",
            ";".join(self.techniques) if self.techniques else "",
            self.protocol,
            str(self.port) if self.port else "",
            self.description,
        ]

    @staticmethod
    def csv_header() -> List[str]:
        """Return CSV header row."""
        return [
            "Type",
            "Value",
            "Severity",
            "Risk_Score",
            "First_Seen",
            "Last_Seen",
            "Occurrences",
            "Context",
            "Associated_IPs",
            "MITRE_Techniques",
            "Protocol",
            "Port",
            "Description",
        ]
