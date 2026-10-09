"""
OT PCAP Analyzer
================
Advanced OT/ICS network traffic analyzer with threat detection.

Usage:
    python -m ot_pcap_analyzer              # Launch GUI
    python -m ot_pcap_analyzer --gui        # Launch GUI
    python -m ot_pcap_analyzer --cli file.pcap  # CLI analysis

Features:
    - OT protocol decoding: Modbus TCP/UDP, S7comm, DNP3, EtherNet/IP (CIP),
      IEC 60870-5-104, OPC UA, MQTT, BACnet/IP
    - Rule-based detection of OT and IT attacks, optional ML outlier scoring
    - Attack-chain correlation and storylines with MITRE ATT&CK for ICS mapping
    - Excel / JSON / CSV reports, SOC-style PyQt5 GUI

Requirements:
    pip install -r requirements.txt
"""

from .version import VERSION

__version__ = VERSION
__all__ = [
    'VERSION',
    'OTProtocol',
    'OTEvent',
    'OTAsset',
    'SecurityAnomaly',
    'AnalyzerConfig',
    'OTAnalyzer',
    # New: Attack Chain & Storyline
    'AttackChain',
    'AttackPhase',
    'AttackStoryline',
    'AttackStorylineGenerator',
    # New: Threat Intelligence & Database ()
    'ThreatIntelligence',
    'AnalysisDatabase',
    # OT Malware Detection & Advanced Threat Scoring
    'OTMalwareDetector',
    'AdvancedThreatDetector',
    'MalwareDetectionResult',
    'AttackScore',
]

# Lazy imports for better startup performance
def __getattr__(name):
    if name == 'OTProtocol':
        from .constants import OTProtocol
        return OTProtocol
    elif name == 'OTEvent':
        from .models import OTEvent
        return OTEvent
    elif name == 'OTAsset':
        from .models import OTAsset
        return OTAsset
    elif name == 'SecurityAnomaly':
        from .models import SecurityAnomaly
        return SecurityAnomaly
    elif name == 'AnalyzerConfig':
        from .models import AnalyzerConfig
        return AnalyzerConfig
    elif name == 'OTAnalyzer':
        from .analyzer import OTAnalyzer
        return OTAnalyzer
    # New: Attack Chain & Storyline
    elif name == 'AttackChain':
        from .models import AttackChain
        return AttackChain
    elif name == 'AttackPhase':
        from .models import AttackPhase
        return AttackPhase
    elif name == 'AttackStoryline':
        from .models import AttackStoryline
        return AttackStoryline
    elif name == 'AttackStorylineGenerator':
        from .storyline import AttackStorylineGenerator
        return AttackStorylineGenerator
    # New: Threat Intelligence & Database ()
    elif name == 'ThreatIntelligence':
        from .threat_intel import ThreatIntelligence
        return ThreatIntelligence
    elif name == 'AnalysisDatabase':
        from .database import AnalysisDatabase
        return AnalysisDatabase
    # OT Malware Detection & Advanced Threat Scoring
    elif name == 'OTMalwareDetector':
        from .ot_malware_signatures import OTMalwareDetector
        return OTMalwareDetector
    elif name == 'MalwareDetectionResult':
        from .ot_malware_signatures import MalwareDetectionResult
        return MalwareDetectionResult
    elif name == 'AdvancedThreatDetector':
        from .advanced_threat_detector import AdvancedThreatDetector
        return AdvancedThreatDetector
    elif name == 'AttackScore':
        from .advanced_threat_detector import AttackScore
        return AttackScore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
