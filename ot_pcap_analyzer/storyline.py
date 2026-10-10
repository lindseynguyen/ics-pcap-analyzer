"""
OT PCAP Analyzer - Attack Storyline Generator
==============================================
Generates attack storylines for OT operators.

Output format:
- Narrative text
- Timeline summary
- OT impact assessment
- Remediation checklist

This module does NOT change the application's core logic.
It only adds a new optional feature (default OFF).
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib

from .models import (
    AttackChain, AttackPhase, AttackStoryline,
    SecurityAnomaly, OTAsset
)
from .utils import normalize_timestamp


# =============================================================================
# ATTACK PHASE DEFINITIONS (based on MITRE ATT&CK)
# =============================================================================

ATTACK_PHASES = {
    "RECONNAISSANCE": {
        "index": 0,
        "name": "RECONNAISSANCE",
        "description": "Attacker collects information about the target",
        "tactics": ["TA0043"],
        "keywords": ["SCAN", "PROBE", "ENUM", "DISCOVERY"],
    },
    "INITIAL_ACCESS": {
        "index": 1,
        "name": "INITIAL ACCESS",
        "description": "Attacker gains initial foothold in the network",
        "tactics": ["TA0001"],
        "keywords": ["BRUTE", "EXPLOIT", "PHISHING", "ACCESS"],
    },
    "EXECUTION": {
        "index": 2,
        "name": "EXECUTION",
        "description": "Attacker runs malicious code on the system",
        "tactics": ["TA0002"],
        "keywords": ["WEBSHELL", "MALWARE", "SCRIPT", "EXECUTE", "COMMAND"],
    },
    "PERSISTENCE": {
        "index": 3,
        "name": "PERSISTENCE",
        "description": "Attacker maintains access to the system",
        "tactics": ["TA0003"],
        "keywords": ["BACKDOOR", "PERSIST", "IMPLANT"],
    },
    "PRIVILEGE_ESCALATION": {
        "index": 4,
        "name": "PRIVILEGE ESCALATION",
        "description": "Attacker gains higher privileges",
        "tactics": ["TA0004"],
        "keywords": ["PRIVILEGE", "ESCALAT", "ROOT", "ADMIN"],
    },
    "LATERAL_MOVEMENT": {
        "index": 5,
        "name": "LATERAL MOVEMENT",
        "description": "Attacker moves through the network to other systems",
        "tactics": ["TA0008"],
        "keywords": ["LATERAL", "SMB", "RDP", "SSH", "PIVOT"],
    },
    "COLLECTION": {
        "index": 6,
        "name": "COLLECTION",
        "description": "Attacker gathers data of interest",
        "tactics": ["TA0009"],
        "keywords": ["COLLECT", "HARVEST", "CAPTURE"],
    },
    "EXFILTRATION": {
        "index": 7,
        "name": "EXFILTRATION",
        "description": "Attacker steals data from the network",
        "tactics": ["TA0010"],
        "keywords": ["EXFIL", "TUNNEL", "C2", "BEACON", "DNS_TUNNEL"],
    },
    "IMPACT": {
        "index": 8,
        "name": "IMPACT",
        "description": "Attacker disrupts or destroys systems",
        "tactics": ["TA0040"],
        "keywords": ["MODBUS_WRITE", "PLC", "RANSOMWARE", "WIPER", "STOP", "DAMAGE"],
    },
}


# =============================================================================
# STORYLINE TEMPLATES
# =============================================================================

STORYLINE_TEMPLATES = {
    "WEBSHELL_TO_OT": {
        "title": "CRITICAL ALERT - IT to OT Attack Chain Detected",
        "narrative_template": """
CRITICAL SECURITY INCIDENT - IT TO OT ATTACK CHAIN

Time range: {start_time} - {end_time}
Attack source: {source_ips}
Targets: {target_ips}

ATTACK PROGRESSION:
{phase_timeline}

OT IMPACT ASSESSMENT:
{ot_impact}

This attack chain shows a progression from IT network penetration to OT system access.
The attacker has established persistence via webshell and is attempting to reach OT assets.
""",

    },

    "C2_BEACON_DETECTED": {
        "title": "HIGH ALERT - Command & Control Communication Detected",
        "narrative_template": """
SECURITY ALERT - C2 BEACON DETECTED

Time range: {start_time} - {end_time}
Infected host: {source_ips}
C2 server: {target_ips}

BEACON PATTERN:
{phase_timeline}

RISK ASSESSMENT:
{ot_impact}

Regular beacon communication indicates an active compromise. The infected system may be
receiving commands from an external attacker. Immediate isolation is recommended.
""",

    },

    "DATA_EXFIL_DETECTED": {
        "title": "CRITICAL ALERT - Data Exfiltration Detected",
        "narrative_template": """
CRITICAL ALERT - DATA EXFILTRATION IN PROGRESS

Time range: {start_time} - {end_time}
Source: {source_ips}
Destination: {target_ips}

EXFILTRATION DETAILS:
{phase_timeline}

DATA AT RISK:
{ot_impact}

Large amounts of data are being transferred outside the network. This may include
sensitive OT configuration, process data, or intellectual property.
""",

    },

    "PLC_MANIPULATION": {
        "title": "CRITICAL ALERT - PLC/RTU Manipulation Detected",
        "narrative_template": """
CRITICAL ALERT - INDUSTRIAL CONTROL SYSTEM MANIPULATION

Time range: {start_time} - {end_time}
Attack source: {source_ips}
Target devices: {target_ips}

ATTACK DETAILS:
{phase_timeline}

PRODUCTION IMPACT:
{ot_impact}

Unauthorized commands have been sent to industrial control systems. This may cause
process disruption, equipment damage, or safety incidents. IMMEDIATE ACTION REQUIRED.
""",

    },

    "GENERIC_ATTACK_CHAIN": {
        "title": "SECURITY ALERT - Attack Chain Detected",
        "narrative_template": """
SECURITY ALERT - ATTACK CHAIN DETECTED

Time range: {start_time} - {end_time}
Source IPs: {source_ips}
Target IPs: {target_ips}

ATTACK TIMELINE:
{phase_timeline}

ASSESSMENT:
{ot_impact}

Multiple related security events have been correlated into an attack chain.
Review the timeline and take appropriate action.
""",

    },

    "UNKNOWN_PATTERN": {
        "title": "ALERT - Unknown Attack Pattern Detected - Manual Investigation Required",
        "narrative_template": """
ALERT - UNKNOWN ATTACK PATTERN DETECTED

Time range: {start_time} - {end_time}
Source IPs: {source_ips}
Target IPs: {target_ips}

ANOMALOUS ACTIVITY DETECTED:
{phase_timeline}

PRELIMINARY ASSESSMENT:
{ot_impact}

ANALYSIS REQUIRED:
This activity does not match known attack patterns in our signature database.
This could indicate:
- A novel or zero-day attack technique
- An Advanced Persistent Threat (APT) using custom tools
- False positive correlation requiring validation
- Benign anomalous behavior

RECOMMENDATION: Engage security experts for detailed forensic analysis.
Do NOT dismiss this alert - unknown patterns may represent sophisticated threats.
""",

    },
}


# =============================================================================
# THREAT ASSESSMENT DETAILS - Detailed assessment for each threat type
# =============================================================================

THREAT_ASSESSMENT_DETAILS = {
    "WEBSHELL_TO_OT": {
        "threat_level": "CRITICAL",
        "technical_description": """
WebShell attack represents a critical compromise of the IT infrastructure with potential to reach OT systems.
The attacker has successfully uploaded and executed malicious code, establishing a persistent backdoor.
This provides remote command execution capability, allowing full system control.
        """,
        "business_impact": """
HIGH BUSINESS RISK:
- Production disruption possible if OT systems are reached
- Data theft of sensitive process information and intellectual property
- Potential for sabotage or ransomware deployment
- Regulatory compliance violations (NERC CIP, IEC 62443, etc.)
- Reputation damage and customer trust erosion
        """,
        "indicators": [
            "Suspicious PHP/ASP/JSP files in web directories",
            "Unusual outbound network connections from web server",
            "High privilege commands executed from web application context",
            "Base64 encoded or obfuscated code in HTTP requests/responses",
            "File uploads with double extensions (.jpg.php)",
        ],
        "attacker_objectives": [
            "Establish persistent access to the network",
            "Reconnaissance of IT and OT network topology",
            "Credential harvesting for privilege escalation",
            "Lateral movement to OT segments",
            "Data exfiltration or destructive actions",
        ],

    },

    "C2_BEACON_DETECTED": {
        "threat_level": "HIGH",
        "technical_description": """
Command & Control (C2) beacon indicates an active malware infection with established communication to attacker infrastructure.
The regular beacon pattern allows attackers to maintain persistent access and issue commands remotely.
This is typically post-exploitation activity following initial compromise.
        """,
        "business_impact": """
MEDIUM-HIGH BUSINESS RISK:
- Ongoing data exfiltration from compromised systems
- Remote attacker control enables further attacks
- Potential for ransomware or wiper malware deployment
- Intellectual property theft and competitive disadvantage
- Investigation and remediation costs
        """,
        "indicators": [
            "Regular periodic network connections to external IPs",
            "DNS queries to suspicious or newly registered domains",
            "Encoded or encrypted traffic patterns",
            "Connections to known malicious IPs (threat intel feeds)",
            "Unusual processes making network connections",
        ],
        "attacker_objectives": [
            "Maintain persistent remote access",
            "Receive commands from C2 infrastructure",
            "Exfiltrate data on demand",
            "Deploy additional malware or tools",
            "Coordinate multi-stage attacks",
        ],

    },

    "DATA_EXFIL_DETECTED": {
        "threat_level": "CRITICAL",
        "technical_description": """
Data exfiltration indicates active theft of sensitive information from the network.
Large volume transfers, unusual protocols, or encrypted tunnels suggest systematic data stealing.
This may include OT configurations, process data, credentials, or proprietary information.
        """,
        "business_impact": """
CRITICAL BUSINESS RISK:
- Loss of competitive advantage from IP theft
- Regulatory fines for data breach (GDPR, CCPA, etc.)
- Customer data compromise and privacy violations
- OT system blueprints leaked to adversaries
- Long-term strategic disadvantage
        """,
        "indicators": [
            "Large outbound data transfers to unusual destinations",
            "Use of tunneling protocols (DNS, ICMP, HTTP)",
            "Compressed or encrypted archives being transferred",
            "Access to sensitive file shares or databases",
            "Staging of data in temporary directories before transfer",
        ],
        "attacker_objectives": [
            "Steal sensitive OT/ICS configurations and process data",
            "Exfiltrate intellectual property and trade secrets",
            "Harvest credentials for further attacks",
            "Gather intelligence on production systems",
            "Obtain data for espionage or competitive advantage",
        ],

    },

    "PLC_MANIPULATION": {
        "threat_level": "CRITICAL",
        "technical_description": """
PLC/RTU manipulation represents direct attacks on industrial control systems.
Unauthorized write commands can modify setpoints, disable safety systems, or cause physical damage.
This is the most dangerous phase of ICS attacks with potential for safety incidents.
        """,
        "business_impact": """
CATASTROPHIC BUSINESS RISK:
- Production shutdown or equipment damage
- Safety incidents endangering personnel
- Environmental contamination or releases
- Massive financial losses from downtime
- Potential for criminal or civil liability
        """,
        "indicators": [
            "Modbus/S7COMM/DNP3 write commands from unauthorized sources",
            "Unexpected changes to PLC memory or configuration",
            "Engineering workstation connections from unusual IPs",
            "Ladder logic modifications without change control",
            "Unusual setpoint changes during production",
        ],
        "attacker_objectives": [
            "Sabotage production processes",
            "Cause equipment damage or failure",
            "Create safety hazards",
            "Demonstrate capability for extortion/ransom",
            "Nation-state cyber warfare or terrorism",
        ],

    },

    "GENERIC_ATTACK_CHAIN": {
        "threat_level": "MEDIUM-HIGH",
        "technical_description": """
Multiple suspicious activities correlated across time, indicating a coordinated attack campaign.
The attack pattern shows reconnaissance, access attempts, and potential exploitation.
        """,
        "business_impact": """
VARIABLE BUSINESS RISK:
- Depends on attack progression and success
- Potential for escalation to higher severity
- May indicate broader campaign targeting organization
- Investigation costs and security improvements needed
        """,
        "indicators": [
            "Correlated suspicious activities from same source",
            "Progressive attack phases over time",
            "Multiple MITRE ATT&CK techniques observed",
            "Unusual patterns not matching known attack types",
        ],
        "attacker_objectives": [
            "Varies based on specific attack pattern",
            "May include reconnaissance, access, or exploitation",
            "Objectives to be determined through investigation",
        ],

    },

    "UNKNOWN_PATTERN": {
        "threat_level": "UNKNOWN",
        "technical_description": """
Anomalous activity detected that doesn't match known attack patterns.
This could represent a novel attack technique, zero-day exploit, or advanced persistent threat (APT).
Further investigation required to characterize the threat.
        """,
        "business_impact": """
UNKNOWN RISK - REQUIRES INVESTIGATION:
- Potentially high risk due to unknown nature
- May be false positive or benign activity
- Could represent sophisticated attack not in signature database
- Warrants careful analysis and expert review
        """,
        "indicators": [
            "Anomalous network behavior not matching signatures",
            "Unusual protocol usage or packet patterns",
            "Correlated events without clear attack classification",
            "Suspicious but unrecognized malicious patterns",
        ],
        "attacker_objectives": [
            "Unknown - requires forensic investigation",
            "May be testing new techniques or tools",
            "Could be reconnaissance for future attacks",
            "Potentially benign anomaly requiring verification",
        ],

    },
}


# =============================================================================
# USER GUIDANCE TEMPLATES - Detailed guidance for users
# =============================================================================

USER_GUIDANCE_TEMPLATES = {
    "WEBSHELL_TO_OT": {
        "detection_guidance": """
HOW TO DETECT WEBSHELLS:
1. Look for suspicious files in web directories (/var/www/, /htdocs/, etc.)
2. Check for recent file modifications on web servers
3. Review web server access logs for unusual POST requests
4. Scan for known webshell signatures (c99.php, r57.php, etc.)
5. Monitor for base64-encoded parameters in HTTP requests
        """,
        "investigation_steps": """
INVESTIGATION CHECKLIST:
□ Identify the webshell file location and upload time
□ Review web server logs for initial upload and subsequent access
□ Check commands executed through the webshell
□ Identify what data or systems were accessed
□ Determine if lateral movement to OT occurred
□ Check for additional backdoors or persistence mechanisms
□ Preserve evidence for forensic analysis
        """,
        "prevention_tips": """
PREVENTION BEST PRACTICES:
• Implement Web Application Firewall (WAF)
• Regular security updates and patching
• File upload restrictions (whitelist extensions)
• File integrity monitoring on web directories
• Principle of least privilege for web applications
• Regular security audits and penetration testing
• Network segmentation between IT and OT
        """,

    },

    "C2_BEACON_DETECTED": {
        "detection_guidance": """
HOW TO DETECT C2 BEACONS:
1. Look for periodic/regular network connections (e.g., every 60 seconds)
2. Check DNS queries to newly registered or suspicious domains
3. Monitor for connections to known malicious IPs (threat intel)
4. Identify unusual protocols or ports for outbound traffic
5. Analyze traffic patterns for encoded/encrypted data
        """,
        "investigation_steps": """
INVESTIGATION CHECKLIST:
□ Identify infected host and malware sample
□ Determine C2 infrastructure (IPs, domains)
□ Analyze beacon timing and protocol
□ Check what data was exfiltrated
□ Identify initial infection vector
□ Search for other infected hosts
□ Preserve memory dump and disk image for analysis
        """,
        "prevention_tips": """
PREVENTION BEST PRACTICES:
• Deploy DNS filtering and threat intelligence feeds
• Implement egress filtering at firewall
• Use endpoint detection and response (EDR) tools
• Regular antivirus/anti-malware updates
• Email security and phishing awareness training
• Application whitelisting where possible
• Network behavior anomaly detection
        """,

    },

    "DATA_EXFIL_DETECTED": {
        "detection_guidance": """
HOW TO DETECT DATA EXFILTRATION:
1. Monitor for large outbound data transfers
2. Check for use of tunneling protocols (DNS, ICMP)
3. Look for compressed/encrypted archives being sent
4. Identify access to sensitive file shares or databases
5. Watch for data staging in temporary directories
        """,
        "investigation_steps": """
INVESTIGATION CHECKLIST:
□ Quantify data volume exfiltrated
□ Identify what data was accessed and stolen
□ Determine exfiltration method and destination
□ Check timeline of data access and transfer
□ Identify compromised credentials used
□ Assess business impact of data loss
□ Determine notification requirements (legal/regulatory)
        """,
        "prevention_tips": """
PREVENTION BEST PRACTICES:
• Data Loss Prevention (DLP) solutions
• Encryption of sensitive data at rest and in transit
• Access controls and least privilege principles
• Database activity monitoring
• Network traffic analysis and anomaly detection
• Regular backup and recovery testing
• Incident response plan for data breach scenarios
        """,

    },

    "PLC_MANIPULATION": {
        "detection_guidance": """
HOW TO DETECT PLC MANIPULATION:
1. Monitor all write commands to PLCs/RTUs
2. Baseline normal engineering workstation activity
3. Alert on configuration changes without change control
4. Watch for connections from unauthorized IP addresses
5. Implement process value anomaly detection
        """,
        "investigation_steps": """
INVESTIGATION CHECKLIST - URGENT:
□ IMMEDIATELY verify all safety systems are functional
□ Check current PLC configuration vs. golden image
□ Review all recent write commands and their sources
□ Inspect ladder logic for unauthorized modifications
□ Verify process setpoints and alarm thresholds
□ Interview operators about unusual system behavior
□ Preserve forensic evidence (network captures, PLC backups)
        """,
        "prevention_tips": """
PREVENTION BEST PRACTICES - CRITICAL:
• Network segmentation with firewall between IT/OT
• Unidirectional gateways for critical PLCs
• Multi-factor authentication for engineering access
• Change control process for all PLC modifications
• Regular PLC configuration backups and versioning
• ICS-specific intrusion detection systems
• Security monitoring 24/7 for OT networks
• Air-gap critical safety systems where possible
        """,

    },

    "UNKNOWN_PATTERN": {
        "detection_guidance": """
HOW TO APPROACH UNKNOWN PATTERNS:
1. Treat as potentially HIGH severity until proven otherwise
2. Document all observables meticulously (timestamps, IPs, protocols, payloads)
3. Compare against threat intelligence feeds and APT reports
4. Look for patterns not in your detection rule base
5. Engage experienced security analysts immediately
6. Do NOT rely solely on automated tools for unknown threats
        """,
        "investigation_steps": """
INVESTIGATION CHECKLIST - UNKNOWN THREAT:
□ Preserve complete forensic evidence (DON'T reboot systems)
□ Capture full packet traces of suspicious traffic
□ Document exact sequence of events with timestamps
□ Check for similar activity in historical logs
□ Correlate with external threat intelligence sources
□ Engage senior analyst or third-party forensic expert
□ Consider whether this is targeted attack vs. opportunistic
□ Assess if this could be nation-state or APT activity
□ Look for custom tools, scripts, or malware variants
□ Check if any vulnerability is being exploited (potential zero-day)
        """,
        "prevention_tips": """
PREVENTION FOR UNKNOWN THREATS:
• Implement defense-in-depth strategy (multiple security layers)
• Deploy behavioral analysis and anomaly detection systems
• Use AI/ML-based threat detection where appropriate
• Maintain comprehensive logging for forensic analysis
• Regular threat hunting exercises by skilled analysts
• Participate in industry threat intelligence sharing
• Keep all systems patched and updated (reduce attack surface)
• Implement application whitelisting where possible
• Network segmentation to limit blast radius
• Incident response retainer with specialized OT security firm
        """,

    },
}


# =============================================================================
# REMEDIATION TEMPLATES
# =============================================================================

REMEDIATION_TEMPLATES = {
    "WEBSHELL_TO_OT": {
        "immediate": [
            "ISOLATE the compromised server from the network (unplug network cable or disable port)",
            "BLOCK the source IP at firewall immediately",
            "VERIFY OT devices are not receiving unauthorized commands",
            "NOTIFY the operations team for manual monitoring",
            "CONTACT the security incident response team (SOC/CERT)",
        ],
        "short_term": [
            "Perform forensic analysis on the compromised server",
            "Scan for additional webshells or backdoors",
            "Review firewall and IDS logs for related activity",
            "Check all OT devices for unauthorized changes",
            "Reset credentials for affected systems",
        ],
        "long_term": [
            "Implement network segmentation between IT and OT",
            "Deploy web application firewall (WAF)",
            "Establish file integrity monitoring",
            "Review and update access control policies",
            "Conduct security awareness training",
        ],

    },

    "C2_BEACON_DETECTED": {
        "immediate": [
            "ISOLATE the infected host from the network immediately",
            "BLOCK communication to the C2 server at firewall",
            "PRESERVE system state for forensic analysis (don't reboot)",
            "NOTIFY the security team",
            "CHECK for lateral movement to other systems",
        ],
        "short_term": [
            "Perform memory analysis on infected system",
            "Identify the malware family and capabilities",
            "Scan network for other infected hosts",
            "Review DNS logs for beacon patterns",
            "Update endpoint detection signatures",
        ],
        "long_term": [
            "Deploy EDR solution across all endpoints",
            "Implement DNS sinkholing for known C2 domains",
            "Establish threat hunting program",
            "Review and improve email filtering",
            "Conduct incident response drill",
        ],

    },

    "DATA_EXFIL_DETECTED": {
        "immediate": [
            "BLOCK the external destination at firewall",
            "ISOLATE the source system",
            "IDENTIFY what data may have been exfiltrated",
            "NOTIFY management and legal team if PII/sensitive data involved",
            "PRESERVE logs and network captures for investigation",
        ],
        "short_term": [
            "Analyze exfiltrated data to assess impact",
            "Check for data staging areas on internal systems",
            "Review DLP alerts and logs",
            "Scan for additional data collection activities",
            "Assess regulatory notification requirements",
        ],
        "long_term": [
            "Implement DLP solution",
            "Classify and label sensitive data",
            "Restrict outbound connections from OT network",
            "Implement data encryption at rest",
            "Review data access permissions",
        ],

    },

    "PLC_MANIPULATION": {
        "immediate": [
            "SWITCH affected PLC/RTU to manual control mode if safe",
            "VERIFY process is in safe state",
            "ISOLATE the attack source from OT network",
            "NOTIFY process operators immediately",
            "CONTACT OT vendor support if needed",
        ],
        "short_term": [
            "Compare PLC program with known-good backup",
            "Check for unauthorized configuration changes",
            "Review all OT device logs",
            "Verify safety system integrity",
            "Document all changes for forensics",
        ],
        "long_term": [
            "Implement OT-specific firewall/IDS",
            "Establish secure remote access procedures",
            "Implement change management for OT",
            "Deploy application whitelisting on HMI/EWS",
            "Conduct OT security assessment",
        ],

    },

    "GENERIC_ATTACK_CHAIN": {
        "immediate": [
            "Isolate affected systems from the network",
            "Block source IP addresses at firewall",
            "Notify security team",
            "Preserve evidence for investigation",
            "Monitor for additional suspicious activity",
        ],
        "short_term": [
            "Conduct thorough investigation",
            "Scan for indicators of compromise",
            "Review access logs",
            "Check for persistence mechanisms",
            "Assess scope of compromise",
        ],
        "long_term": [
            "Review and improve security controls",
            "Update detection capabilities",
            "Conduct lessons learned session",
            "Update incident response procedures",
            "Implement recommended security improvements",
        ],

    },

    "UNKNOWN_PATTERN": {
        "immediate": [
            "DO NOT dismiss - preserve ALL evidence immediately",
            "Engage senior security analyst or external forensic expert",
            "Document all observed behaviors and anomalies in detail",
            "Isolate affected systems if risk is assessed as HIGH",
            "Monitor continuously for pattern evolution",
            "Check threat intelligence feeds for similar activity",
        ],
        "short_term": [
            "Perform deep forensic analysis (memory, disk, network)",
            "Correlate with threat intelligence and APT reports",
            "Reverse engineer any suspicious binaries or scripts",
            "Consult with ICS/OT security specialists",
            "Submit suspicious files to malware analysis sandbox",
            "Review similar timeframes for related activity",
            "Consider engaging incident response retainer",
        ],
        "long_term": [
            "Develop custom detection signatures based on findings",
            "Share IOCs with industry ISAC/ISAO if appropriate",
            "Enhance monitoring for novel attack techniques",
            "Conduct threat hunting exercises regularly",
            "Participate in threat intelligence sharing communities",
            "Update incident response playbooks with lessons learned",
            "Consider advanced threat detection technologies (AI/ML)",
        ],

    },
}


# =============================================================================
# ATTACK STORYLINE GENERATOR
# =============================================================================

class AttackStorylineGenerator:
    """
    Generates attack storylines for OT operators.

    Output format:
    - Narrative text (English only)
    - Timeline summary
    - OT impact assessment
    - Remediation checklist

    This module does NOT change the core detection logic.
    It only produces output that is easy for users to understand.
    """

    def __init__(self):
        """Initialize generator."""
        self.generated_storylines: List[AttackStoryline] = []

    def generate_storyline(
        self,
        chain: AttackChain,
        anomalies: List[SecurityAnomaly],
        ot_assets: Dict[str, OTAsset]
    ) -> AttackStoryline:
        """
        Create a storyline from an attack chain.

        Args:
            chain: Correlated AttackChain
            anomalies: List of anomalies in the chain
            ot_assets: Dict of OT assets

        Returns:
            AttackStoryline object
        """
        # Determine attack type
        attack_type = self._classify_attack(chain, anomalies)

        # Get template
        template = STORYLINE_TEMPLATES.get(attack_type, STORYLINE_TEMPLATES["GENERIC_ATTACK_CHAIN"])
        remediation = REMEDIATION_TEMPLATES.get(attack_type, REMEDIATION_TEMPLATES["GENERIC_ATTACK_CHAIN"])

        # Build timeline and OT impact sections
        phase_timeline = self._generate_phase_timeline(chain, anomalies)
        ot_impact = self._generate_ot_impact(chain, ot_assets)

        # Format narrative
        format_vars = {
            "start_time": self._format_timestamp(chain.start_time),
            "end_time": self._format_timestamp(chain.end_time),
            "source_ips": ", ".join(sorted(chain.source_ips)) if chain.source_ips else "Unknown",
            "target_ips": ", ".join(sorted(chain.target_ips)) if chain.target_ips else "Unknown",
            "phase_timeline": phase_timeline,
            "ot_impact": ot_impact,
        }

        narrative = template["narrative_template"].format(**format_vars)

        # Generate key events list
        key_events = self._extract_key_events(chain, anomalies)

        # Determine production risk
        production_risk = self._assess_production_risk(chain, ot_assets)

        # Get threat assessment details
        threat_assessment = THREAT_ASSESSMENT_DETAILS.get(
            attack_type,
            THREAT_ASSESSMENT_DETAILS.get("GENERIC_ATTACK_CHAIN", {})
        )

        # Get user guidance
        user_guidance = USER_GUIDANCE_TEMPLATES.get(attack_type, {})

        # Create storyline with enhanced details
        storyline = AttackStoryline(
            storyline_id=self._generate_id(chain),
            chain_id=chain.chain_id,

            # Narrative
            title=template["title"],
            narrative=narrative,
            timeline_summary=phase_timeline,
            key_events=key_events,

            # OT Impact
            ot_impact_summary=ot_impact,
            affected_assets=list(chain.ot_assets_at_risk),
            production_risk=production_risk,

            # Remediation
            immediate_actions=remediation["immediate"],
            short_term_actions=remediation["short_term"],
            long_term_actions=remediation["long_term"],
            generated_at=datetime.now().timestamp(),
            confidence=chain.confidence,
            attack_type=attack_type,
            severity=chain.overall_severity,

            # Enhanced Threat Assessment
            threat_level=threat_assessment.get("threat_level", "UNKNOWN"),
            technical_description=threat_assessment.get("technical_description", "").strip(),
            business_impact=threat_assessment.get("business_impact", "").strip(),
            threat_indicators=threat_assessment.get("indicators", []),
            attacker_objectives=threat_assessment.get("attacker_objectives", []),
            detection_guidance=user_guidance.get("detection_guidance", "").strip(),
            investigation_steps=user_guidance.get("investigation_steps", "").strip(),
            prevention_tips=user_guidance.get("prevention_tips", "").strip(),
            )

        self.generated_storylines.append(storyline)
        return storyline

    def _classify_attack(
        self,
        chain: AttackChain,
        anomalies: List[SecurityAnomaly]
    ) -> str:
        """
        Classify the attack type based on the chain and anomalies.

        Enhanced with:
        - Priority-based classification
        - Unknown pattern detection
        - Threat_analysis integration
        - Confidence scoring
        """
        anomaly_types = [a.anomaly_type.upper() for a in anomalies]
        combined = " ".join(anomaly_types)

        # Also check threat_analysis for better classification
        threat_types = []
        for a in anomalies:
            if hasattr(a, 'threat_analysis') and a.threat_analysis:
                detected = a.threat_analysis.get('detected_threats', [])
                threat_types.extend([t.upper() for t in detected])

        combined_threats = " ".join(threat_types)
        all_indicators = combined + " " + combined_threats

        # Priority 1: PLC/OT Direct Manipulation (MOST CRITICAL)
        if any(kw in all_indicators for kw in ["MODBUS_WRITE", "PLC", "S7COMM", "DNP3", "IEC104", "WRITE_COIL", "WRITE_REGISTER"]):
            return "PLC_MANIPULATION"

        # Priority 2: WebShell with OT Impact
        if any(kw in all_indicators for kw in ["WEBSHELL", "PHP_EXECUTION", "SHELL_EXEC"]):
            if chain.has_ot_impact or chain.ot_escalation_score > 0.5:
                return "WEBSHELL_TO_OT"
            # WebShell without OT impact falls through to generic

        # Priority 3: Data Exfiltration
        if any(kw in all_indicators for kw in ["EXFIL", "TUNNEL", "DNS_TUNNEL", "DATA_STEAL"]):
            return "DATA_EXFIL_DETECTED"

        # Priority 4: C2 Communication
        if any(kw in all_indicators for kw in ["C2_BEACON", "BEACON", "COMMAND_CONTROL", "C2"]):
            return "C2_BEACON_DETECTED"

        # Priority 5: Generic Attack Chain (multi-phase but no specific pattern)
        # Check if we have recognizable patterns
        known_patterns = [
            "SCAN", "PROBE", "BRUTE", "EXPLOIT", "WEBSHELL", "MALWARE",
            "BACKDOOR", "LATERAL", "COLLECT", "EXFIL", "C2"
        ]

        has_known_patterns = any(kw in all_indicators for kw in known_patterns)

        if has_known_patterns and len(chain.phases) >= 2:
            return "GENERIC_ATTACK_CHAIN"

        # Priority 6: Unknown Pattern (no match with known patterns)
        # This could be:
        # - Novel attack technique
        # - False positives
        # - Benign anomalies correlated by chance
        # - Advanced persistent threat (APT) with custom tools

        if len(chain.phases) >= 2 or chain.total_events >= 5:
            # Multiple phases or many events but no known pattern
            # Mark as UNKNOWN for manual investigation
            return "UNKNOWN_PATTERN"

        # Fallback: treat as generic if we got this far
        return "GENERIC_ATTACK_CHAIN"

    def _generate_phase_timeline(
        self,
        chain: AttackChain,
        anomalies: List[SecurityAnomaly]
    ) -> str:
        """
        Build a timeline of the phases with enhanced detail.

        Enhanced to include:
        - Timing analysis (duration, velocity)
        - Event count per phase
        - Severity progression
        - Visualization metadata
        """
        timeline_en = []

        # Calculate phase statistics for better analysis
        total_duration = chain.end_time - chain.start_time

        # Add header with attack velocity analysis
        if total_duration > 0:
            velocity_score = len(chain.phases) / (total_duration / 3600)  # phases per hour
            if velocity_score > 2:
                velocity_assessment = "RAPID PROGRESSION (high threat urgency)"
            elif velocity_score > 1:
                velocity_assessment = "Moderate progression"
            else:
                velocity_assessment = "Slow progression (patient attacker)"

            timeline_en.append(f"Attack Velocity: {velocity_assessment}")
            timeline_en.append(f"Total Duration: {self._format_duration(total_duration)}")
            timeline_en.append(f"Phases: {len(chain.phases)} | Events: {chain.total_events}")
            timeline_en.append("-" * 70)

        # Generate detailed phase timeline
        for i, phase in enumerate(chain.phases, 1):
            phase_info = ATTACK_PHASES.get(phase.phase_name, {})
            time_str = self._format_timestamp(phase.timestamp)

            # Count events in this phase
            phase_event_count = max(phase.event_count or 0, len(phase.event_ids))

            # Severity indicator
            severity_symbol = self._get_severity_symbol(phase.severity)

            # English timeline with enhanced details
            en_line = f"{severity_symbol} Phase {i}/{len(chain.phases)}: {phase.phase_name}"
            en_line += f"\n   Time: {time_str} | Events: {phase_event_count} | Severity: {phase.severity}"
            en_line += f"\n   Description: {phase.description or phase_info.get('description', '')}"
            if phase.mitre_techniques:
                en_line += f"\n   MITRE ATT&CK: {', '.join(phase.mitre_techniques)}"
            timeline_en.append(en_line)
            if phase.mitre_techniques:
                pass

        # Add attack progression analysis
        if len(chain.phases) >= 3:
            timeline_en.append("-" * 70)
            timeline_en.append("PROGRESSION ANALYSIS:")
            timeline_en.append(f"The attacker progressed through {len(chain.phases)} distinct phases,")
            timeline_en.append("indicating a sophisticated, multi-stage attack campaign.")

        return "\n".join(timeline_en)

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minutes"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
        else:
            days = int(seconds / 86400)
            hours = int((seconds % 86400) / 3600)
            return f"{days}d {hours}h"

    def _get_severity_symbol(self, severity: str) -> str:
        """Get symbol for severity level."""
        severity_symbols = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }
        return severity_symbols.get(severity, "⚪")

    def _generate_ot_impact(
        self,
        chain: AttackChain,
        ot_assets: Dict[str, OTAsset]
    ) -> str:
        """Build the OT impact assessment."""
        if not chain.has_ot_impact and not chain.ot_assets_at_risk:
            return "No direct OT impact detected. Continue monitoring for lateral movement."

        impact_lines_en = []

        for asset_ip in chain.ot_assets_at_risk:
            asset = ot_assets.get(asset_ip)
            if asset:
                device_type = asset.device_type
                protocols = ", ".join(sorted(asset.protocols_seen)) if asset.protocols_seen else "Unknown"

                impact_lines_en.append(
                    f"- {asset_ip} ({device_type}): May be compromised. Protocols: {protocols}"
                )
            else:
                impact_lines_en.append(f"- {asset_ip}: At risk")

        # Add escalation score
        if chain.ot_escalation_score >= 0.8:
            impact_lines_en.append(f"\nOT Escalation Score: {chain.ot_escalation_score:.2f} (CRITICAL)")
        elif chain.ot_escalation_score >= 0.5:
            impact_lines_en.append(f"\nOT Escalation Score: {chain.ot_escalation_score:.2f} (HIGH)")

        return "\n".join(impact_lines_en)

    def _extract_key_events(
        self,
        chain: AttackChain,
        anomalies: List[SecurityAnomaly]
    ) -> List[Dict[str, Any]]:
        """Extract the key events."""
        key_events = []

        for anomaly in anomalies[:20]:  # Limit to 20 events
            # Base event data
            event = {
                "time": self._format_timestamp(anomaly.timestamp),
                "timestamp": anomaly.timestamp,
                "type": anomaly.anomaly_type,
                "severity": anomaly.severity,
                "source": anomaly.src_ip,
                "target": anomaly.dst_ip,
                "description": anomaly.description,
                "significance": self._get_event_significance(anomaly),
            }

            # Integrate threat_analysis if present (HTTP WebShell detection)
            if hasattr(anomaly, 'threat_analysis') and anomaly.threat_analysis:
                ta = anomaly.threat_analysis

                # Add detected threats to the description
                detected_threats = ta.get('detected_threats', [])
                if detected_threats:
                    threats_str = ', '.join(detected_threats)

                # Add threat level and risk score
                threat_level = ta.get('threat_level', '')
                risk_score = ta.get('risk_score', 0)
                if threat_level:
                    pass
                if risk_score > 0:
                    pass

                # Add WebShell indicators if present
                webshell_indicators = ta.get('webshell_indicators', [])
                if webshell_indicators:
                    ws_type = webshell_indicators[0].get('type', '')
                    if ws_type:
                        pass

                # Add command execution evidence if present
                cmd_evidence = ta.get('command_execution_evidence', [])
                if cmd_evidence:
                    cmd_str = cmd_evidence[0] if isinstance(cmd_evidence, list) else str(cmd_evidence)
                    if len(cmd_str) > 50:
                        cmd_str = cmd_str[:50] + '...'

            key_events.append(event)

        # Sort by timestamp
        key_events.sort(key=lambda x: x["timestamp"])
        return key_events

    def _get_event_significance(self, anomaly: SecurityAnomaly) -> str:
        """Determine the significance of an event."""
        atype = anomaly.anomaly_type.upper()

        if "WEBSHELL" in atype or "C2" in atype or "PLC" in atype:
            return "CRITICAL - Immediate action required"
        elif "LATERAL" in atype or "BRUTE" in atype or "EXPLOIT" in atype:
            return "HIGH - Active attack in progress"
        elif "SCAN" in atype or "PROBE" in atype:
            return "MEDIUM - Reconnaissance activity"
        else:
            return "NORMAL - Part of attack chain"

    def _assess_production_risk(
        self,
        chain: AttackChain,
        ot_assets: Dict[str, OTAsset]
    ) -> str:
        """Assess production risk."""
        if chain.ot_escalation_score >= 0.8:
            return "CRITICAL"
        elif chain.ot_escalation_score >= 0.6:
            return "HIGH"
        elif chain.ot_escalation_score >= 0.4:
            return "MEDIUM"
        elif chain.ot_escalation_score >= 0.2:
            return "LOW"
        else:
            return "NONE"

    def _format_timestamp(self, ts: float) -> str:
        """Format a timestamp as a human-readable string."""
        if ts <= 0:
            return "Unknown"
        # Normalize timestamp to avoid "year out of range" errors
        normalized = normalize_timestamp(ts)
        if normalized is None:
            return "Unknown"
        try:
            dt = datetime.fromtimestamp(normalized)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, ValueError):
            return "Unknown"

    def _generate_id(self, chain: AttackChain) -> str:
        """Generate a unique ID for the storyline."""
        base = f"{chain.chain_id}-{datetime.now().timestamp()}"
        return f"STORY-{hashlib.md5(base.encode()).hexdigest()[:12].upper()}"

    def generate_text_report(self, storyline: AttackStoryline) -> str:
        """
        Build a plain-text report from a storyline.

        Args:
            storyline: AttackStoryline object

        Returns:
            Formatted text report
        """
        lines = []
        sep = "=" * 75

        lines.append(sep)
        lines.append(f"  {storyline.title}")
        lines.append(sep)
        lines.append(f"  Storyline ID: {storyline.storyline_id}")
        lines.append(f"  Chain ID: {storyline.chain_id}")
        lines.append(f"  Generated: {self._format_timestamp(storyline.generated_at)}")
        lines.append(f"  Severity: {storyline.severity}")
        lines.append(f"  Production Risk: {storyline.production_risk}")
        lines.append(sep)
        lines.append("")
        lines.append(storyline.narrative)
        lines.append("")

        # === THREAT ASSESSMENT ===
        if storyline.threat_level:
            lines.append(sep)
            lines.append("  THREAT ASSESSMENT")
            lines.append(sep)
            lines.append(f"  Threat Level: {storyline.threat_level}")
            lines.append("")

            if storyline.technical_description:
                lines.append("  Technical Analysis:")
                lines.append(storyline.technical_description)
                lines.append("")

            if storyline.business_impact:
                lines.append("  Business Impact:")
                lines.append(storyline.business_impact)
                lines.append("")

        # === INDICATORS OF COMPROMISE ===
        if storyline.threat_indicators:
            lines.append(sep)
            lines.append("  INDICATORS OF COMPROMISE")
            lines.append(sep)
            for i, indicator in enumerate(storyline.threat_indicators, 1):
                lines.append(f"  {i}. {indicator}")
            lines.append("")
            lines.append("")

        # === ATTACKER OBJECTIVES ===
        if storyline.attacker_objectives:
            lines.append(sep)
            lines.append("  ATTACKER OBJECTIVES")
            lines.append(sep)
            for i, objective in enumerate(storyline.attacker_objectives, 1):
                lines.append(f"  {i}. {objective}")
            lines.append("")
            lines.append("")

        # === USER GUIDANCE ===
        if storyline.detection_guidance:
            lines.append(sep)
            lines.append("  DETECTION GUIDANCE")
            lines.append(sep)
            lines.append(storyline.detection_guidance)
            lines.append("")
            lines.append("")

        if storyline.investigation_steps:
            lines.append(sep)
            lines.append("  INVESTIGATION CHECKLIST")
            lines.append(sep)
            lines.append(storyline.investigation_steps)
            lines.append("")
            lines.append("")

        if storyline.prevention_tips:
            lines.append(sep)
            lines.append("  PREVENTION TIPS")
            lines.append(sep)
            lines.append(storyline.prevention_tips)
            lines.append("")
            lines.append("")

        # === REMEDIATION ===
        lines.append(sep)
        lines.append("  IMMEDIATE ACTIONS")
        lines.append(sep)

        actions = storyline.immediate_actions
        for i, action in enumerate(actions, 1):
            lines.append(f"  [ ] {i}. {action}")
            lines.append("")

        lines.append(sep)
        lines.append("  SHORT-TERM ACTIONS (24h)")
        lines.append(sep)

        actions = storyline.short_term_actions
        for i, action in enumerate(actions, 1):
            lines.append(f"  [ ] {i}. {action}")
            lines.append("")

        lines.append(sep)
        lines.append("  LONG-TERM ACTIONS (1 week)")
        lines.append(sep)

        actions = storyline.long_term_actions
        for i, action in enumerate(actions, 1):
            lines.append(f"  [ ] {i}. {action}")
            lines.append("")

        lines.append(sep)
        lines.append("  Emergency Contact: SOC Hotline")
        lines.append(sep)

        return "\n".join(lines)

    def get_storylines(self) -> List[AttackStoryline]:
        """Return the list of generated storylines."""
        return self.generated_storylines

    def clear_storylines(self):
        """Clear the list of storylines."""
        self.generated_storylines.clear()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def detect_attack_phase(anomaly: SecurityAnomaly) -> Optional[str]:
    """
    Determine the attack phase from the anomaly type.

    Priority:
    1. Check the threat_analysis dict (if present) - for HTTP WebShell detection
    2. Fall back to anomaly_type string matching

    Args:
        anomaly: SecurityAnomaly object

    Returns:
        Phase name or None
    """
    # STEP 1: Check the threat_analysis dict (if present)
    if hasattr(anomaly, 'threat_analysis') and anomaly.threat_analysis:
        detected_threats = anomaly.threat_analysis.get('detected_threats', [])

        # Map detected threats to attack phases
        for threat in detected_threats:
            threat_upper = threat.upper()

            # EXECUTION phase keywords
            if any(kw in threat_upper for kw in ['WEBSHELL', 'MALWARE', 'SCRIPT', 'EXECUTE', 'COMMAND', 'PHP_EXECUTION', 'SHELL_EXEC']):
                return 'EXECUTION'

            # PERSISTENCE phase keywords
            if any(kw in threat_upper for kw in ['BACKDOOR', 'PERSIST', 'IMPLANT']):
                return 'PERSISTENCE'

            # EXFILTRATION phase keywords
            if any(kw in threat_upper for kw in ['EXFIL', 'C2', 'BEACON', 'TUNNEL', 'DNS_TUNNEL']):
                return 'EXFILTRATION'

            # INITIAL_ACCESS phase keywords
            if any(kw in threat_upper for kw in ['UPLOAD', 'FILE_WRITE', 'BRUTE', 'EXPLOIT']):
                return 'INITIAL_ACCESS'

            # COLLECTION phase keywords
            if any(kw in threat_upper for kw in ['COLLECT', 'HARVEST', 'DATA_STEAL']):
                return 'COLLECTION'

            # LATERAL_MOVEMENT phase keywords
            if any(kw in threat_upper for kw in ['LATERAL', 'SMB', 'RDP', 'SSH', 'PIVOT']):
                return 'LATERAL_MOVEMENT'

    # STEP 2: Fallback - check the anomaly_type string (original logic)
    atype = anomaly.anomaly_type.upper()

    for phase_name, phase_info in ATTACK_PHASES.items():
        keywords = phase_info.get("keywords", [])
        for keyword in keywords:
            if keyword in atype:
                return phase_name

    return None


def get_phase_index(phase_name: str) -> int:
    """Return the phase index (0-8)."""
    phase_info = ATTACK_PHASES.get(phase_name, {})
    return phase_info.get("index", -1)


def create_attack_phase(
    phase_name: str,
    anomaly: SecurityAnomaly,
    event_id: int = 0
) -> AttackPhase:
    """
    Create an AttackPhase from an anomaly.

    Args:
        phase_name: Phase name
        anomaly: SecurityAnomaly object
        event_id: Event ID

    Returns:
        AttackPhase object
    """
    phase_info = ATTACK_PHASES.get(phase_name, {})

    return AttackPhase(
        phase_name=phase_name,
        phase_index=phase_info.get("index", -1),
        timestamp=anomaly.timestamp,
        event_ids=[event_id] if event_id is not None else [],
        event_count=1,
        mitre_tactics=phase_info.get("tactics", []),
        mitre_techniques=list(anomaly.mitre_techniques),
        description=phase_info.get("description", ""),
        severity=anomaly.severity,
    )
