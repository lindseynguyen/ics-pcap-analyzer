"""
OT PCAP Analyzer - Enhanced HTTP Stream Analysis
================================================
Deep inspection for WebShell detection and HTTP attacks.

Features:
- Multi-stage WebShell detection (upload, execution, commands)
- PHP/JSP/ASPX/Python backdoor signatures
- Obfuscation detection (base64, hex, gzip chains)
- POST data analysis for file uploads
- Command execution pattern matching
- Reverse shell detection
- SQL injection in HTTP
- Path traversal attacks
- Session tracking for attack correlation
"""

import re
import base64
import hashlib
import zlib
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
from datetime import datetime

from .utils import cached_regex, entropy, logger


# =============================================================================
# ENHANCED WEBSHELL SIGNATURES
# =============================================================================

WEBSHELL_SIGNATURES = {
    # PHP WebShells - Common names
    "KNOWN_WEBSHELL_FILES": [
        r"c99\.php", r"r57\.php", r"b374k\.php", r"wso\.php", r"alfa\.php",
        r"weevely", r"china_chopper", r"bypasswaf\.php", r"adminer\.php",
        r"phpspy\.php", r"antichat\.php", r"matamu\.php", r"indoxploit\.php",
        r"mini\.php", r"shell\.php", r"cmd\.php", r"backdoor\.php",
    ],

    # PHP Dangerous functions
    "PHP_EXECUTION": [
        r"eval\s*\(",
        r"assert\s*\(",
        r"exec\s*\(",
        r"system\s*\(",
        r"passthru\s*\(",
        r"shell_exec\s*\(",
        r"popen\s*\(",
        r"proc_open\s*\(",
        r"pcntl_exec\s*\(",
        r"`[^`]+`",  # Backtick execution
        r"create_function\s*\(",
        r"include\s*\(\s*[\$_]",  # Dynamic include
        r"require\s*\(\s*[\$_]",  # Dynamic require
    ],

    # Variable function calls (obfuscation)
    "PHP_VARIABLE_FUNCTIONS": [
        r"\$[a-zA-Z_]+\s*\(\s*\$",  # $func($var)
        r"\$\{[^\}]+\}\s*\(",  # ${var}()
        r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(",  # $_GET['x']()
        r"\$\$[a-zA-Z_]+\s*\(",  # $$var()
    ],

    # Encoding/Obfuscation chains
    "PHP_OBFUSCATION": [
        r"base64_decode\s*\(",
        r"gzinflate\s*\(",
        r"gzuncompress\s*\(",
        r"gzdecode\s*\(",
        r"str_rot13\s*\(",
        r"convert_uudecode\s*\(",
        r"hex2bin\s*\(",
        r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",  # Hex encoded
    ],

    # JSP WebShells
    "JSP_EXECUTION": [
        r"Runtime\.getRuntime\(\)\.exec",
        r"ProcessBuilder",
        r"\.getInputStream\(\)",
        r"\.getOutputStream\(\)",
        r"<%\s*Runtime",
        r"java\.lang\.Runtime",
        r"request\.getParameter.*exec",
    ],

    # ASPX WebShells
    "ASPX_EXECUTION": [
        r"Process\.Start",
        r"ProcessStartInfo",
        r"System\.Diagnostics\.Process",
        r"cmd\.exe.*aspx",
        r"powershell.*aspx",
        r"Response\.Write.*Process",
    ],

    # Python WebShells
    "PYTHON_EXECUTION": [
        r"os\.system\s*\(",
        r"os\.popen\s*\(",
        r"subprocess\.call",
        r"subprocess\.Popen",
        r"__import__\s*\(\s*['\"]os['\"]",
        r"exec\s*\(.*request",
        r"eval\s*\(.*request",
    ],

    # Command patterns (cross-platform)
    "COMMAND_PATTERNS": [
        # Linux/Unix commands
        r"/bin/(?:bash|sh|dash|zsh)",
        r"bash\s+-[ci]",
        r"sh\s+-[ci]",
        r"cat\s+/etc/passwd",
        r"cat\s+/etc/shadow",
        r"wget\s+http",
        r"curl\s+http",
        r"nc\s+-[el]",  # netcat
        r"ncat\s+-[el]",
        r"socat\s+",

        # Windows commands
        r"cmd\.exe\s+/[ck]",
        r"cmd\s+/[ck]",
        r"powershell\.exe\s+-",
        r"powershell\s+-(?:enc|nop|w\s+hidden)",
        r"net\s+user",
        r"net\s+localgroup",
        r"reg\s+(?:add|query|delete)",

        # Common recon commands
        r"whoami",
        r"id\s*[;&|]",
        r"uname\s+-a",
        r"(?<![\w=])hostname(?=\s*(?:$|[;&|`)]))",  # the command, not a "hostname=" parameter
        r"ipconfig\s*/all",
        r"ifconfig",
        r"netstat\s+-",
        r"ps\s+aux",
        r"tasklist",
    ],

    # Reverse shell patterns
    "REVERSE_SHELL": [
        r"tcp:\d+\.\d+\.\d+\.\d+:\d+",  # Socat/netcat reverse
        r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+",  # Bash reverse shell
        r"mkfifo\s+/tmp/",  # Named pipe reverse shell
        r"python.*socket.*connect",
        r"perl.*socket.*connect",
        r"ruby.*socket.*connect",
        r"nc\s+-e\s+/bin/(?:bash|sh)",
        r"ncat\s+-e\s+/bin/(?:bash|sh)",
        r"\|&\s*/bin/(?:bash|sh)",  # Pipe to shell
    ],
}


# File upload patterns (multipart/form-data)
FILE_UPLOAD_PATTERNS = {
    "DANGEROUS_EXTENSIONS": [
        r"\.php[3-7]?", r"\.phtml", r"\.phar", r"\.inc",
        r"\.jsp", r"\.jspx", r"\.jsw", r"\.jsv",
        r"\.asp", r"\.aspx", r"\.cer", r"\.asa",
        r"\.py", r"\.pl", r"\.cgi",
        r"\.exe", r"\.dll", r"\.bat", r"\.cmd",
        r"\.sh", r"\.bash",
    ],

    "DOUBLE_EXTENSION": [
        r"\.(?:jpg|png|gif|pdf|doc|txt)\.php",
        r"\.(?:jpg|png|gif|pdf|doc|txt)\.jsp",
        r"\.(?:jpg|png|gif|pdf|doc|txt)\.aspx",
        r"\.(?:jpg|png|gif|pdf|doc|txt)\.exe",
    ],

    "NULL_BYTE": [
        r"\.php%00",
        r"\.jsp%00",
        r"\.asp%00",
        r"%00\.(?:jpg|png|gif)",
    ],

    "MAGIC_BYTES": {
        "ELF": b"\x7fELF",
        "PE": b"MZ",
        "PHP": b"<?php",
        "JSP": b"<%@",
        "ASPX": b"<%@",
    },
}


# =============================================================================
# ENHANCED HTTP STREAM ANALYZER
# =============================================================================

class EnhancedHTTPStreamAnalyzer:
    """
    Enhanced HTTP stream analyzer with deep WebShell detection.

    Features:
    - Multi-stage attack detection (upload -> execution -> command)
    - Session correlation (track attacker across requests)
    - Payload decoding with explanation
    - Behavioral analysis (timing, frequency, patterns)
    """

    def __init__(self):
        # Session tracking for correlation
        self.sessions: Dict[str, Dict] = {}  # session_id -> session_data

        # IP tracking for attacker profiling
        self.ip_activity: Dict[str, List[Dict]] = defaultdict(list)
        self.ip_uploaded_files: Dict[str, List[str]] = defaultdict(list)
        self.ip_commands_executed: Dict[str, List[str]] = defaultdict(list)

        # WebShell detection state
        self.suspected_webshells: Dict[str, Dict] = {}  # uri -> details
        self.confirmed_webshells: Dict[str, Dict] = {}  # uri -> details

        # Attack chain tracking
        self.attack_sequences: Dict[str, List[Dict]] = defaultdict(list)

    def analyze_http_request(self, http_data: Dict) -> List[Dict]:
        """
        Perform comprehensive analysis of an HTTP request.

        Returns:
            List of detected threats with detailed evidence
        """
        threats = []

        src_ip = http_data.get('src_ip', '')
        uri = http_data.get('uri', '')
        method = http_data.get('method', '')
        body = http_data.get('body', '')
        headers = http_data.get('headers', {})
        timestamp = http_data.get('timestamp', 0)

        # Track activity
        activity = {
            'timestamp': timestamp,
            'method': method,
            'uri': uri,
            'body_size': len(body) if body else 0,
        }
        self.ip_activity[src_ip].append(activity)

        # 1. Check for known WebShell access
        webshell_threat = self._detect_webshell_access(http_data)
        if webshell_threat:
            threats.append(webshell_threat)

        # 2. Check for file upload (potential WebShell installation)
        if method == 'POST':
            upload_threat = self._detect_file_upload(http_data)
            if upload_threat:
                threats.append(upload_threat)

        # 3. Check for command execution in GET/POST params
        cmd_threat = self._detect_command_execution(http_data)
        if cmd_threat:
            threats.append(cmd_threat)

        # 4. Check for reverse shell establishment
        revshell_threat = self._detect_reverse_shell(http_data)
        if revshell_threat:
            threats.append(revshell_threat)

        # 5. Check for obfuscated payload
        obfuscation_threat = self._detect_obfuscation(http_data)
        if obfuscation_threat:
            threats.append(obfuscation_threat)

        # 6. Behavioral analysis (rapid requests, suspicious patterns)
        behavior_threat = self._analyze_behavior(src_ip, http_data)
        if behavior_threat:
            threats.append(behavior_threat)

        # 7. Correlate with previous activity (multi-stage attack)
        correlation_threat = self._correlate_attack_chain(src_ip, http_data, threats)
        if correlation_threat:
            threats.append(correlation_threat)

        return threats

    def _detect_webshell_access(self, http_data: Dict) -> Optional[Dict]:
        """Detect access to known WebShell files."""
        uri = http_data.get('uri', '')
        body = http_data.get('body', '')

        # Check URI for known WebShell filenames
        for pattern in WEBSHELL_SIGNATURES['KNOWN_WEBSHELL_FILES']:
            if cached_regex(pattern, re.IGNORECASE).search(uri):
                return {
                    'type': 'WEBSHELL_ACCESS',
                    'severity': 'CRITICAL',
                    'confidence': 0.95,
                    'description': f"Access to known WebShell file: {uri}",
                    'evidence': {
                        'uri': uri,
                        'pattern': pattern,
                        'matched_type': 'known_filename',
                    },
                    'mitre': ['T1505.003'],
                    'recommendation': "Isolate server immediately and check for compromise.",
                }

        # Check body for WebShell content
        if body:
            body_text = body if isinstance(body, str) else body.decode('utf-8', errors='replace')

            # PHP execution functions
            php_patterns_found = []
            for pattern in WEBSHELL_SIGNATURES['PHP_EXECUTION']:
                if cached_regex(pattern, re.IGNORECASE).search(body_text):
                    php_patterns_found.append(pattern)

            if len(php_patterns_found) >= 3:
                return {
                    'type': 'WEBSHELL_EXECUTION_PHP',
                    'severity': 'CRITICAL',
                    'confidence': 0.90,
                    'description': f"PHP WebShell execution detected with {len(php_patterns_found)} dangerous functions",
                    'evidence': {
                        'uri': uri,
                        'patterns_found': php_patterns_found[:5],
                        'body_preview': body_text[:200],
                    },
                    'mitre': ['T1505.003', 'T1059.004'],
                    'recommendation': "WebShell is active. Isolate server and perform incident response.",
                }

        return None

    def _detect_file_upload(self, http_data: Dict) -> Optional[Dict]:
        """Detect dangerous file uploads (WebShell)."""
        body = http_data.get('body', '')
        content_type = http_data.get('content_type', '')
        uri = http_data.get('uri', '')
        src_ip = http_data.get('src_ip', '')

        if 'multipart/form-data' not in content_type.lower():
            return None

        if not body:
            return None

        body_bytes = body if isinstance(body, bytes) else body.encode('utf-8', errors='replace')
        body_text = body if isinstance(body, str) else body.decode('utf-8', errors='replace')

        # Extract filename from Content-Disposition
        filename_match = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)', body_text, re.IGNORECASE)
        if not filename_match:
            return None

        filename = filename_match.group(1)

        # Check for dangerous extensions
        is_dangerous = False
        matched_pattern = None

        for pattern in FILE_UPLOAD_PATTERNS['DANGEROUS_EXTENSIONS']:
            # Anchor to the end of the file name: "q3.shared.xlsx" is not ".sh"
            if cached_regex(pattern + r'(?:$|[\s\x00%])', re.IGNORECASE).search(filename.strip()):
                is_dangerous = True
                matched_pattern = pattern
                break

        # Check for double extension
        for pattern in FILE_UPLOAD_PATTERNS['DOUBLE_EXTENSION']:
            if cached_regex(pattern, re.IGNORECASE).search(filename):
                is_dangerous = True
                matched_pattern = f"double_extension:{pattern}"
                break

        # Check for null byte
        for pattern in FILE_UPLOAD_PATTERNS['NULL_BYTE']:
            if cached_regex(pattern, re.IGNORECASE).search(filename):
                is_dangerous = True
                matched_pattern = f"null_byte:{pattern}"
                break

        if not is_dangerous:
            return None

        # Extract file content (simplified - find boundary)
        # The boundary is declared in the Content-Type header (fall back to the body)
        boundary_match = (re.search(rb'boundary="?([^\r\n;"]+)"?', content_type.encode('utf-8', errors='replace'))
                          or re.search(rb'boundary=([^\r\n;]+)', body_bytes))
        if boundary_match:
            boundary = boundary_match.group(1)
            parts = body_bytes.split(b'--' + boundary)

            for part in parts:
                if b'filename=' in part:
                    # Find content after headers
                    content_start = part.find(b'\r\n\r\n')
                    if content_start != -1:
                        file_content = part[content_start+4:]

                        # Check magic bytes
                        for magic_name, magic_bytes in FILE_UPLOAD_PATTERNS['MAGIC_BYTES'].items():
                            if file_content.startswith(magic_bytes):
                                # Track upload
                                self.ip_uploaded_files[src_ip].append(filename)

                                return {
                                    'type': 'FILE_UPLOAD_DANGEROUS',
                                    'severity': 'CRITICAL',
                                    'confidence': 0.92,
                                    'description': f"Dangerous file upload: {filename} ({magic_name} file)",
                                    'evidence': {
                                        'filename': filename,
                                        'uri': uri,
                                        'extension_pattern': matched_pattern,
                                        'file_type': magic_name,
                                        'file_size': len(file_content),
                                        'content_preview': file_content[:200].hex(),
                                    },
                                    'mitre': ['T1505.003', 'T1105'],
                                    'recommendation': "Block upload and scan server for malicious files.",
                                }

        # Generic dangerous upload (no content analysis)
        self.ip_uploaded_files[src_ip].append(filename)

        return {
            'type': 'FILE_UPLOAD_SUSPICIOUS',
            'severity': 'HIGH',
            'confidence': 0.80,
            'description': f"Suspicious file upload: {filename}",
            'evidence': {
                'filename': filename,
                'uri': uri,
                'pattern': matched_pattern,
            },
            'mitre': ['T1505.003', 'T1105'],
            'recommendation': "Review uploaded file and block if malicious.",
        }

    def _detect_command_execution(self, http_data: Dict) -> Optional[Dict]:
        """Detect command execution via HTTP parameters."""
        uri = http_data.get('uri', '')
        body = http_data.get('body', '')
        src_ip = http_data.get('src_ip', '')

        # Combine URI and body for searching (bytes bodies decoded; also match the
        # percent-decoded form, e.g. "?cmd=cat%20%2Fetc%2Fpasswd")
        from urllib.parse import unquote_plus
        body_text = body if isinstance(body, str) else (body or b'').decode('utf-8', errors='replace')
        raw_text = uri + ' ' + body_text
        decoded_text = unquote_plus(raw_text)
        search_text = raw_text if decoded_text == raw_text else raw_text + ' ' + decoded_text

        commands_found = []

        for pattern in WEBSHELL_SIGNATURES['COMMAND_PATTERNS']:
            matches = cached_regex(pattern, re.IGNORECASE).findall(search_text)
            if matches:
                commands_found.extend(matches)

        if not commands_found:
            return None

        # Track commands
        self.ip_commands_executed[src_ip].extend(commands_found)

        # Determine severity based on command type
        severity = 'MEDIUM'
        if any(cmd in str(commands_found).lower() for cmd in ['passwd', 'shadow', 'wget', 'curl', 'nc', 'bash']):
            severity = 'CRITICAL'
        elif any(cmd in str(commands_found).lower() for cmd in ['powershell', 'cmd.exe', 'net user']):
            severity = 'CRITICAL'

        return {
            'type': 'COMMAND_EXECUTION_HTTP',
            'severity': severity,
            'confidence': 0.88,
            'description': f"Command execution via HTTP: {len(commands_found)} commands detected",
            'evidence': {
                'commands': commands_found[:10],
                'uri': uri[:200],
                'body_preview': body[:200] if body else '',
            },
            'mitre': ['T1059', 'T1505.003'],
            'recommendation': "WebShell is actively executing commands. Immediate isolation required.",
        }

    def _detect_reverse_shell(self, http_data: Dict) -> Optional[Dict]:
        """Detect reverse shell establishment."""
        body = http_data.get('body', '')
        uri = http_data.get('uri', '')

        if not body:
            return None

        body_text = body if isinstance(body, str) else body.decode('utf-8', errors='replace')

        reverse_patterns_found = []

        for pattern in WEBSHELL_SIGNATURES['REVERSE_SHELL']:
            if cached_regex(pattern, re.IGNORECASE).search(body_text):
                reverse_patterns_found.append(pattern)

        if not reverse_patterns_found:
            return None

        # Extract IP:PORT if possible
        ip_port_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', body_text)
        c2_info = ip_port_match.group(0) if ip_port_match else "unknown"

        return {
            'type': 'REVERSE_SHELL_HTTP',
            'severity': 'CRITICAL',
            'confidence': 0.95,
            'description': f"Reverse shell detected targeting: {c2_info}",
            'evidence': {
                'patterns': reverse_patterns_found,
                'c2_target': c2_info,
                'uri': uri,
                'body_preview': body_text[:300],
            },
            'mitre': ['T1071.001', 'T1059'],
            'recommendation': "CRITICAL: Reverse shell active. Block C2 connection and isolate server.",
        }

    def _detect_obfuscation(self, http_data: Dict) -> Optional[Dict]:
        """Detect obfuscated payloads."""
        body = http_data.get('body', '')
        uri = http_data.get('uri', '')

        if not body:
            return None

        body_text = body if isinstance(body, str) else body.decode('utf-8', errors='replace')

        # Count obfuscation layers
        obfuscation_found = []

        for pattern in WEBSHELL_SIGNATURES['PHP_OBFUSCATION']:
            matches = cached_regex(pattern, re.IGNORECASE).findall(body_text)
            if matches:
                obfuscation_found.extend(matches)

        # Check for nested obfuscation (eval inside base64_decode, etc.)
        if re.search(r'eval\s*\(\s*base64_decode', body_text, re.IGNORECASE):
            obfuscation_found.append('eval(base64_decode) chain')

        if re.search(r'eval\s*\(\s*gzinflate', body_text, re.IGNORECASE):
            obfuscation_found.append('eval(gzinflate) chain')

        # Check entropy (high entropy = encrypted/encoded)
        body_bytes = body if isinstance(body, bytes) else body.encode('utf-8', errors='replace')
        body_entropy = entropy(body_bytes)

        if len(obfuscation_found) >= 2 or body_entropy > 7.0:
            return {
                'type': 'OBFUSCATED_PAYLOAD_HTTP',
                'severity': 'HIGH',
                'confidence': 0.85,
                'description': f"Obfuscated payload: {len(obfuscation_found)} encoding layers, entropy={body_entropy:.2f}",
                'evidence': {
                    'obfuscation_methods': list(set(obfuscation_found))[:5],
                    'entropy': body_entropy,
                    'uri': uri,
                    'body_size': len(body_bytes),
                },
                'mitre': ['T1027', 'T1140'],
                'recommendation': "Multi-layer obfuscation indicates advanced malware. Analyze payload carefully.",
            }

        return None

    def _analyze_behavior(self, src_ip: str, http_data: Dict) -> Optional[Dict]:
        """Analyze behavior (timing, frequency, patterns)."""
        if src_ip not in self.ip_activity or len(self.ip_activity[src_ip]) < 5:
            return None

        recent_activity = self.ip_activity[src_ip][-20:]

        # Calculate request rate
        if len(recent_activity) >= 2:
            time_span = recent_activity[-1]['timestamp'] - recent_activity[0]['timestamp']
            if time_span > 0:
                request_rate = len(recent_activity) / time_span  # requests per second

                # Rapid requests to same URI (automation/scanner)
                uris = [a['uri'] for a in recent_activity]
                unique_uris = set(uris)

                if request_rate > 5.0 and len(unique_uris) < 3:
                    return {
                        'type': 'RAPID_HTTP_REQUESTS',
                        'severity': 'MEDIUM',
                        'confidence': 0.75,
                        'description': f"Rapid requests: {request_rate:.1f} req/s to {len(unique_uris)} URIs",
                        'evidence': {
                            'request_rate': request_rate,
                            'unique_uris': len(unique_uris),
                            'sample_uris': list(unique_uris)[:3],
                        },
                        'mitre': ['T1595'],
                        'recommendation': "Automated tool or WebShell automation. Monitor closely.",
                    }

        return None

    def _correlate_attack_chain(self, src_ip: str, http_data: Dict, current_threats: List[Dict]) -> Optional[Dict]:
        """Correlate attack stages (upload -> access -> command)."""
        # Track attack sequence
        for threat in current_threats:
            self.attack_sequences[src_ip].append({
                'timestamp': http_data.get('timestamp', 0),
                'type': threat['type'],
                'uri': http_data.get('uri', ''),
            })

        # Check for complete attack chain
        sequence = self.attack_sequences[src_ip]

        if len(sequence) < 3:
            return None

        # Look for: upload -> access -> command pattern
        types_seen = [s['type'] for s in sequence[-10:]]

        has_upload = any('UPLOAD' in t for t in types_seen)
        has_access = any('WEBSHELL_ACCESS' in t or 'EXECUTION' in t for t in types_seen)
        has_command = any('COMMAND' in t for t in types_seen)

        if has_upload and has_access and has_command:
            return {
                'type': 'ATTACK_CHAIN_WEBSHELL',
                'severity': 'CRITICAL',
                'confidence': 0.95,
                'description': f"Complete WebShell attack chain detected from {src_ip}",
                'evidence': {
                    'attack_stages': len(sequence),
                    'uploaded_files': self.ip_uploaded_files.get(src_ip, []),
                    'commands_executed': self.ip_commands_executed.get(src_ip, [])[:5],
                    'timeline': [f"{s['timestamp']:.0f}: {s['type']}" for s in sequence[-5:]],
                },
                'mitre': ['T1505.003', 'T1059', 'T1105'],
                'recommendation': "FULL ATTACK CHAIN: Upload -> Execution -> Commands. Immediate incident response required.",
            }

        return None

    def get_attack_summary(self, src_ip: str) -> Dict:
        """Summarize the attack activity of a single IP."""
        return {
            'total_requests': len(self.ip_activity.get(src_ip, [])),
            'uploaded_files': self.ip_uploaded_files.get(src_ip, []),
            'commands_executed': self.ip_commands_executed.get(src_ip, []),
            'attack_sequence': self.attack_sequences.get(src_ip, []),
            'threat_level': self._calculate_threat_level(src_ip),
        }

    def _calculate_threat_level(self, src_ip: str) -> str:
        """Calculate threat level based on observed activity."""
        uploaded = len(self.ip_uploaded_files.get(src_ip, []))
        commands = len(self.ip_commands_executed.get(src_ip, []))
        sequence = len(self.attack_sequences.get(src_ip, []))

        if uploaded > 0 and commands > 0:
            return "CRITICAL"
        elif commands > 5:
            return "CRITICAL"
        elif uploaded > 0 or commands > 0:
            return "HIGH"
        elif sequence > 10:
            return "MEDIUM"
        else:
            return "LOW"


# =============================================================================
# INTEGRATION FUNCTIONS
# =============================================================================

def analyze_http_stream_enhanced(http_data: Dict, analyzer: EnhancedHTTPStreamAnalyzer = None) -> Tuple[List[Dict], EnhancedHTTPStreamAnalyzer]:
    """
    Wrapper function for use in analyzer.py

    Args:
        http_data: HTTP request data
        analyzer: Optional existing analyzer instance

    Returns:
        (threats, analyzer_instance)
    """
    if analyzer is None:
        analyzer = EnhancedHTTPStreamAnalyzer()

    threats = analyzer.analyze_http_request(http_data)

    return threats, analyzer


def get_webshell_report(analyzer: EnhancedHTTPStreamAnalyzer, src_ip: str = None) -> str:
    """
    Generate a WebShell report for a specific IP or for all IPs.

    Args:
        analyzer: EnhancedHTTPStreamAnalyzer instance
        src_ip: Optional specific IP to report on

    Returns:
        Formatted report string
    """
    lines = []
    lines.append("=" * 80)
    lines.append("WEBSHELL DETECTION REPORT")
    lines.append("=" * 80)
    lines.append("")

    if src_ip:
        summary = analyzer.get_attack_summary(src_ip)
        lines.append(f"IP: {src_ip}")
        lines.append(f"Threat Level: {summary['threat_level']}")
        lines.append(f"Total Requests: {summary['total_requests']}")
        lines.append(f"Uploaded Files: {len(summary['uploaded_files'])}")
        if summary['uploaded_files']:
            lines.append("  Files:")
            for f in summary['uploaded_files'][:10]:
                lines.append(f"    - {f}")
        lines.append(f"Commands Executed: {len(summary['commands_executed'])}")
        if summary['commands_executed']:
            lines.append("  Commands:")
            for cmd in summary['commands_executed'][:10]:
                lines.append(f"    - {cmd}")
        lines.append("")
    else:
        lines.append("All Attackers Summary:")
        lines.append("")

        for ip in analyzer.ip_activity.keys():
            summary = analyzer.get_attack_summary(ip)
            if summary['threat_level'] in ['CRITICAL', 'HIGH']:
                lines.append(f"  {ip}: {summary['threat_level']}")
                lines.append(f"    Uploads: {len(summary['uploaded_files'])}, Commands: {len(summary['commands_executed'])}")
                lines.append("")

    lines.append("=" * 80)

    return "\n".join(lines)