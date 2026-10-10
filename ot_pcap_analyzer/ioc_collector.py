"""
OT PCAP Analyzer - IOC Collector
=================================
Extract and categorize Indicators of Compromise (IOCs) from analyzer data.
"""

import json
import csv
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

from .ioc_models import IOCRecord
from .constants import MITRE_ATTACK_ICS, MITRE_ATTACK_ENTERPRISE


from .version import VERSION


class IOCCollector:
    """
    Extract and categorize IOCs from OT PCAP analyzer data.

    Extracts:
    - Malicious IP addresses (with risk scores)
    - File hashes (SHA256)
    - Domains and URLs
    - MITRE ATT&CK techniques
    - Network artifacts

    Provides export to JSON and CSV formats.
    """

    def __init__(self):
        """Initialize IOC collector."""
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.pw'}
        # Regex for URL extraction
        self.url_pattern = re.compile(r'https?://[^\s<>"\']+')
        # Regex for domain extraction
        self.domain_pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')

    def extract_iocs(self, analyzer) -> Dict[str, List[IOCRecord]]:
        """
        Extract all IOCs from analyzer data with attack-type categorization.

        Args:
            analyzer: OTAnalyzer instance with completed analysis

        Returns:
            Dictionary with categorized IOCs:
            {
                "malicious_ips": [IOCRecord, ...],
                "file_hashes": [IOCRecord, ...],
                "domains": [IOCRecord, ...],
                "urls": [IOCRecord, ...],
                "mitre_techniques": [IOCRecord, ...],
                "by_attack_type": {attack_type: [IOCRecord, ...], ...}
            }
        """
        if not analyzer:
            return self._empty_iocs()

        iocs = {
            "malicious_ips": self._extract_malicious_ips(analyzer),
            "file_hashes": self._extract_file_hashes(analyzer),
            "mitre_techniques": self._extract_mitre_techniques(analyzer),
        }

        # Extract domains and URLs
        domains, urls = self._extract_domains_urls(analyzer)
        iocs["domains"] = domains
        iocs["urls"] = urls

        # Extract IOCs by attack type for better evaluation
        iocs["by_attack_type"] = self._extract_iocs_by_attack_type(analyzer)

        return iocs

    def _extract_iocs_by_attack_type(self, analyzer) -> Dict[str, List[IOCRecord]]:
        """
        Extract IOCs categorized by attack type for better evaluation.

        This helps security analysts understand which IOCs are associated
        with which types of attacks, enabling better threat assessment.
        """
        attack_iocs = defaultdict(list)

        # Get attack-specific IOCs from threat detector if available
        if hasattr(analyzer, 'threat_detector'):
            detector = analyzer.threat_detector
            if hasattr(detector, 'get_iocs_by_attack_type'):
                raw_iocs = detector.get_iocs_by_attack_type()
                for attack_type, ioc_list in raw_iocs.items():
                    for ioc_data in ioc_list:
                        ioc_record = self._convert_to_ioc_record(attack_type, ioc_data)
                        if ioc_record:
                            attack_iocs[attack_type].append(ioc_record)

        # Also extract from anomalies grouped by type
        if hasattr(analyzer, 'anomalies'):
            anomaly_groups = defaultdict(list)
            for anomaly in analyzer.anomalies:
                atype = getattr(anomaly, 'anomaly_type', 'UNKNOWN')
                # Normalize attack type
                attack_category = self._categorize_attack(atype)
                anomaly_groups[attack_category].append(anomaly)

            for attack_category, anomalies in anomaly_groups.items():
                for anomaly in anomalies:
                    # Extract IP IOC
                    src_ip = getattr(anomaly, 'src_ip', '')
                    if src_ip and src_ip not in ['Multiple', 'Network', '']:
                        ioc_record = IOCRecord(
                            ioc_type="IP",
                            value=src_ip,
                            severity=getattr(anomaly, 'severity', 'MEDIUM'),
                            first_seen=getattr(anomaly, 'timestamp', 0.0),
                            last_seen=getattr(anomaly, 'timestamp', 0.0),
                            occurrences=1,
                            context=attack_category,
                            associated_ips=[],
                            description=f"Source IP in {attack_category} attack",
                            risk_score=getattr(anomaly, 'confidence', 0.7),
                            techniques=getattr(anomaly, 'mitre_techniques', []),
                        )
                        # Avoid duplicates
                        existing = [i for i in attack_iocs[attack_category] if i.value == src_ip]
                        if existing:
                            existing[0].occurrences += 1
                            existing[0].last_seen = max(existing[0].last_seen, ioc_record.first_seen)
                        else:
                            attack_iocs[attack_category].append(ioc_record)

        return dict(attack_iocs)

    def _categorize_attack(self, anomaly_type: str) -> str:
        """Categorize anomaly type into broader attack category."""
        atype = anomaly_type.upper()

        if 'WEBSHELL' in atype or 'SHELL' in atype:
            return 'WEBSHELL'
        elif 'SQL' in atype or 'INJECTION' in atype:
            return 'SQL_INJECTION'
        elif 'XSS' in atype:
            return 'XSS'
        elif 'SCAN' in atype or 'PORT_SCAN' in atype:
            return 'PORT_SCAN'
        elif 'DNS' in atype and 'TUNNEL' in atype:
            return 'DNS_TUNNELING'
        elif 'ARP' in atype and 'SPOOF' in atype:
            return 'ARP_SPOOFING'
        elif 'C2' in atype or 'BEACON' in atype:
            return 'C2_BEACON'
        elif 'EXFIL' in atype:
            return 'DATA_EXFILTRATION'
        elif 'BRUTE' in atype:
            return 'BRUTE_FORCE'
        elif 'LATERAL' in atype or 'SMB' in atype:
            return 'LATERAL_MOVEMENT'
        elif 'HTTP' in atype:
            return 'HTTP_ATTACK'
        elif 'MODBUS' in atype or 'S7' in atype or 'PLC' in atype or 'DNP3' in atype:
            return 'OT_PROTOCOL_ATTACK'
        else:
            return 'OTHER'

    def _convert_to_ioc_record(self, attack_type: str, ioc_data: Dict) -> Optional[IOCRecord]:
        """Convert raw IOC data to IOCRecord."""
        try:
            ip = ioc_data.get('ip', ioc_data.get('src_ip', ''))
            if not ip:
                return None

            return IOCRecord(
                ioc_type="IP",
                value=ip,
                severity=ioc_data.get('severity', 'MEDIUM'),
                first_seen=ioc_data.get('timestamp', 0.0),
                last_seen=ioc_data.get('timestamp', 0.0),
                occurrences=1,
                context=attack_type,
                # associated_ips holds IP strings only; scanned ports go in the description
                associated_ips=[str(x) for x in ioc_data.get('targets', [])][:5] if 'targets' in ioc_data else [],
                description=(f"IOC from {attack_type}: {ioc_data.get('pattern', '')}"
                             + (f" (ports: {', '.join(str(p) for p in list(ioc_data.get('ports', []))[:10])})"
                                if ioc_data.get('ports') else "")),
                risk_score=ioc_data.get('confidence', 0.7),
                techniques=[],
            )
        except Exception:
            return None

    def _empty_iocs(self) -> Dict[str, List[IOCRecord]]:
        """Return empty IOCs structure."""
        return {
            "malicious_ips": [],
            "file_hashes": [],
            "domains": [],
            "urls": [],
            "mitre_techniques": [],
        }

    def _extract_malicious_ips(self, analyzer) -> List[IOCRecord]:
        """
        Extract malicious IP addresses from analyzer.

        Criteria: risk_score >= 0.5
        """
        ioc_records = []

        # Get IP risk scores from threat detector
        if not hasattr(analyzer, 'threat_detector'):
            return ioc_records

        ip_risk_scores = getattr(analyzer.threat_detector, 'ip_risk_scores', {})
        ip_violations = getattr(analyzer.threat_detector, 'ip_violations', {})

        for ip, risk_score in ip_risk_scores.items():
            if risk_score < 0.5:  # Only include malicious IPs
                continue

            # Determine severity based on risk score
            if risk_score >= 0.9:
                severity = "CRITICAL"
            elif risk_score >= 0.7:
                severity = "HIGH"
            elif risk_score >= 0.5:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Get violations for this IP
            violations = ip_violations.get(ip, [])
            violation_types = set()
            first_seen = float('inf')
            last_seen = 0.0

            for v in violations:
                if isinstance(v, dict):
                    v_type = v.get('type', '')
                    if v_type:
                        violation_types.add(v_type)
                    v_time = v.get('timestamp', 0.0)
                    if v_time:
                        first_seen = min(first_seen, v_time)
                        last_seen = max(last_seen, v_time)

            # Default timestamps if no violations
            if first_seen == float('inf'):
                first_seen = 0.0
            if last_seen == 0.0:
                last_seen = first_seen

            # Build description
            if violation_types:
                desc_en = f"Malicious activity detected: {', '.join(list(violation_types)[:3])}"
            else:
                desc_en = "High-risk IP address detected"

            # Find associated chains
            context_chains = []
            if hasattr(analyzer, 'attack_chains'):
                for chain in analyzer.attack_chains:
                    src_ips = getattr(chain, 'source_ips', set())
                    tgt_ips = getattr(chain, 'target_ips', set())
                    if ip in src_ips or ip in tgt_ips:
                        chain_id = getattr(chain, 'chain_id', '')
                        if chain_id:
                            context_chains.append(chain_id)

            context = ", ".join(context_chains[:3]) if context_chains else "Network Scan"

            ioc_record = IOCRecord(
                ioc_type="IP",
                value=ip,
                severity=severity,
                first_seen=first_seen,
                last_seen=last_seen,
                occurrences=len(violations),
                context=context,
                associated_ips=[],  # IPs don't have associated IPs
                description=desc_en,
                risk_score=risk_score,
                techniques=[],
            )
            ioc_records.append(ioc_record)

        # Sort by risk score descending
        ioc_records.sort(key=lambda x: x.risk_score, reverse=True)

        return ioc_records

    def _extract_file_hashes(self, analyzer) -> List[IOCRecord]:
        """
        Extract file hashes (SHA256) from suspicious payloads.
        """
        ioc_records = []
        seen_hashes = set()

        # Extract from decoded payloads
        if hasattr(analyzer, 'threat_detector') and hasattr(analyzer.threat_detector, 'decoded_payloads'):
            for payload in analyzer.threat_detector.decoded_payloads:
                sha256 = getattr(payload, 'sha256_hash', '')
                if not sha256 or sha256 in seen_hashes:
                    continue
                seen_hashes.add(sha256)

                detected_type = getattr(payload, 'detected_type', 'UNKNOWN')
                risk_level = getattr(payload, 'risk_level', 'MEDIUM')
                timestamp = getattr(payload, 'timestamp', 0.0)
                src_ip = getattr(payload, 'src_ip', '')
                dst_ip = getattr(payload, 'dst_ip', '')
                behavior_summary = getattr(payload, 'behavior_summary', '')

                # Map risk level to severity
                severity_map = {
                    'CRITICAL': 'CRITICAL',
                    'HIGH': 'HIGH',
                    'MEDIUM': 'MEDIUM',
                    'LOW': 'LOW',
                }
                severity = severity_map.get(risk_level, 'MEDIUM')

                # Build description
                desc_en = f"Suspicious payload ({detected_type}): {behavior_summary[:100]}"

                # Payload preview
                final_payload = getattr(payload, 'final_payload', b'')
                if final_payload:
                    try:
                        preview = final_payload[:200].decode('utf-8', errors='replace')
                    except:
                        preview = final_payload[:200].hex()
                else:
                    preview = ""

                ioc_record = IOCRecord(
                    ioc_type="HASH",
                    value=sha256[:64],  # Full SHA256
                    severity=severity,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    occurrences=1,
                    context=detected_type,
                    associated_ips=[ip for ip in [src_ip, dst_ip] if ip],
                    description=desc_en,
                    risk_score=0.0,
                    techniques=[],
                    payload_preview=preview,
                )
                ioc_records.append(ioc_record)

        # Extract from anomalies with extracted_payload
        if hasattr(analyzer, 'anomalies'):
            for anomaly in analyzer.anomalies:
                extracted_payload = getattr(anomaly, 'extracted_payload', None)
                if not extracted_payload:
                    continue

                sha256 = getattr(extracted_payload, 'sha256_hash', '')
                if not sha256 or sha256 in seen_hashes:
                    continue
                seen_hashes.add(sha256)

                payload_type = getattr(extracted_payload, 'payload_type', 'UNKNOWN')
                detection_reason = getattr(extracted_payload, 'detection_reason', '')
                timestamp = getattr(anomaly, 'timestamp', 0.0)
                src_ip = getattr(anomaly, 'src_ip', '')
                dst_ip = getattr(anomaly, 'dst_ip', '')
                severity = getattr(anomaly, 'severity', 'MEDIUM')

                desc_en = f"Extracted from anomaly: {detection_reason[:100]}"

                # Payload preview
                payload_data = getattr(extracted_payload, 'payload_data', b'')
                if payload_data:
                    try:
                        preview = payload_data[:200].decode('utf-8', errors='replace')
                    except:
                        preview = payload_data[:200].hex()
                else:
                    preview = ""

                ioc_record = IOCRecord(
                    ioc_type="HASH",
                    value=sha256[:64],
                    severity=severity,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    occurrences=1,
                    context=payload_type,
                    associated_ips=[ip for ip in [src_ip, dst_ip] if ip],
                    description=desc_en,
                    risk_score=0.0,
                    techniques=[],
                    payload_preview=preview,
                )
                ioc_records.append(ioc_record)

        return ioc_records

    def _extract_mitre_techniques(self, analyzer) -> List[IOCRecord]:
        """
        Extract MITRE ATT&CK techniques from anomalies and attack chains.
        """
        technique_data = defaultdict(lambda: {
            'occurrences': 0,
            'severity': 'LOW',
            'first_seen': float('inf'),
            'last_seen': 0.0,
            'contexts': set(),
            'associated_ips': set(),
        })

        # Extract from anomalies
        if hasattr(analyzer, 'anomalies'):
            for anomaly in analyzer.anomalies:
                techniques = getattr(anomaly, 'mitre_techniques', [])
                timestamp = getattr(anomaly, 'timestamp', 0.0)
                severity = getattr(anomaly, 'severity', 'MEDIUM')
                src_ip = getattr(anomaly, 'src_ip', '')
                dst_ip = getattr(anomaly, 'dst_ip', '')
                anomaly_type = getattr(anomaly, 'anomaly_type', '')

                for technique in techniques:
                    if not technique:
                        continue

                    data = technique_data[technique]
                    data['occurrences'] += 1
                    data['first_seen'] = min(data['first_seen'], timestamp)
                    data['last_seen'] = max(data['last_seen'], timestamp)
                    data['contexts'].add(anomaly_type)

                    if src_ip:
                        data['associated_ips'].add(src_ip)
                    if dst_ip:
                        data['associated_ips'].add(dst_ip)

                    # Upgrade severity if needed
                    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                    current_sev = severity_order.get(data['severity'], 1)
                    new_sev = severity_order.get(severity, 1)
                    if new_sev > current_sev:
                        data['severity'] = severity

        # Extract from attack chains
        if hasattr(analyzer, 'attack_chains'):
            for chain in analyzer.attack_chains:
                all_techniques = getattr(chain, 'all_techniques', set())
                chain_id = getattr(chain, 'chain_id', '')
                start_time = getattr(chain, 'start_time', 0.0)
                end_time = getattr(chain, 'end_time', start_time)
                severity = getattr(chain, 'overall_severity', 'MEDIUM')
                source_ips = getattr(chain, 'source_ips', set())

                for technique in all_techniques:
                    if not technique:
                        continue

                    data = technique_data[technique]
                    data['occurrences'] += 1
                    data['first_seen'] = min(data['first_seen'], start_time)
                    data['last_seen'] = max(data['last_seen'], end_time)
                    data['contexts'].add(f"CHAIN:{chain_id}")

                    for ip in source_ips:
                        if ip:
                            data['associated_ips'].add(ip)

                    # Upgrade severity
                    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                    current_sev = severity_order.get(data['severity'], 1)
                    new_sev = severity_order.get(severity, 1)
                    if new_sev > current_sev:
                        data['severity'] = severity

        # Build IOC records
        ioc_records = []
        for technique, data in technique_data.items():
            if data['first_seen'] == float('inf'):
                data['first_seen'] = 0.0

            # Get technique description from constants
            technique_name = ""
            technique_desc = ""

            # Try OT techniques first
            if technique in MITRE_ATTACK_ICS:
                technique_name = MITRE_ATTACK_ICS[technique]  # String value
                technique_desc = f"ICS/OT Technique: {technique}"
            # Then enterprise techniques
            elif technique in MITRE_ATTACK_ENTERPRISE:
                technique_name = MITRE_ATTACK_ENTERPRISE[technique]  # String value
                technique_desc = f"Enterprise Technique: {technique}"
            else:
                technique_name = technique
                technique_desc = "Unknown MITRE technique"

            desc_en = f"{technique_name}" if not technique_desc else f"{technique_name} - {technique_desc}"

            context = ", ".join(list(data['contexts'])[:5])

            ioc_record = IOCRecord(
                ioc_type="MITRE_TECHNIQUE",
                value=technique,
                severity=data['severity'],
                first_seen=data['first_seen'],
                last_seen=data['last_seen'],
                occurrences=data['occurrences'],
                context=context,
                associated_ips=list(data['associated_ips'])[:10],
                description=desc_en,
                risk_score=0.0,
                techniques=[technique],
            )
            ioc_records.append(ioc_record)

        # Sort by occurrences descending
        ioc_records.sort(key=lambda x: x.occurrences, reverse=True)

        return ioc_records

    def _extract_domains_urls(self, analyzer) -> Tuple[List[IOCRecord], List[IOCRecord]]:
        """
        Extract domains and URLs from HTTP traffic and anomalies.

        Returns:
            Tuple of (domains, urls)
        """
        domain_data = defaultdict(lambda: {
            'occurrences': 0,
            'severity': 'LOW',
            'first_seen': float('inf'),
            'last_seen': 0.0,
            'associated_ips': set(),
            'suspicious': False,
        })

        url_data = defaultdict(lambda: {
            'occurrences': 0,
            'severity': 'LOW',
            'first_seen': float('inf'),
            'last_seen': 0.0,
            'associated_ips': set(),
        })

        # Extract from anomalies (HTTP attacks)
        if hasattr(analyzer, 'anomalies'):
            for anomaly in analyzer.anomalies:
                timestamp = getattr(anomaly, 'timestamp', 0.0)
                severity = getattr(anomaly, 'severity', 'MEDIUM')
                src_ip = getattr(anomaly, 'src_ip', '')
                dst_ip = getattr(anomaly, 'dst_ip', '')
                evidence = getattr(anomaly, 'evidence', {})

                if not isinstance(evidence, dict):
                    continue

                # Extract host/domain from HTTP headers
                host = evidence.get('host', '') or evidence.get('Host', '')
                if host:
                    # Clean host (remove port)
                    domain = host.split(':')[0].strip()
                    if domain and self._is_valid_domain(domain):
                        data = domain_data[domain]
                        data['occurrences'] += 1
                        data['first_seen'] = min(data['first_seen'], timestamp)
                        data['last_seen'] = max(data['last_seen'], timestamp)

                        if src_ip:
                            data['associated_ips'].add(src_ip)
                        if dst_ip:
                            data['associated_ips'].add(dst_ip)

                        # Mark as suspicious if anomaly severity is high
                        if severity in ['CRITICAL', 'HIGH']:
                            data['suspicious'] = True
                            data['severity'] = severity

                # Extract URI/URL
                uri = evidence.get('uri', '') or evidence.get('URI', '')
                if uri and host:
                    # Build full URL
                    if not uri.startswith('http'):
                        full_url = f"http://{host}{uri}"
                    else:
                        full_url = uri

                    if len(full_url) < 500:  # Reasonable URL length
                        data = url_data[full_url]
                        data['occurrences'] += 1
                        data['first_seen'] = min(data['first_seen'], timestamp)
                        data['last_seen'] = max(data['last_seen'], timestamp)

                        if src_ip:
                            data['associated_ips'].add(src_ip)
                        if dst_ip:
                            data['associated_ips'].add(dst_ip)

                        data['severity'] = severity

        # Build domain IOC records
        domain_records = []
        for domain, data in domain_data.items():
            if data['first_seen'] == float('inf'):
                data['first_seen'] = 0.0

            # Check if domain has suspicious TLD
            has_suspicious_tld = any(domain.endswith(tld) for tld in self.suspicious_tlds)

            if has_suspicious_tld and data['severity'] == 'LOW':
                data['severity'] = 'MEDIUM'
                data['suspicious'] = True

            desc_en = f"Domain accessed: {domain}"
            if data['suspicious'] or has_suspicious_tld:
                desc_en += " (Suspicious)"

            ioc_record = IOCRecord(
                ioc_type="DOMAIN",
                value=domain,
                severity=data['severity'],
                first_seen=data['first_seen'],
                last_seen=data['last_seen'],
                occurrences=data['occurrences'],
                context="HTTP Traffic",
                associated_ips=list(data['associated_ips'])[:10],
                description=desc_en,
                risk_score=0.0,
                techniques=[],
            )
            domain_records.append(ioc_record)

        # Build URL IOC records
        url_records = []
        for url, data in url_data.items():
            if data['first_seen'] == float('inf'):
                data['first_seen'] = 0.0

            # Check for suspicious patterns in URL
            suspicious_patterns = [
                'cmd=', 'exec=', '../', '..\\', '<script', 'eval(',
                'base64', 'shell', '/etc/passwd', '/etc/shadow'
            ]
            has_suspicious_pattern = any(pattern in url.lower() for pattern in suspicious_patterns)

            if has_suspicious_pattern and data['severity'] in ['LOW', 'MEDIUM']:
                data['severity'] = 'HIGH'

            # Truncate URL for description
            display_url = url if len(url) < 100 else url[:97] + "..."

            desc_en = f"URL accessed: {display_url}"

            ioc_record = IOCRecord(
                ioc_type="URL",
                value=url,
                severity=data['severity'],
                first_seen=data['first_seen'],
                last_seen=data['last_seen'],
                occurrences=data['occurrences'],
                context="HTTP Traffic",
                associated_ips=list(data['associated_ips'])[:10],
                description=desc_en,
                risk_score=0.0,
                techniques=[],
            )
            url_records.append(ioc_record)

        # Sort by occurrences
        domain_records.sort(key=lambda x: x.occurrences, reverse=True)
        url_records.sort(key=lambda x: x.occurrences, reverse=True)

        return domain_records, url_records

    def _is_valid_domain(self, domain: str) -> bool:
        """Check if string is a valid domain name."""
        if not domain or len(domain) > 253:
            return False
        # Exclude IP addresses
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return False
        # Basic domain pattern check
        return bool(self.domain_pattern.match(domain))

    def export_to_json(self, iocs: Dict[str, List[IOCRecord]], filepath: str, analyzer_version: str = VERSION, pcap_file: str = ""):
        """
        Export IOCs to JSON format.

        Args:
            iocs: Dictionary of categorized IOCs
            filepath: Output file path
            analyzer_version: Version string
            pcap_file: PCAP filename
        """
        total_iocs = sum(len(ioc_list) for ioc_list in iocs.values() if isinstance(ioc_list, list))

        export_data = {
            "export_metadata": {
                "timestamp": datetime.now().isoformat(),
                "analyzer_version": analyzer_version,
                "pcap_file": pcap_file,
                "total_iocs": total_iocs,
            },
            "malicious_ips": [ioc.to_dict() for ioc in iocs.get("malicious_ips", [])],
            "file_hashes": [ioc.to_dict() for ioc in iocs.get("file_hashes", [])],
            "domains": [ioc.to_dict() for ioc in iocs.get("domains", [])],
            "urls": [ioc.to_dict() for ioc in iocs.get("urls", [])],
            "mitre_techniques": [ioc.to_dict() for ioc in iocs.get("mitre_techniques", [])],
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

    def export_to_csv(self, iocs: Dict[str, List[IOCRecord]], filepath: str):
        """
        Export IOCs to CSV format (flat structure).

        Args:
            iocs: Dictionary of categorized IOCs
            filepath: Output file path
        """
        # Flatten all IOCs into single list
        # Only the categorized IOCRecord lists; other entries (e.g. the
        # 'by_attack_type' summary dict) are not IOC records.
        all_iocs = []
        for ioc_list in iocs.values():
            if isinstance(ioc_list, list):
                all_iocs.extend(ioc for ioc in ioc_list if hasattr(ioc, "to_csv_row"))

        # Write CSV
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow(IOCRecord.csv_header())

            # Write rows
            for ioc in all_iocs:
                writer.writerow(ioc.to_csv_row())
