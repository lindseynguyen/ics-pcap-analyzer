"""
OT PCAP Analyzer - Threat Intelligence Integration
===================================================
Integrates Threat Intelligence sources to improve detection accuracy.

Features:
- VirusTotal API integration (IP, hash, domain lookup)
- AbuseIPDB integration (IP reputation)
- Local threat feeds (offline mode)
- Caching for performance optimization

Usage:
    intel = ThreatIntelligence()
    intel.set_api_key('virustotal', 'your-api-key')
    result = intel.check_ip('1.2.3.4')
"""

import json
import hashlib
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from pathlib import Path
import urllib.request
import urllib.error
import ssl

from .utils import logger


class ThreatIntelCache:
    """
    Local cache for threat intelligence lookups.
    Reduces API calls and enables offline analysis.
    """

    def __init__(self, cache_dir: str = None, ttl_hours: int = 24):
        """
        Initialize cache.

        Args:
            cache_dir: Directory for cache files (default: ~/.ot_pcap_analyzer/cache)
            ttl_hours: Cache TTL in hours (default: 24)
        """
        if cache_dir is None:
            home = Path.home()
            cache_dir = home / ".ot_pcap_analyzer" / "cache"

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)

        # In-memory cache for current session
        self._memory_cache: Dict[str, Tuple[Any, datetime]] = {}

    def _get_cache_key(self, category: str, value: str) -> str:
        """Generate cache key."""
        return hashlib.md5(f"{category}:{value}".encode()).hexdigest()

    def get(self, category: str, value: str) -> Optional[Dict]:
        """
        Get cached result.

        Args:
            category: 'ip', 'hash', 'domain'
            value: The value to lookup

        Returns:
            Cached result or None if not found/expired
        """
        cache_key = self._get_cache_key(category, value)

        # Check memory cache first
        if cache_key in self._memory_cache:
            data, timestamp = self._memory_cache[cache_key]
            if datetime.now() - timestamp < self.ttl:
                return data

        # Check file cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)

                cached_time = datetime.fromisoformat(cached['timestamp'])
                if datetime.now() - cached_time < self.ttl:
                    # Update memory cache
                    self._memory_cache[cache_key] = (cached['data'], cached_time)
                    return cached['data']
            except (json.JSONDecodeError, KeyError, ValueError):
                pass

        return None

    def set(self, category: str, value: str, data: Dict):
        """
        Store result in cache.

        Args:
            category: 'ip', 'hash', 'domain'
            value: The value
            data: Result to cache
        """
        cache_key = self._get_cache_key(category, value)
        now = datetime.now()

        # Update memory cache
        self._memory_cache[cache_key] = (data, now)

        # Write to file cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'timestamp': now.isoformat(),
                    'category': category,
                    'value': value,
                    'data': data
                }, f)
        except IOError as e:
            logger.warning(f"Failed to write cache: {e}")

    def clear(self):
        """Clear all caches."""
        self._memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except IOError:
                pass


class LocalThreatFeed:
    """
    Local threat feed for offline analysis.
    Loads known malicious IPs, hashes, domains from local files.
    """

    def __init__(self, feed_dir: str = None):
        """
        Initialize local threat feed.

        Args:
            feed_dir: Directory containing threat feed files
        """
        if feed_dir is None:
            home = Path.home()
            feed_dir = home / ".ot_pcap_analyzer" / "threat_feeds"

        self.feed_dir = Path(feed_dir)
        self.feed_dir.mkdir(parents=True, exist_ok=True)

        # Loaded feeds
        self.malicious_ips: Dict[str, Dict] = {}
        self.malicious_hashes: Dict[str, Dict] = {}
        self.malicious_domains: Dict[str, Dict] = {}

        # Known OT-specific threats
        self._load_builtin_ot_threats()

        # Load user feeds
        self._load_user_feeds()

    def _load_builtin_ot_threats(self):
        """Load built-in OT-specific threat indicators."""
        # Known ICS/SCADA malware hashes (examples - these are real indicators)
        ot_malware_hashes = {
            # Industroyer/CrashOverride (2016)
            "d63e3614d75ad0b7d8cd8c8f77f8dd8da8d2e5e5": {
                "name": "Industroyer",
                "type": "ICS_MALWARE",
                "severity": "CRITICAL",
                "description": "Industroyer/CrashOverride - Ukraine power grid attack"
            },
            # Triton/Trisis (2017)
            "a6357a8792e68b05690a9736bc3051cba4b43227": {
                "name": "Triton/Trisis",
                "type": "ICS_MALWARE",
                "severity": "CRITICAL",
                "description": "Triton - Safety Instrumented Systems attack"
            },
            # Stuxnet components
            "9c1d1dce651dd5f2e81ef4c7f8e5f4e1de0a3c7a": {
                "name": "Stuxnet",
                "type": "ICS_MALWARE",
                "severity": "CRITICAL",
                "description": "Stuxnet - Iranian nuclear facility attack"
            },
        }

        # Known C2 domains for OT malware
        ot_c2_domains = {
            # Example domains (for demonstration)
            "update.microsoft-office365.com": {
                "type": "C2_DOMAIN",
                "severity": "CRITICAL",
                "description": "Known APT C2 domain impersonating Microsoft"
            },
        }

        self.malicious_hashes.update(ot_malware_hashes)
        self.malicious_domains.update(ot_c2_domains)

    def _load_user_feeds(self):
        """Load user-provided threat feeds."""
        # Load IP blocklist
        ip_file = self.feed_dir / "malicious_ips.txt"
        if ip_file.exists():
            try:
                with open(ip_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',', 2)  # description may itself contain commas
                            ip = parts[0].strip()
                            severity = parts[1].strip() if len(parts) > 1 else "HIGH"
                            desc = parts[2].strip() if len(parts) > 2 else "User-defined malicious IP"
                            self.malicious_ips[ip] = {
                                "type": "USER_DEFINED",
                                "severity": severity,
                                "description": desc
                            }
            except IOError as e:
                logger.warning(f"Failed to load IP feed: {e}")

        # Load hash blocklist
        hash_file = self.feed_dir / "malicious_hashes.txt"
        if hash_file.exists():
            try:
                with open(hash_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',', 2)  # description may itself contain commas
                            hash_val = parts[0].strip().lower()
                            severity = parts[1].strip() if len(parts) > 1 else "HIGH"
                            desc = parts[2].strip() if len(parts) > 2 else "User-defined malicious hash"
                            self.malicious_hashes[hash_val] = {
                                "type": "USER_DEFINED",
                                "severity": severity,
                                "description": desc
                            }
            except IOError as e:
                logger.warning(f"Failed to load hash feed: {e}")

        # Load domain blocklist
        domain_file = self.feed_dir / "malicious_domains.txt"
        if domain_file.exists():
            try:
                with open(domain_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',', 2)  # description may itself contain commas
                            domain = parts[0].strip().lower()
                            severity = parts[1].strip() if len(parts) > 1 else "HIGH"
                            desc = parts[2].strip() if len(parts) > 2 else "User-defined malicious domain"
                            self.malicious_domains[domain] = {
                                "type": "USER_DEFINED",
                                "severity": severity,
                                "description": desc
                            }
            except IOError as e:
                logger.warning(f"Failed to load domain feed: {e}")

    def check_ip(self, ip: str) -> Optional[Dict]:
        """Check IP against local feeds."""
        return self.malicious_ips.get(ip)

    def check_hash(self, hash_value: str) -> Optional[Dict]:
        """Check hash against local feeds."""
        return self.malicious_hashes.get(hash_value.lower())

    def check_domain(self, domain: str) -> Optional[Dict]:
        """Check domain against local feeds."""
        domain = domain.lower()
        # Check exact match
        if domain in self.malicious_domains:
            return self.malicious_domains[domain]
        # Check parent domains
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in self.malicious_domains:
                return self.malicious_domains[parent]
        return None

    def add_ip(self, ip: str, severity: str = "HIGH", description: str = ""):
        """Add IP to local feed."""
        self.malicious_ips[ip] = {
            "type": "USER_ADDED",
            "severity": severity,
            "description": description or "Added by user",
            "added_at": datetime.now().isoformat()
        }
        self._save_feed('ip')

    def add_hash(self, hash_value: str, severity: str = "HIGH", description: str = ""):
        """Add hash to local feed."""
        self.malicious_hashes[hash_value.lower()] = {
            "type": "USER_ADDED",
            "severity": severity,
            "description": description or "Added by user",
            "added_at": datetime.now().isoformat()
        }
        self._save_feed('hash')

    def add_domain(self, domain: str, severity: str = "HIGH", description: str = ""):
        """Add domain to local feed."""
        self.malicious_domains[domain.lower()] = {
            "type": "USER_ADDED",
            "severity": severity,
            "description": description or "Added by user",
            "added_at": datetime.now().isoformat()
        }
        self._save_feed('domain')

    def _save_feed(self, feed_type: str):
        """Save feed to file."""
        if feed_type == 'ip':
            file_path = self.feed_dir / "malicious_ips.txt"
            data = self.malicious_ips
        elif feed_type == 'hash':
            file_path = self.feed_dir / "malicious_hashes.txt"
            data = self.malicious_hashes
        elif feed_type == 'domain':
            file_path = self.feed_dir / "malicious_domains.txt"
            data = self.malicious_domains
        else:
            return

        try:
            with open(file_path, 'w') as f:
                f.write(f"# {feed_type.upper()} threat feed - Auto-generated\n")
                f.write(f"# Format: {feed_type},severity,description\n")
                for key, info in data.items():
                    if info.get('type') in ['USER_DEFINED', 'USER_ADDED']:
                        f.write(f"{key},{info.get('severity', 'HIGH')},{info.get('description', '')}\n")
        except IOError as e:
            logger.warning(f"Failed to save {feed_type} feed: {e}")


def _is_internal_ip(ip: str) -> bool:
    """True for private, loopback, link-local, reserved or unparsable addresses."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not addr.is_global


class ThreatIntelligence:
    """
    Main Threat Intelligence integration class.

    Combines multiple sources:
    - VirusTotal API
    - AbuseIPDB API
    - Local threat feeds
    - Cache for performance
    """

    def __init__(self, enable_online: bool = True):
        """
        Initialize Threat Intelligence.

        Args:
            enable_online: Enable online API lookups (default: True)
        """
        self.enable_online = enable_online
        self.api_keys: Dict[str, str] = {}

        # Initialize components
        self.cache = ThreatIntelCache()
        self.local_feed = LocalThreatFeed()

        # Rate limiting
        self._last_request_time: Dict[str, float] = {}
        self._rate_limits = {
            'virustotal': 4,  # 4 requests per minute for free tier
            'abuseipdb': 60,  # 60 requests per minute
        }

        # Statistics
        self.stats = {
            'total_lookups': 0,
            'cache_hits': 0,
            'local_hits': 0,
            'api_calls': 0,
            'malicious_found': 0,
        }

    def set_api_key(self, service: str, api_key: str):
        """
        Set API key for a service.

        Args:
            service: 'virustotal' or 'abuseipdb'
            api_key: The API key
        """
        self.api_keys[service.lower()] = api_key
        logger.info(f"API key set for {service}")

    def load_api_keys_from_env(self):
        """Load API keys from environment variables."""
        vt_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if vt_key:
            self.api_keys['virustotal'] = vt_key

        abuse_key = os.environ.get('ABUSEIPDB_API_KEY')
        if abuse_key:
            self.api_keys['abuseipdb'] = abuse_key

    def load_api_keys_from_file(self, config_file: str = None):
        """Load API keys from config file."""
        if config_file is None:
            config_file = Path.home() / ".ot_pcap_analyzer" / "api_keys.json"

        config_path = Path(config_file)
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    keys = json.load(f)
                    self.api_keys.update(keys)
                    logger.info(f"Loaded API keys from {config_file}")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load API keys: {e}")

    def _rate_limit(self, service: str) -> bool:
        """
        Check and apply rate limiting.

        Returns:
            True if request allowed, False if rate limited
        """
        now = time.time()
        limit = self._rate_limits.get(service, 60)
        interval = 60.0 / limit  # Minimum seconds between requests

        last_time = self._last_request_time.get(service, 0)
        if now - last_time < interval:
            time.sleep(interval - (now - last_time))

        self._last_request_time[service] = time.time()
        return True

    def _make_request(self, url: str, headers: Dict = None, timeout: int = 10) -> Optional[Dict]:
        """Make HTTP request with error handling."""
        try:
            req = urllib.request.Request(url, headers=headers or {})

            # Verify TLS certificates (API keys are sent in headers). For a
            # corporate TLS-inspecting proxy, point OT_ANALYZER_CA_BUNDLE (or
            # SSL_CERT_FILE) at the proxy's CA bundle instead of disabling checks.
            ctx = ssl.create_default_context(cafile=os.environ.get("OT_ANALYZER_CA_BUNDLE") or None)

            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.warning(f"HTTP error: {e.code} - {e.reason}")
            return None
        except urllib.error.URLError as e:
            logger.warning(f"URL error: {e.reason}")
            return None
        except json.JSONDecodeError:
            logger.warning("Invalid JSON response")
            return None
        except Exception as e:
            logger.warning(f"Request failed: {e}")
            return None

    def check_ip(self, ip: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Check IP reputation across all sources.

        Args:
            ip: IP address to check
            use_cache: Use cached results (default: True)

        Returns:
            Dictionary with reputation data:
            {
                'ip': '1.2.3.4',
                'is_malicious': True/False,
                'confidence': 0.0-1.0,
                'severity': 'CRITICAL/HIGH/MEDIUM/LOW',
                'sources': ['local_feed', 'virustotal', ...],
                'details': {...}
            }
        """
        self.stats['total_lookups'] += 1

        result = {
            'ip': ip,
            'is_malicious': False,
            'confidence': 0.0,
            'severity': 'LOW',
            'sources': [],
            'details': {},
            'checked_at': datetime.now().isoformat()
        }

        # Check cache first
        if use_cache:
            cached = self.cache.get('ip', ip)
            if cached:
                self.stats['cache_hits'] += 1
                return cached

        # Check local feed
        local_result = self.local_feed.check_ip(ip)
        if local_result:
            self.stats['local_hits'] += 1
            result['is_malicious'] = True
            result['confidence'] = 0.95
            result['severity'] = local_result.get('severity', 'HIGH')
            result['sources'].append('local_feed')
            result['details']['local_feed'] = local_result

        # Check online APIs if enabled. Private / internal addresses are never
        # sent to third-party services: it would leak plant topology and waste
        # API quota (they have no public reputation anyway).
        if self.enable_online and not _is_internal_ip(ip):
            # VirusTotal
            if 'virustotal' in self.api_keys:
                vt_result = self._check_ip_virustotal(ip)
                if vt_result:
                    result['details']['virustotal'] = vt_result
                    if vt_result.get('malicious_count', 0) > 0:
                        result['is_malicious'] = True
                        result['sources'].append('virustotal')
                        # Adjust confidence based on detection count
                        detection_ratio = vt_result['malicious_count'] / max(vt_result['total_engines'], 1)
                        result['confidence'] = max(result['confidence'], detection_ratio)
                        if detection_ratio > 0.5:
                            result['severity'] = 'CRITICAL'
                        elif detection_ratio > 0.2:
                            result['severity'] = 'HIGH'

            # AbuseIPDB
            if 'abuseipdb' in self.api_keys:
                abuse_result = self._check_ip_abuseipdb(ip)
                if abuse_result:
                    result['details']['abuseipdb'] = abuse_result
                    if abuse_result.get('abuse_confidence_score', 0) > 50:
                        result['is_malicious'] = True
                        result['sources'].append('abuseipdb')
                        result['confidence'] = max(
                            result['confidence'],
                            abuse_result['abuse_confidence_score'] / 100
                        )
                        if abuse_result['abuse_confidence_score'] > 80:
                            result['severity'] = 'CRITICAL'
                        elif abuse_result['abuse_confidence_score'] > 50:
                            result['severity'] = 'HIGH'

        if result['is_malicious']:
            self.stats['malicious_found'] += 1

        # Cache result
        if use_cache:
            self.cache.set('ip', ip, result)

        return result

    def _check_ip_virustotal(self, ip: str) -> Optional[Dict]:
        """Check IP on VirusTotal."""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return None

        self._rate_limit('virustotal')
        self.stats['api_calls'] += 1

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': api_key}

        data = self._make_request(url, headers)
        if not data or 'data' not in data:
            return None

        attributes = data['data'].get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return {
            'malicious_count': stats.get('malicious', 0),
            'suspicious_count': stats.get('suspicious', 0),
            'harmless_count': stats.get('harmless', 0),
            'total_engines': sum(stats.values()),
            'country': attributes.get('country', 'Unknown'),
            'as_owner': attributes.get('as_owner', 'Unknown'),
            'reputation': attributes.get('reputation', 0),
        }

    def _check_ip_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Check IP on AbuseIPDB."""
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return None

        self._rate_limit('abuseipdb')
        self.stats['api_calls'] += 1

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }

        data = self._make_request(url, headers)
        if not data or 'data' not in data:
            return None

        result_data = data['data']
        return {
            'abuse_confidence_score': result_data.get('abuseConfidenceScore', 0),
            'total_reports': result_data.get('totalReports', 0),
            'country_code': result_data.get('countryCode', 'Unknown'),
            'isp': result_data.get('isp', 'Unknown'),
            'is_tor': result_data.get('isTor', False),
            'is_public': result_data.get('isPublic', True),
        }

    def check_hash(self, hash_value: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Check file hash reputation.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash
            use_cache: Use cached results

        Returns:
            Reputation data dictionary
        """
        self.stats['total_lookups'] += 1
        hash_value = hash_value.lower()

        result = {
            'hash': hash_value,
            'is_malicious': False,
            'confidence': 0.0,
            'severity': 'LOW',
            'malware_name': None,
            'sources': [],
            'details': {},
            'checked_at': datetime.now().isoformat()
        }

        # Check cache
        if use_cache:
            cached = self.cache.get('hash', hash_value)
            if cached:
                self.stats['cache_hits'] += 1
                return cached

        # Check local feed
        local_result = self.local_feed.check_hash(hash_value)
        if local_result:
            self.stats['local_hits'] += 1
            result['is_malicious'] = True
            result['confidence'] = 0.95
            result['severity'] = local_result.get('severity', 'HIGH')
            result['malware_name'] = local_result.get('name')
            result['sources'].append('local_feed')
            result['details']['local_feed'] = local_result

        # Check VirusTotal
        if self.enable_online and 'virustotal' in self.api_keys:
            vt_result = self._check_hash_virustotal(hash_value)
            if vt_result:
                result['details']['virustotal'] = vt_result
                if vt_result.get('malicious_count', 0) > 0:
                    result['is_malicious'] = True
                    result['sources'].append('virustotal')
                    detection_ratio = vt_result['malicious_count'] / max(vt_result['total_engines'], 1)
                    result['confidence'] = max(result['confidence'], detection_ratio)
                    result['malware_name'] = vt_result.get('suggested_threat_label')
                    if detection_ratio > 0.5:
                        result['severity'] = 'CRITICAL'
                    elif detection_ratio > 0.2:
                        result['severity'] = 'HIGH'

        if result['is_malicious']:
            self.stats['malicious_found'] += 1

        if use_cache:
            self.cache.set('hash', hash_value, result)

        return result

    def _check_hash_virustotal(self, hash_value: str) -> Optional[Dict]:
        """Check hash on VirusTotal."""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return None

        self._rate_limit('virustotal')
        self.stats['api_calls'] += 1

        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {'x-apikey': api_key}

        data = self._make_request(url, headers)
        if not data or 'data' not in data:
            return None

        attributes = data['data'].get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return {
            'malicious_count': stats.get('malicious', 0),
            'suspicious_count': stats.get('suspicious', 0),
            'total_engines': sum(stats.values()),
            'suggested_threat_label': attributes.get('popular_threat_classification', {}).get('suggested_threat_label'),
            'file_type': attributes.get('type_description', 'Unknown'),
            'file_size': attributes.get('size', 0),
        }

    def check_domain(self, domain: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Check domain reputation.

        Args:
            domain: Domain to check
            use_cache: Use cached results

        Returns:
            Reputation data dictionary
        """
        self.stats['total_lookups'] += 1
        domain = domain.lower()

        result = {
            'domain': domain,
            'is_malicious': False,
            'confidence': 0.0,
            'severity': 'LOW',
            'sources': [],
            'details': {},
            'checked_at': datetime.now().isoformat()
        }

        # Check cache
        if use_cache:
            cached = self.cache.get('domain', domain)
            if cached:
                self.stats['cache_hits'] += 1
                return cached

        # Check local feed
        local_result = self.local_feed.check_domain(domain)
        if local_result:
            self.stats['local_hits'] += 1
            result['is_malicious'] = True
            result['confidence'] = 0.95
            result['severity'] = local_result.get('severity', 'HIGH')
            result['sources'].append('local_feed')
            result['details']['local_feed'] = local_result

        # Check VirusTotal
        if self.enable_online and 'virustotal' in self.api_keys:
            vt_result = self._check_domain_virustotal(domain)
            if vt_result:
                result['details']['virustotal'] = vt_result
                if vt_result.get('malicious_count', 0) > 0:
                    result['is_malicious'] = True
                    result['sources'].append('virustotal')
                    detection_ratio = vt_result['malicious_count'] / max(vt_result['total_engines'], 1)
                    result['confidence'] = max(result['confidence'], detection_ratio)
                    if detection_ratio > 0.3:
                        result['severity'] = 'CRITICAL'
                    elif detection_ratio > 0.1:
                        result['severity'] = 'HIGH'

        if result['is_malicious']:
            self.stats['malicious_found'] += 1

        if use_cache:
            self.cache.set('domain', domain, result)

        return result

    def _check_domain_virustotal(self, domain: str) -> Optional[Dict]:
        """Check domain on VirusTotal."""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return None

        self._rate_limit('virustotal')
        self.stats['api_calls'] += 1

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}

        data = self._make_request(url, headers)
        if not data or 'data' not in data:
            return None

        attributes = data['data'].get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return {
            'malicious_count': stats.get('malicious', 0),
            'suspicious_count': stats.get('suspicious', 0),
            'total_engines': sum(stats.values()),
            'registrar': attributes.get('registrar', 'Unknown'),
            'creation_date': attributes.get('creation_date'),
            'reputation': attributes.get('reputation', 0),
        }

    def enrich_anomaly(self, anomaly) -> Dict[str, Any]:
        """
        Enrich anomaly with threat intelligence data.

        Args:
            anomaly: SecurityAnomaly object

        Returns:
            Enrichment data dictionary
        """
        enrichment = {
            'threat_intel_checked': True,
            'findings': []
        }

        # Check source IP
        if hasattr(anomaly, 'src_ip') and anomaly.src_ip:
            ip_result = self.check_ip(anomaly.src_ip)
            if ip_result['is_malicious']:
                enrichment['findings'].append({
                    'type': 'ip',
                    'value': anomaly.src_ip,
                    'result': ip_result
                })

        # Check destination IP
        if hasattr(anomaly, 'dst_ip') and anomaly.dst_ip:
            if anomaly.dst_ip not in ['Multiple', 'Network', '']:
                ip_result = self.check_ip(anomaly.dst_ip)
                if ip_result['is_malicious']:
                    enrichment['findings'].append({
                        'type': 'ip',
                        'value': anomaly.dst_ip,
                        'result': ip_result
                    })

        # Check extracted payload hash if available
        if hasattr(anomaly, 'extracted_payload') and anomaly.extracted_payload:
            payload = anomaly.extracted_payload
            if hasattr(payload, 'sha256_hash') and payload.sha256_hash:
                hash_result = self.check_hash(payload.sha256_hash)
                if hash_result['is_malicious']:
                    enrichment['findings'].append({
                        'type': 'hash',
                        'value': payload.sha256_hash,
                        'result': hash_result
                    })

        return enrichment

    def get_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return {
            **self.stats,
            'cache_hit_rate': self.stats['cache_hits'] / max(self.stats['total_lookups'], 1) * 100,
            'local_feed_ips': len(self.local_feed.malicious_ips),
            'local_feed_hashes': len(self.local_feed.malicious_hashes),
            'local_feed_domains': len(self.local_feed.malicious_domains),
            'apis_configured': list(self.api_keys.keys()),
        }
