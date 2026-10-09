"""
OT PCAP Analyzer - Database Backend
====================================
Historical storage and analysis using an SQLite database.

Features:
- Store analysis sessions
- Store anomalies with full metadata
- Store IOCs for correlation
- Queries and statistics
- Export/Import capabilities

Usage:
    db = AnalysisDatabase()
    session_id = db.create_session("capture.pcap")
    db.store_anomalies(session_id, anomalies)
    db.store_iocs(session_id, iocs)

    # Query historical data
    stats = db.get_statistics()
    trends = db.get_attack_trends()
"""

import sqlite3
import json
import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from contextlib import contextmanager
import threading

from .utils import logger


# ---------------------------------------------------------------------------
# Timestamp handling
# ---------------------------------------------------------------------------
# Anomaly timestamps are capture times (UNIX epoch floats). Earlier versions
# stored them raw in TIMESTAMP columns, which crashed sqlite3's default
# PARSE_DECLTYPES converter on read ("not enough values to unpack") and made
# strftime()-based trend queries return NULL. They are now stored as ISO-8601
# UTC strings; the converter below also accepts numeric epoch values.

def _ts_to_db(ts: Any) -> Optional[str]:
    """Convert an epoch float / datetime to the ISO string stored in the DB."""
    if ts is None or ts == "":
        return None
    if isinstance(ts, datetime):
        return ts.isoformat(sep=" ")
    try:
        value = float(ts)
    except (TypeError, ValueError):
        return str(ts)
    try:
        return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
    except (OverflowError, OSError, ValueError):
        return None


def _convert_timestamp(raw: bytes):
    text = raw.decode("utf-8", errors="replace")
    try:
        return datetime.fromtimestamp(float(text), timezone.utc).replace(tzinfo=None)
    except ValueError:
        pass
    except (OverflowError, OSError):
        return text
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return text


sqlite3.register_adapter(datetime, lambda d: d.isoformat(sep=" "))
sqlite3.register_converter("TIMESTAMP", _convert_timestamp)


class AnalysisDatabase:
    """
    SQLite database backend for storing analysis results.
    Thread-safe implementation.
    """

    # Database schema version for migrations
    SCHEMA_VERSION = 1

    def __init__(self, db_path: str = None):
        """
        Initialize database connection.

        Args:
            db_path: Path to database file (default: ~/.ot_pcap_analyzer/analysis.db)
        """
        if db_path is None:
            home = Path.home()
            db_dir = home / ".ot_pcap_analyzer"
            # Analysis history contains plant topology and payloads: owner-only
            db_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            db_path = db_dir / "analysis.db"

        self.db_path = str(db_path)
        self._local = threading.local()

        # Initialize schema
        self._init_schema()

    @contextmanager
    def _get_connection(self):
        """Get thread-local database connection."""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                self.db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            self._local.connection.row_factory = sqlite3.Row
            # Deleted history must really disappear from the file (privacy)
            self._local.connection.execute("PRAGMA secure_delete = ON")

        try:
            yield self._local.connection
        except Exception as e:
            self._local.connection.rollback()
            raise

    def _init_schema(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Create tables
            cursor.executescript("""
                -- Schema version tracking
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Analysis sessions
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    pcap_file TEXT NOT NULL,
                    pcap_hash TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    status TEXT DEFAULT 'running',
                    total_packets INTEGER DEFAULT 0,
                    total_anomalies INTEGER DEFAULT 0,
                    metadata TEXT
                );

                -- Anomalies/Threats detected
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    description TEXT,
                    confidence REAL DEFAULT 0.0,
                    raw_data TEXT,
                    enrichment_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                -- IOC Records
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    severity TEXT,
                    attack_type TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    occurrence_count INTEGER DEFAULT 1,
                    context TEXT,
                    threat_intel TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                -- Attack flow/timeline
                CREATE TABLE IF NOT EXISTS attack_timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    timestamp TIMESTAMP,
                    anomaly_id INTEGER,
                    description TEXT,
                    techniques TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id),
                    FOREIGN KEY (anomaly_id) REFERENCES anomalies(id)
                );

                -- Global IOC watchlist (cross-session)
                CREATE TABLE IF NOT EXISTS ioc_watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    severity TEXT DEFAULT 'HIGH',
                    description TEXT,
                    tags TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP,
                    hit_count INTEGER DEFAULT 0,
                    source TEXT,
                    is_active INTEGER DEFAULT 1
                );

                -- Statistics cache
                CREATE TABLE IF NOT EXISTS statistics_cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Create indexes for performance
                CREATE INDEX IF NOT EXISTS idx_anomalies_session ON anomalies(session_id);
                CREATE INDEX IF NOT EXISTS idx_anomalies_type ON anomalies(anomaly_type);
                CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
                CREATE INDEX IF NOT EXISTS idx_anomalies_src_ip ON anomalies(src_ip);
                CREATE INDEX IF NOT EXISTS idx_anomalies_dst_ip ON anomalies(dst_ip);
                CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp);

                CREATE INDEX IF NOT EXISTS idx_iocs_session ON iocs(session_id);
                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
                CREATE INDEX IF NOT EXISTS idx_iocs_attack_type ON iocs(attack_type);

                CREATE INDEX IF NOT EXISTS idx_watchlist_type ON ioc_watchlist(ioc_type);
                CREATE INDEX IF NOT EXISTS idx_watchlist_value ON ioc_watchlist(value);
            """)

            # Check and update schema version
            cursor.execute("SELECT MAX(version) FROM schema_version")
            row = cursor.fetchone()
            current_version = row[0] if row and row[0] else 0

            if current_version < self.SCHEMA_VERSION:
                cursor.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (self.SCHEMA_VERSION,)
                )

            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")

    # ==================== Session Management ====================

    def create_session(self, pcap_file: str, metadata: Dict = None,
                       pcap_hash: Optional[str] = None) -> str:
        """
        Create new analysis session.

        Args:
            pcap_file: Path to PCAP file being analyzed
            metadata: Additional metadata

        Returns:
            Session ID
        """
        session_id = hashlib.md5(
            f"{pcap_file}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        # Calculate PCAP file hash if file exists (streamed: captures can be GBs)
        if not pcap_hash and os.path.isfile(pcap_file):
            try:
                digest = hashlib.sha256()
                with open(pcap_file, 'rb') as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        digest.update(chunk)
                pcap_hash = digest.hexdigest()
            except IOError:
                pass

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (id, pcap_file, pcap_hash, metadata)
                VALUES (?, ?, ?, ?)
            """, (
                session_id,
                pcap_file,
                pcap_hash,
                json.dumps(metadata) if metadata else None
            ))
            conn.commit()

        logger.info(f"Created session {session_id} for {pcap_file}")
        return session_id

    def update_session(self, session_id: str, status: str = None,
                       total_packets: int = None, total_anomalies: int = None):
        """Update session status and statistics."""
        updates = []
        params = []

        if status:
            updates.append("status = ?")
            params.append(status)
            if status == 'completed':
                updates.append("completed_at = ?")
                params.append(datetime.now())

        if total_packets is not None:
            updates.append("total_packets = ?")
            params.append(total_packets)

        if total_anomalies is not None:
            updates.append("total_anomalies = ?")
            params.append(total_anomalies)

        if not updates:
            return

        params.append(session_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE sessions SET {', '.join(updates)} WHERE id = ?",
                params
            )
            conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def get_recent_sessions(self, limit: int = 20) -> List[Dict]:
        """Get recent analysis sessions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM sessions
                ORDER BY started_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # ==================== Anomaly Storage ====================

    def store_anomaly(self, session_id: str, anomaly, enrichment: Dict = None) -> int:
        """
        Store single anomaly.

        Args:
            session_id: Session ID
            anomaly: SecurityAnomaly object
            enrichment: Threat intelligence enrichment data

        Returns:
            Anomaly ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Extract anomaly attributes safely
            raw_data = {}
            if hasattr(anomaly, '__dict__'):
                for k, v in anomaly.__dict__.items():
                    if not k.startswith('_'):
                        try:
                            json.dumps(v)  # Test if serializable
                            raw_data[k] = v
                        except (TypeError, ValueError):
                            raw_data[k] = str(v)

            cursor.execute("""
                INSERT INTO anomalies (
                    session_id, anomaly_type, severity, timestamp,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    description, confidence, raw_data, enrichment_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                getattr(anomaly, 'anomaly_type', 'Unknown'),
                getattr(anomaly, 'severity', 'MEDIUM'),
                _ts_to_db(getattr(anomaly, 'timestamp', None)),
                getattr(anomaly, 'src_ip', None),
                getattr(anomaly, 'dst_ip', None),
                getattr(anomaly, 'src_port', None),
                getattr(anomaly, 'dst_port', None),
                getattr(anomaly, 'protocol', None),
                getattr(anomaly, 'description', ''),
                getattr(anomaly, 'confidence', 0.0),
                json.dumps(raw_data),
                json.dumps(enrichment) if enrichment else None
            ))

            conn.commit()
            return cursor.lastrowid

    def store_anomalies(self, session_id: str, anomalies: List,
                        enrichments: Dict[int, Dict] = None) -> int:
        """
        Store multiple anomalies in batch.

        Args:
            session_id: Session ID
            anomalies: List of SecurityAnomaly objects
            enrichments: Dict mapping anomaly index to enrichment data

        Returns:
            Number of anomalies stored
        """
        count = 0
        enrichments = enrichments or {}

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for i, anomaly in enumerate(anomalies):
                try:
                    raw_data = {}
                    if hasattr(anomaly, '__dict__'):
                        for k, v in anomaly.__dict__.items():
                            if not k.startswith('_'):
                                try:
                                    json.dumps(v)
                                    raw_data[k] = v
                                except (TypeError, ValueError):
                                    raw_data[k] = str(v)

                    enrichment = enrichments.get(i)

                    cursor.execute("""
                        INSERT INTO anomalies (
                            session_id, anomaly_type, severity, timestamp,
                            src_ip, dst_ip, src_port, dst_port, protocol,
                            description, confidence, raw_data, enrichment_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        session_id,
                        getattr(anomaly, 'anomaly_type', 'Unknown'),
                        getattr(anomaly, 'severity', 'MEDIUM'),
                        _ts_to_db(getattr(anomaly, 'timestamp', None)),
                        getattr(anomaly, 'src_ip', None),
                        getattr(anomaly, 'dst_ip', None),
                        getattr(anomaly, 'src_port', None),
                        getattr(anomaly, 'dst_port', None),
                        getattr(anomaly, 'protocol', None),
                        getattr(anomaly, 'description', ''),
                        getattr(anomaly, 'confidence', 0.0),
                        json.dumps(raw_data),
                        json.dumps(enrichment) if enrichment else None
                    ))
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to store anomaly: {e}")

            conn.commit()

        logger.info(f"Stored {count} anomalies for session {session_id}")
        return count

    def get_anomalies(self, session_id: str = None, anomaly_type: str = None,
                      severity: str = None, src_ip: str = None,
                      start_time: datetime = None, end_time: datetime = None,
                      limit: int = 1000) -> List[Dict]:
        """
        Query anomalies with filters.

        Args:
            session_id: Filter by session
            anomaly_type: Filter by type
            severity: Filter by severity
            src_ip: Filter by source IP
            start_time: Filter by timestamp (from)
            end_time: Filter by timestamp (to)
            limit: Maximum results

        Returns:
            List of anomaly dictionaries
        """
        conditions = []
        params = []

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)

        if anomaly_type:
            conditions.append("anomaly_type = ?")
            params.append(anomaly_type)

        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)

        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)

        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT * FROM anomalies
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            """, params)

            results = []
            for row in cursor.fetchall():
                anomaly = dict(row)
                # Parse JSON fields
                if anomaly.get('raw_data'):
                    anomaly['raw_data'] = json.loads(anomaly['raw_data'])
                if anomaly.get('enrichment_data'):
                    anomaly['enrichment_data'] = json.loads(anomaly['enrichment_data'])
                results.append(anomaly)

            return results

    # ==================== IOC Storage ====================

    def store_ioc(self, session_id: str, ioc_type: str, value: str,
                  severity: str = None, attack_type: str = None,
                  context: Dict = None, threat_intel: Dict = None) -> int:
        """
        Store single IOC.

        Returns:
            IOC ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if IOC already exists in this session
            cursor.execute("""
                SELECT id, occurrence_count FROM iocs
                WHERE session_id = ? AND ioc_type = ? AND value = ?
            """, (session_id, ioc_type, value))

            existing = cursor.fetchone()

            if existing:
                # Update existing IOC
                cursor.execute("""
                    UPDATE iocs
                    SET occurrence_count = occurrence_count + 1,
                        last_seen = ?,
                        threat_intel = COALESCE(?, threat_intel)
                    WHERE id = ?
                """, (
                    datetime.now(),
                    json.dumps(threat_intel) if threat_intel else None,
                    existing['id']
                ))
                conn.commit()
                return existing['id']
            else:
                # Insert new IOC
                cursor.execute("""
                    INSERT INTO iocs (
                        session_id, ioc_type, value, severity, attack_type,
                        first_seen, last_seen, context, threat_intel
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    ioc_type,
                    value,
                    severity,
                    attack_type,
                    datetime.now(),
                    datetime.now(),
                    json.dumps(context) if context else None,
                    json.dumps(threat_intel) if threat_intel else None
                ))
                conn.commit()
                return cursor.lastrowid

    def store_iocs(self, session_id: str, iocs: Dict[str, List]) -> int:
        """
        Store multiple IOCs from IOC collector output.

        Args:
            session_id: Session ID
            iocs: IOC dictionary from IOCCollector

        Returns:
            Number of IOCs stored
        """
        count = 0

        # Map IOC categories to database types
        type_mapping = {
            'ip_addresses': 'IP',
            'domains': 'DOMAIN',
            'urls': 'URL',
            'file_hashes': 'HASH',
            'email_addresses': 'EMAIL',
            'user_agents': 'USER_AGENT',
            'ports': 'PORT',
            'protocols': 'PROTOCOL',
        }

        for ioc_category, ioc_list in iocs.items():
            if ioc_category == 'by_attack_type':
                # Handle attack-type categorized IOCs
                for attack_type, attack_iocs in ioc_list.items():
                    for ioc in attack_iocs:
                        if hasattr(ioc, 'type') and hasattr(ioc, 'value'):
                            self.store_ioc(
                                session_id,
                                ioc.type,
                                str(ioc.value),
                                severity=getattr(ioc, 'severity', None),
                                attack_type=attack_type,
                                context={'source': ioc_category}
                            )
                            count += 1
            elif isinstance(ioc_list, list):
                db_type = type_mapping.get(ioc_category, ioc_category.upper())

                for ioc in ioc_list:
                    if hasattr(ioc, 'value'):
                        self.store_ioc(
                            session_id,
                            getattr(ioc, 'ioc_type', None) or db_type,
                            str(ioc.value),
                            severity=getattr(ioc, 'severity', None),
                            context={'source': ioc_category}
                        )
                    else:
                        self.store_ioc(
                            session_id,
                            db_type,
                            str(ioc),
                            context={'source': ioc_category}
                        )
                    count += 1

        logger.info(f"Stored {count} IOCs for session {session_id}")
        return count

    def get_iocs(self, session_id: str = None, ioc_type: str = None,
                 attack_type: str = None, limit: int = 1000) -> List[Dict]:
        """Query IOCs with filters."""
        conditions = []
        params = []

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)

        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)

        if attack_type:
            conditions.append("attack_type = ?")
            params.append(attack_type)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT * FROM iocs
                WHERE {where_clause}
                ORDER BY occurrence_count DESC, created_at DESC
                LIMIT ?
            """, params)

            results = []
            for row in cursor.fetchall():
                ioc = dict(row)
                if ioc.get('context'):
                    ioc['context'] = json.loads(ioc['context'])
                if ioc.get('threat_intel'):
                    ioc['threat_intel'] = json.loads(ioc['threat_intel'])
                results.append(ioc)

            return results

    # ==================== IOC Watchlist ====================

    def add_to_watchlist(self, ioc_type: str, value: str, severity: str = "HIGH",
                         description: str = None, tags: List[str] = None,
                         source: str = None) -> int:
        """
        Add IOC to global watchlist.

        Returns:
            Watchlist entry ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    INSERT INTO ioc_watchlist (
                        ioc_type, value, severity, description, tags, source
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    ioc_type,
                    value,
                    severity,
                    description,
                    json.dumps(tags) if tags else None,
                    source
                ))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                # Already exists, update hit count
                cursor.execute("""
                    UPDATE ioc_watchlist
                    SET hit_count = hit_count + 1,
                        last_seen_at = CURRENT_TIMESTAMP
                    WHERE value = ?
                """, (value,))
                conn.commit()
                return 0

    def check_watchlist(self, ioc_type: str, value: str) -> Optional[Dict]:
        """Check if IOC is in watchlist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM ioc_watchlist
                WHERE ioc_type = ? AND value = ? AND is_active = 1
            """, (ioc_type, value))

            row = cursor.fetchone()
            if row:
                # Update hit count
                cursor.execute("""
                    UPDATE ioc_watchlist
                    SET hit_count = hit_count + 1,
                        last_seen_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (row['id'],))
                conn.commit()

                result = dict(row)
                if result.get('tags'):
                    result['tags'] = json.loads(result['tags'])
                return result

        return None

    def get_watchlist(self, ioc_type: str = None, active_only: bool = True) -> List[Dict]:
        """Get watchlist entries."""
        conditions = []
        params = []

        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)

        if active_only:
            conditions.append("is_active = 1")

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT * FROM ioc_watchlist
                WHERE {where_clause}
                ORDER BY hit_count DESC, added_at DESC
            """, params)

            results = []
            for row in cursor.fetchall():
                entry = dict(row)
                if entry.get('tags'):
                    entry['tags'] = json.loads(entry['tags'])
                results.append(entry)

            return results

    # ==================== Statistics & Analytics ====================

    def get_statistics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get overall statistics.

        Args:
            days: Number of days to include

        Returns:
            Statistics dictionary
        """
        cutoff = datetime.now() - timedelta(days=days)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            stats = {}

            # Session stats
            cursor.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                       SUM(total_packets) as total_packets,
                       SUM(total_anomalies) as total_anomalies
                FROM sessions
                WHERE started_at >= ?
            """, (cutoff,))
            row = cursor.fetchone()
            stats['sessions'] = {
                'total': row['total'] or 0,
                'completed': row['completed'] or 0,
                'total_packets': row['total_packets'] or 0,
                'total_anomalies': row['total_anomalies'] or 0,
            }

            # Anomaly type distribution
            cursor.execute("""
                SELECT anomaly_type, COUNT(*) as count
                FROM anomalies a
                JOIN sessions s ON a.session_id = s.id
                WHERE s.started_at >= ?
                GROUP BY anomaly_type
                ORDER BY count DESC
            """, (cutoff,))
            stats['anomaly_types'] = {row['anomaly_type']: row['count'] for row in cursor.fetchall()}

            # Severity distribution
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM anomalies a
                JOIN sessions s ON a.session_id = s.id
                WHERE s.started_at >= ?
                GROUP BY severity
            """, (cutoff,))
            stats['severity_distribution'] = {row['severity']: row['count'] for row in cursor.fetchall()}

            # Top attacking IPs
            cursor.execute("""
                SELECT src_ip, COUNT(*) as count
                FROM anomalies a
                JOIN sessions s ON a.session_id = s.id
                WHERE s.started_at >= ? AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 10
            """, (cutoff,))
            stats['top_source_ips'] = [
                {'ip': row['src_ip'], 'count': row['count']}
                for row in cursor.fetchall()
            ]

            # IOC type distribution
            cursor.execute("""
                SELECT ioc_type, COUNT(*) as count, SUM(occurrence_count) as total_occurrences
                FROM iocs i
                JOIN sessions s ON i.session_id = s.id
                WHERE s.started_at >= ?
                GROUP BY ioc_type
            """, (cutoff,))
            stats['ioc_types'] = {
                row['ioc_type']: {
                    'unique': row['count'],
                    'total_occurrences': row['total_occurrences']
                }
                for row in cursor.fetchall()
            }

            return stats

    def get_attack_trends(self, days: int = 30, interval: str = 'day') -> List[Dict]:
        """
        Get attack trends over time.

        Args:
            days: Number of days to include
            interval: 'hour', 'day', 'week'

        Returns:
            List of trend data points
        """
        cutoff = datetime.now() - timedelta(days=days)

        # SQLite date formatting based on interval
        if interval == 'hour':
            date_format = '%Y-%m-%d %H:00'
        elif interval == 'week':
            date_format = '%Y-%W'
        else:
            date_format = '%Y-%m-%d'

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT
                    strftime('{date_format}', timestamp) as period,
                    COUNT(*) as total_anomalies,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
                FROM anomalies
                WHERE timestamp >= ?
                GROUP BY period
                ORDER BY period
            """, (cutoff,))

            return [dict(row) for row in cursor.fetchall()]

    def get_ip_reputation_history(self, ip: str) -> Dict[str, Any]:
        """
        Get historical activity for an IP address.

        Args:
            ip: IP address

        Returns:
            Historical data for the IP
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            result = {
                'ip': ip,
                'first_seen': None,
                'last_seen': None,
                'total_anomalies': 0,
                'anomaly_types': {},
                'sessions': [],
            }

            # Get anomalies involving this IP
            cursor.execute("""
                SELECT
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    COUNT(*) as total,
                    anomaly_type
                FROM anomalies
                WHERE src_ip = ? OR dst_ip = ?
                GROUP BY anomaly_type
            """, (ip, ip))

            for row in cursor.fetchall():
                # Types whose timestamps are all NULL return NULL MIN/MAX: skip them
                if row['first_seen'] is not None and (
                        result['first_seen'] is None or row['first_seen'] < result['first_seen']):
                    result['first_seen'] = row['first_seen']
                if row['last_seen'] is not None and (
                        result['last_seen'] is None or row['last_seen'] > result['last_seen']):
                    result['last_seen'] = row['last_seen']
                result['total_anomalies'] += row['total']
                result['anomaly_types'][row['anomaly_type']] = row['total']

            # Get sessions involving this IP
            cursor.execute("""
                SELECT DISTINCT s.id, s.pcap_file, s.started_at
                FROM sessions s
                JOIN anomalies a ON a.session_id = s.id
                WHERE a.src_ip = ? OR a.dst_ip = ?
                ORDER BY s.started_at DESC
                LIMIT 10
            """, (ip, ip))

            result['sessions'] = [dict(row) for row in cursor.fetchall()]

            return result

    def search_iocs(self, query: str, limit: int = 100) -> List[Dict]:
        """
        Search IOCs by value pattern.

        Args:
            query: Search pattern (supports SQL LIKE wildcards)
            limit: Maximum results

        Returns:
            Matching IOCs
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT i.*, s.pcap_file
                FROM iocs i
                JOIN sessions s ON i.session_id = s.id
                WHERE i.value LIKE ?
                ORDER BY i.occurrence_count DESC
                LIMIT ?
            """, (f"%{query}%", limit))

            results = []
            for row in cursor.fetchall():
                ioc = dict(row)
                if ioc.get('context'):
                    ioc['context'] = json.loads(ioc['context'])
                if ioc.get('threat_intel'):
                    ioc['threat_intel'] = json.loads(ioc['threat_intel'])
                results.append(ioc)

            return results

    # ==================== Export/Import ====================

    def export_session(self, session_id: str, output_file: str) -> bool:
        """
        Export session data to JSON file.

        Args:
            session_id: Session to export
            output_file: Output file path

        Returns:
            True if successful
        """
        try:
            session = self.get_session(session_id)
            if not session:
                logger.warning(f"Session {session_id} not found")
                return False

            anomalies = self.get_anomalies(session_id=session_id)
            iocs = self.get_iocs(session_id=session_id)

            export_data = {
                'export_version': '1.0',
                'exported_at': datetime.now().isoformat(),
                'session': session,
                'anomalies': anomalies,
                'iocs': iocs,
            }

            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

            logger.info(f"Exported session {session_id} to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False

    def import_session(self, input_file: str) -> Optional[str]:
        """
        Import session data from JSON file.

        Args:
            input_file: Input file path

        Returns:
            New session ID if successful
        """
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)

            # Create new session
            old_session = data.get('session', {})
            session_id = self.create_session(
                old_session.get('pcap_file', 'imported'),
                metadata={
                    'imported_from': input_file,
                    'original_session_id': old_session.get('id'),
                }
            )

            # Import anomalies
            with self._get_connection() as conn:
                cursor = conn.cursor()

                for anomaly in data.get('anomalies', []):
                    cursor.execute("""
                        INSERT INTO anomalies (
                            session_id, anomaly_type, severity, timestamp,
                            src_ip, dst_ip, src_port, dst_port, protocol,
                            description, confidence, raw_data, enrichment_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        session_id,
                        anomaly.get('anomaly_type'),
                        anomaly.get('severity'),
                        _ts_to_db(anomaly.get('timestamp')),
                        anomaly.get('src_ip'),
                        anomaly.get('dst_ip'),
                        anomaly.get('src_port'),
                        anomaly.get('dst_port'),
                        anomaly.get('protocol'),
                        anomaly.get('description'),
                        anomaly.get('confidence'),
                        json.dumps(anomaly.get('raw_data')) if anomaly.get('raw_data') else None,
                        json.dumps(anomaly.get('enrichment_data')) if anomaly.get('enrichment_data') else None,
                    ))

                # Import IOCs
                for ioc in data.get('iocs', []):
                    cursor.execute("""
                        INSERT INTO iocs (
                            session_id, ioc_type, value, severity, attack_type,
                            first_seen, last_seen, occurrence_count, context, threat_intel
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        session_id,
                        ioc.get('ioc_type'),
                        ioc.get('value'),
                        ioc.get('severity'),
                        ioc.get('attack_type'),
                        ioc.get('first_seen'),
                        ioc.get('last_seen'),
                        ioc.get('occurrence_count', 1),
                        json.dumps(ioc.get('context')) if ioc.get('context') else None,
                        json.dumps(ioc.get('threat_intel')) if ioc.get('threat_intel') else None,
                    ))

                conn.commit()

            logger.info(f"Imported session from {input_file} as {session_id}")
            return session_id

        except Exception as e:
            logger.error(f"Import failed: {e}")
            return None

    # ==================== History management ====================

    @staticmethod
    def _session_row(row) -> Dict:
        session = dict(row)
        try:
            session['metadata'] = json.loads(session.get('metadata') or '{}') or {}
        except (TypeError, ValueError):
            session['metadata'] = {}
        return session

    def list_sessions(self, search: str = "", since_days: Optional[int] = None,
                      limit: int = 500) -> List[Dict]:
        """Sessions newest first, optionally filtered by file name and age."""
        conditions, params = [], []
        if search:
            conditions.append("pcap_file LIKE ? ESCAPE '\\'")
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
        if since_days:
            conditions.append("started_at >= ?")
            params.append((datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=since_days)).strftime("%Y-%m-%d %H:%M:%S"))
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        with self._get_connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM sessions {where} ORDER BY started_at DESC LIMIT ?", params
            ).fetchall()
        return [self._session_row(r) for r in rows]

    def session_overview(self, session_id: str) -> Optional[Dict]:
        """Session plus severity / type / protocol breakdowns of its stored alerts."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if not row:
                return None
            session = self._session_row(row)
            session['severity'] = {
                r['severity']: r['n'] for r in conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM anomalies WHERE session_id = ? GROUP BY severity",
                    (session_id,))}
            session['top_types'] = [
                (r['anomaly_type'], r['n']) for r in conn.execute(
                    "SELECT anomaly_type, COUNT(*) AS n FROM anomalies WHERE session_id = ? "
                    "GROUP BY anomaly_type ORDER BY n DESC LIMIT 8", (session_id,))]
            session['ioc_count'] = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE session_id = ?", (session_id,)).fetchone()[0]
        return session

    def _delete_where(self, conn, where: str, params) -> int:
        ids = [r[0] for r in conn.execute(f"SELECT id FROM sessions {where}", params)]
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for table in ("attack_timeline", "anomalies", "iocs"):
                conn.execute(f"DELETE FROM {table} WHERE session_id IN ({marks})", chunk)
            conn.execute(f"DELETE FROM sessions WHERE id IN ({marks})", chunk)
        return len(ids)

    def _after_delete(self, conn, removed: int) -> int:
        conn.execute("DELETE FROM statistics_cache")
        conn.commit()
        if removed:
            conn.execute("VACUUM")          # shrink the file, drop freed pages
        return removed

    def delete_sessions(self, session_ids: List[str]) -> int:
        """Delete sessions with all their alerts, IOCs and timeline rows."""
        ids = [str(i) for i in session_ids if i]
        if not ids:
            return 0
        with self._get_connection() as conn:
            marks = ",".join("?" * len(ids))
            removed = self._delete_where(conn, f"WHERE id IN ({marks})", ids)
            return self._after_delete(conn, removed)

    def delete_session(self, session_id: str) -> bool:
        return self.delete_sessions([session_id]) == 1

    def delete_all_sessions(self) -> int:
        """Erase the whole scan history (the user's IOC watchlist is kept)."""
        with self._get_connection() as conn:
            removed = self._delete_where(conn, "", [])
            # orphans from older versions / interrupted imports
            for table in ("attack_timeline", "anomalies", "iocs"):
                conn.execute(f"DELETE FROM {table}")
            return self._after_delete(conn, removed)

    def purge_older_than(self, days: int) -> int:
        """Delete sessions started more than ``days`` days ago (0 = keep everything)."""
        if not days or days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            removed = self._delete_where(conn, "WHERE started_at < ?", [cutoff])
            return self._after_delete(conn, removed)

    def storage_info(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        try:
            size = os.path.getsize(self.db_path)
        except OSError:
            size = 0
        return {"path": self.db_path, "size_bytes": size, "sessions": count}

    def compare_sessions(self, older_id: str, newer_id: str) -> Dict[str, Any]:
        """What changed between two scans (alert types and IOC values)."""
        with self._get_connection() as conn:
            def types(sid):
                return {r[0]: r[1] for r in conn.execute(
                    "SELECT anomaly_type, COUNT(*) FROM anomalies WHERE session_id = ? GROUP BY anomaly_type",
                    (sid,))}

            def iocs(sid):
                return {(r[0], r[1]) for r in conn.execute(
                    "SELECT ioc_type, value FROM iocs WHERE session_id = ?", (sid,))}
            old_t, new_t = types(older_id), types(newer_id)
            old_i, new_i = iocs(older_id), iocs(newer_id)
        return {
            "new_types": sorted(set(new_t) - set(old_t)),
            "resolved_types": sorted(set(old_t) - set(new_t)),
            "changed_types": sorted((t, old_t[t], new_t[t]) for t in set(old_t) & set(new_t)
                                    if old_t[t] != new_t[t]),
            "new_iocs": sorted(new_i - old_i),
            "gone_iocs": sorted(old_i - new_i),
        }

    def vacuum(self):
        """Optimize database size."""
        with self._get_connection() as conn:
            conn.execute("VACUUM")
        logger.info("Database vacuumed")

    def close(self):
        """Close database connection."""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None
