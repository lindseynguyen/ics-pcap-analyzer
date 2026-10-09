"""
OT PCAP Analyzer - Baseline engine
==================================
Learns normal communication patterns and filters anomalies that match them.
Re-exported by analyzer.py for convenience.
"""

from typing import Dict, List, Optional, Any, Tuple

import numpy as np

from .models import (
    OTEvent, SecurityAnomaly, CommunicationBaseline, WhitelistRule
)
from .utils import logger, normalize_timestamp

# =============================================================================
# BASELINE ENGINE - Normal Behavior Learning & Whitelist Management
# =============================================================================

class BaselineEngine:
    """
    Baseline learning engine for reducing false positives.

    Features:
    - Learns normal communication patterns from traffic
    - Supports manual whitelist rules
    - Adjusts anomaly confidence based on learned baselines
    - Helps operators filter out expected OT traffic

    Usage:
        engine = BaselineEngine(max_baselines=10000, learning_period=86400.0)
        engine.learn_from_event(ot_event)
        is_anomaly, confidence = engine.is_anomalous(anomaly, ot_event)
    """

    def __init__(self, max_baselines: int = 10000, learning_period: float = 86400.0):
        """
        Initialize baseline engine.

        Args:
            max_baselines: Maximum number of communication baselines to track
            learning_period: Time period (seconds) to collect data before marking baseline as stable
        """
        self.max_baselines = max_baselines
        self.learning_period = learning_period

        # Communication baselines: key = (src_ip, dst_ip, protocol) -> CommunicationBaseline
        self.baselines: Dict[str, 'CommunicationBaseline'] = {}

        # Whitelist rules
        self.whitelist_rules: List['WhitelistRule'] = []

        # Statistics
        self.total_events_learned = 0
        self.total_anomalies_filtered = 0

    def _make_baseline_key(self, src_ip: str, dst_ip: str, protocol: str) -> str:
        """Generate unique key for communication pair."""
        return f"{src_ip}:{dst_ip}:{protocol}"

    def learn_from_event(self, event: OTEvent, current_time: float = None) -> bool:
        """
        Learn normal behavior patterns from an OT event.

        Args:
            event: OTEvent to learn from
            current_time: Current timestamp (default: event timestamp)

        Returns:
            True if learning was successful, False if baseline limit reached
        """
        if current_time is None:
            current_time = event.timestamp

        key = self._make_baseline_key(event.src_ip, event.dst_ip, event.protocol.value)

        # Check if we need to create a new baseline
        if key not in self.baselines:
            # Check baseline limit
            if len(self.baselines) >= self.max_baselines:
                logger.warning(f"Baseline limit reached ({self.max_baselines}), cannot learn new pattern")
                return False

            # Import here to avoid circular dependency
            from .models import CommunicationBaseline
            from datetime import datetime

            # Create new baseline
            self.baselines[key] = CommunicationBaseline(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                protocol=event.protocol.value,
                src_port=event.src_port,
                dst_port=event.dst_port,
                first_seen=current_time,
                last_updated=current_time,
                samples_count=0
            )

        baseline = self.baselines[key]

        # Update sample count
        baseline.samples_count += 1
        previous_update = baseline.last_updated  # needed for the interval below
        baseline.last_updated = current_time
        self.total_events_learned += 1

        # Update function codes and operations
        if event.function_code is not None:
            baseline.normal_function_codes.add(event.function_code)
        if event.operation_type:
            baseline.normal_operations.add(event.operation_type)

        # Update timing patterns (only if we have previous data)
        if baseline.samples_count > 1:
            interval = current_time - previous_update

            # Update interval statistics
            if baseline.samples_count == 2:
                baseline.avg_interval = interval
                baseline.min_interval = interval
                baseline.max_interval = interval
                baseline.std_interval = 0.0
            else:
                # Incremental mean and std calculation
                old_mean = baseline.avg_interval
                n = baseline.samples_count - 1
                baseline.avg_interval = old_mean + (interval - old_mean) / n

                # Update std deviation (Welford's online algorithm)
                baseline.std_interval = np.sqrt(
                    ((n - 1) * baseline.std_interval ** 2 + (interval - old_mean) * (interval - baseline.avg_interval)) / n
                )

                # Update min/max
                baseline.min_interval = min(baseline.min_interval, interval)
                baseline.max_interval = max(baseline.max_interval, interval)

        # Update time patterns
        from datetime import datetime
        normalized_time = normalize_timestamp(current_time)
        if normalized_time:
            dt = datetime.fromtimestamp(normalized_time)
            baseline.active_hours.add(dt.hour)
            baseline.active_days.add(dt.weekday())

        # Mark as stable after learning period
        if current_time - baseline.first_seen >= self.learning_period and not baseline.is_stable:
            baseline.is_stable = True
            logger.info(f"Baseline stabilized: {key} (samples: {baseline.samples_count})")

        return True

    def is_anomalous(self, anomaly: SecurityAnomaly, event: Optional[OTEvent] = None) -> Tuple[bool, float]:
        """
        Check if an anomaly should be reported or filtered based on baseline/whitelist.

        Args:
            anomaly: SecurityAnomaly to evaluate
            event: Associated OTEvent (optional, for more context)

        Returns:
            (is_anomalous, adjusted_confidence) tuple:
                - is_anomalous: True if should be reported, False if filtered
                - adjusted_confidence: Original or reduced confidence based on baseline match
        """
        original_confidence = anomaly.confidence
        adjusted_confidence = original_confidence

        # Check whitelist rules first (highest priority)
        for rule in self.whitelist_rules:
            if not rule.enabled:
                continue

            # Check if rule expired
            if rule.expires_at > 0 and anomaly.timestamp > rule.expires_at:
                continue

            # Check IP patterns
            if rule.src_ip_pattern and not self._match_ip_pattern(anomaly.src_ip, rule.src_ip_pattern):
                continue
            if rule.dst_ip_pattern and not self._match_ip_pattern(anomaly.dst_ip, rule.dst_ip_pattern):
                continue

            # Check protocol
            if rule.protocol and rule.protocol != "*":
                event_proto = event.protocol.name if event is not None else anomaly.protocol
                if event_proto != rule.protocol:
                    continue

            # Check ports
            # SecurityAnomaly has no port fields: take ports from the related OT event
            src_port = event.src_port if event is not None else getattr(anomaly, 'src_port', None)
            dst_port = event.dst_port if event is not None else getattr(anomaly, 'dst_port', None)
            if rule.src_port_pattern and (src_port is None or not self._match_port_pattern(src_port, rule.src_port_pattern)):
                continue
            if rule.dst_port_pattern and (dst_port is None or not self._match_port_pattern(dst_port, rule.dst_port_pattern)):
                continue

            # Check function codes (if OT event provided)
            if rule.function_codes and event:
                if event.function_code not in rule.function_codes:
                    continue

            # Check time restrictions
            from datetime import datetime
            normalized_ts = normalize_timestamp(anomaly.timestamp)
            if normalized_ts:
                dt = datetime.fromtimestamp(normalized_ts)
                if rule.allowed_hours and dt.hour not in rule.allowed_hours:
                    continue
                if rule.allowed_days and dt.weekday() not in rule.allowed_days:
                    continue

            # Rule matched! Reduce confidence
            adjusted_confidence = max(0.0, adjusted_confidence - rule.confidence_reduction)
            logger.debug(f"Whitelist rule '{rule.name}' matched, confidence reduced: {original_confidence:.2f} -> {adjusted_confidence:.2f}")

            # If confidence drops below threshold, filter out
            if adjusted_confidence < 0.2:
                self.total_anomalies_filtered += 1
                return False, adjusted_confidence

        # Check learned baselines
        if event:
            key = self._make_baseline_key(event.src_ip, event.dst_ip, event.protocol.value)
            baseline = self.baselines.get(key)

            if baseline and baseline.is_stable:
                # Check if function code is known
                if event.function_code and event.function_code in baseline.normal_function_codes:
                    # Known function code - reduce confidence by 20%
                    adjusted_confidence *= 0.8

                # Check if operation type is known
                if event.operation_type and event.operation_type in baseline.normal_operations:
                    # Known operation - reduce confidence by 20%
                    adjusted_confidence *= 0.8

                # Check if time pattern matches
                from datetime import datetime
                normalized_ts = normalize_timestamp(event.timestamp)
                if normalized_ts:
                    dt = datetime.fromtimestamp(normalized_ts)
                    if dt.hour in baseline.active_hours and dt.weekday() in baseline.active_days:
                        # Normal time pattern - reduce confidence by 10%
                        adjusted_confidence *= 0.9

                # If significant reduction, log it
                if adjusted_confidence < original_confidence * 0.7:
                    logger.debug(f"Baseline matched for {key}, confidence reduced: {original_confidence:.2f} -> {adjusted_confidence:.2f}")

                # If confidence drops too low, filter out
                if adjusted_confidence < 0.15:
                    self.total_anomalies_filtered += 1
                    return False, adjusted_confidence

        # Anomaly should be reported with adjusted confidence
        return True, adjusted_confidence

    def _match_ip_pattern(self, ip: str, pattern: str) -> bool:
        """
        Match IP against pattern.

        Patterns:
        - Exact: "10.0.1.100"
        - Wildcard: "10.0.1.*"
        - CIDR: "10.0.1.0/24" (not implemented yet, treated as no match)
        """
        if pattern == "*":
            return True
        if pattern == ip:
            return True
        if '*' in pattern:
            # Convert to regex pattern
            pattern_regex = pattern.replace('.', '\\.').replace('*', '.*')
            import re
            return bool(re.match(f"^{pattern_regex}$", ip))
        return False

    def _match_port_pattern(self, port: int, pattern: str) -> bool:
        """
        Match port against pattern.

        Patterns:
        - Exact: "502"
        - Wildcard: "*"
        - Range: "1000-2000" (not implemented yet)
        """
        if pattern == "*":
            return True
        try:
            if '-' in pattern:
                # Range pattern
                start, end = pattern.split('-')
                return int(start) <= port <= int(end)
            else:
                # Exact match
                return port == int(pattern)
        except ValueError:
            return False

    def add_whitelist_rule(self, rule: 'WhitelistRule'):
        """Add a new whitelist rule."""
        self.whitelist_rules.append(rule)
        logger.info(f"Added whitelist rule: {rule.name}")

    def remove_whitelist_rule(self, rule_id: str) -> bool:
        """Remove a whitelist rule by ID."""
        for i, rule in enumerate(self.whitelist_rules):
            if rule.rule_id == rule_id:
                removed = self.whitelist_rules.pop(i)
                logger.info(f"Removed whitelist rule: {removed.name}")
                return True
        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get baseline engine statistics."""
        stable_baselines = sum(1 for b in self.baselines.values() if b.is_stable)
        return {
            'total_baselines': len(self.baselines),
            'stable_baselines': stable_baselines,
            'learning_baselines': len(self.baselines) - stable_baselines,
            'whitelist_rules': len(self.whitelist_rules),
            'active_rules': sum(1 for r in self.whitelist_rules if r.enabled),
            'total_events_learned': self.total_events_learned,
            'total_anomalies_filtered': self.total_anomalies_filtered,
        }
