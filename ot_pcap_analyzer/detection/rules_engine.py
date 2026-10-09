"""
User-defined detection rules for OT events
==========================================

A small, Suricata-like rule language evaluated on decoded
:class:`~ot_pcap_analyzer.models.OTEvent` objects (not on raw packets).
Rules are written in YAML or JSON; see ``examples/rules/README.md`` for the
full schema reference. Example::

    - id: OTR-001
      name: Modbus write from outside the engineering subnet
      severity: HIGH
      mitre: [T0836, T0855]
      match:
        protocol: MODBUS_TCP
        op: [WRITE, SETPOINT]
        src_ip: ["!10.10.5.0/24"]
      threshold: {count: 20, seconds: 10, group_by: [src_ip, dst_ip]}
      cooldown_seconds: 300

Semantics:

* all keys of ``match`` must hold (AND); a list value means "any of" (OR);
* address lists: positive entries are OR-ed, ``!`` entries are AND-ed (none may match);
* ``threshold`` fires when ``count`` matching events occur within ``seconds`` in a
  group (``group_by`` fields; default: one global group);
* ``cooldown_seconds`` (default 60) suppresses repeated alerts of the same rule
  for the same group (``threshold.group_by`` or, without threshold, the
  ``(src_ip, dst_ip)`` pair).

Only the standard library is required. PyYAML is imported lazily for
``*.yml`` / ``*.yaml`` files; when it is missing those files are skipped
with a warning (JSON always works).
"""
from __future__ import annotations

import difflib
import ipaddress
import json
import math
import re
from collections import deque
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from ..constants import OTProtocol
from ..models import SecurityAnomaly
from ..utils import logger
from .behavior import event_details, event_op, infer_is_request, protocol_name

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
RISK_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RULE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
OP_RE = re.compile(r"^[A-Z0-9_]+\*?$")

TOP_LEVEL_KEYS = frozenset({
    "id", "name", "severity", "description", "recommendation", "mitre", "enabled",
    "match", "threshold", "cooldown_seconds",
})
MATCH_KEYS = frozenset({
    "protocol", "op", "function_code", "operation_type", "risk_level", "src_ip", "dst_ip",
    "src_port", "dst_port", "unit_id", "target", "value_gt", "value_lt", "value_ge",
    "value_le", "value_eq", "details", "is_request",
})
THRESHOLD_KEYS = frozenset({"count", "seconds", "group_by", "cooldown_seconds"})
GROUP_FIELDS: Dict[str, Callable[[Any], Any]] = {
    "src_ip": lambda e: e.src_ip,
    "dst_ip": lambda e: e.dst_ip,
    "protocol": protocol_name,
    "function_code": lambda e: e.function_code,
    "target": lambda e: event_details(e).get("target"),
    "unit_id": lambda e: e.unit_id,
}
DEFAULT_COOLDOWN = 60.0
DEFAULT_RECOMMENDATION = ("Review the matched event against operational records (work orders, "
                          "maintenance windows) and investigate the source host if the action "
                          "was not planned.")
RULE_FILE_SUFFIXES = (".yml", ".yaml", ".json")
_MAX_GROUPS = 100_000

# Extra ops accepted in rules: derived from operation_type for events without details["op"].
_DERIVED_OPS = frozenset({"CONTROL"})
_FALLBACK_OPS = frozenset({
    "PLC_STOP", "PLC_START", "PLC_PAUSE", "PLC_RESET", "RESTART", "PROGRAM_DOWNLOAD",
    "PROGRAM_UPLOAD", "PROGRAM_DELETE", "FIRMWARE_UPDATE", "MEMORY_CLEAR",
    "CONTROL_SELECT", "CONTROL_EXECUTE", "CONTROL_DIRECT", "CONTROL_CANCEL", "SETPOINT",
    "WRITE", "READ", "FORCE", "CONFIG_WRITE", "CLOCK_SET", "SET_IP", "SET_NAME",
    "FACTORY_RESET", "PASSWORD", "FILE_READ", "FILE_WRITE", "FILE_DELETE",
    "DIAG_LISTEN_ONLY", "LOG_CLEAR", "UNSOLICITED_DISABLE", "TRANSMISSION_OFF", "IDENTIFY",
    "INTERROGATION", "BROWSE", "SESSION_START", "SESSION_STOP", "KEEPALIVE", "PUBLISH",
    "ALARM", "STATUS", "RESPONSE", "ERROR", "OTHER",
})


def _known_ops() -> frozenset:
    try:
        from ..protocols.base import OPS  # imported lazily: optional at rule-load time
        return frozenset(OPS) | _FALLBACK_OPS | _DERIVED_OPS
    except Exception:  # pragma: no cover - protocols package unavailable / mid-edit
        return _FALLBACK_OPS | _DERIVED_OPS


class RuleError(ValueError):
    """Invalid rule specification (message names the rule id and the offending key)."""


# --------------------------------------------------------------------------- value parsing

def _as_list(value) -> list:
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _parse_int(value, rid: str, key: str, lo: int = None, hi: int = None) -> int:
    if isinstance(value, bool):
        raise RuleError(f"rule {rid}: '{key}' expects integers, got {value!r}")
    if isinstance(value, int):
        out = value
    elif isinstance(value, float) and value.is_integer():
        out = int(value)
    elif isinstance(value, str):
        try:
            out = int(value.strip(), 0)
        except ValueError:
            raise RuleError(f"rule {rid}: '{key}' has invalid integer {value!r} "
                            f"(use e.g. 16 or \"0x10\")") from None
    else:
        raise RuleError(f"rule {rid}: '{key}' expects integers, got {value!r}")
    if (lo is not None and out < lo) or (hi is not None and out > hi):
        raise RuleError(f"rule {rid}: '{key}' value {out} out of range [{lo}, {hi}]")
    return out


@lru_cache(maxsize=65536)
def _parse_address(text: str):
    """Event address -> ('ip', ip_address) | ('mac', normalised) | ('raw', text)."""
    if not isinstance(text, str):
        text = str(text)
    if MAC_RE.match(text):
        return "mac", text.lower().replace("-", ":")
    try:
        return "ip", ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return "raw", text.lower()


class _AddressSet:
    """Compiled list of IPs / CIDRs / MACs; used for both positive and negative parts."""
    __slots__ = ("ips", "nets", "macs", "raws")

    def __init__(self):
        self.ips: set = set()
        self.nets: list = []
        self.macs: set = set()
        self.raws: set = set()

    def __bool__(self):
        return bool(self.ips or self.nets or self.macs or self.raws)

    def contains(self, parsed) -> bool:
        kind, val = parsed
        if kind == "ip":
            if val in self.ips:
                return True
            for net in self.nets:
                if val.version == net.version and val in net:
                    return True
            return False
        if kind == "mac":
            return val in self.macs
        return val in self.raws


def _compile_addresses(values, rid: str, key: str) -> Callable[[Any], bool]:
    pos, neg = _AddressSet(), _AddressSet()
    any_pos = False
    for raw in _as_list(values):
        if not isinstance(raw, str) or not raw.strip():
            raise RuleError(f"rule {rid}: '{key}' entries must be non-empty strings "
                            f"(IP, CIDR, MAC or 'any'), got {raw!r}")
        text = raw.strip()
        negate = text.startswith("!")
        if negate:
            text = text[1:].strip()
        target = neg if negate else pos
        if text.lower() == "any":
            if negate:
                raise RuleError(f"rule {rid}: '{key}' entry '!any' would never match")
            any_pos = True
            continue
        if MAC_RE.match(text):
            target.macs.add(text.lower().replace("-", ":"))
            continue
        try:
            if "/" in text:
                target.nets.append(ipaddress.ip_network(text, strict=False))
            else:
                target.ips.add(ipaddress.ip_address(text))
        except ValueError:
            raise RuleError(f"rule {rid}: '{key}' has invalid address {raw!r} "
                            f"(expected IPv4/IPv6 address, CIDR, MAC or 'any')") from None
    has_pos = bool(pos) and not any_pos

    def check(addr) -> bool:
        parsed = _parse_address(addr if isinstance(addr, str) else str(addr))
        if has_pos and not pos.contains(parsed):
            return False
        if neg and neg.contains(parsed):
            return False
        return True
    return check


def _compile_ports(values, rid: str, key: str) -> Callable[[int], bool]:
    singles, ranges, neg_singles, neg_ranges = set(), [], set(), []
    for raw in _as_list(values):
        negate = False
        text = raw
        if isinstance(raw, str):
            text = raw.strip()
            if text.startswith("!"):
                negate, text = True, text[1:].strip()
            if text.lower() == "any" and not negate:
                continue
        if isinstance(text, str) and "-" in text.strip("-"):
            lo_s, hi_s = text.split("-", 1)
            lo = _parse_int(lo_s, rid, key, 0, 65535)
            hi = _parse_int(hi_s, rid, key, 0, 65535)
            if lo > hi:
                raise RuleError(f"rule {rid}: '{key}' range {raw!r} is reversed")
            (neg_ranges if negate else ranges).append((lo, hi))
        else:
            port = _parse_int(text, rid, key, 0, 65535)
            (neg_singles if negate else singles).add(port)
    has_pos = bool(singles or ranges)

    def check(port) -> bool:
        if has_pos and port not in singles and not any(lo <= port <= hi for lo, hi in ranges):
            return False
        if port in neg_singles or any(lo <= port <= hi for lo, hi in neg_ranges):
            return False
        return True
    return check


def _strict_eq(actual, expected) -> bool:
    if isinstance(expected, bool) or isinstance(actual, bool):
        return isinstance(actual, bool) and isinstance(expected, bool) and actual is expected
    return actual == expected


# --------------------------------------------------------------------------- compiled rule

class Rule:
    """A compiled rule. Build it with :meth:`Rule.compile` (or :meth:`RuleEngine.add_rule`)."""

    def __init__(self, spec: dict):
        if not isinstance(spec, dict):
            raise RuleError(f"rule specification must be a mapping, got {type(spec).__name__}")
        rid = spec.get("id")
        if rid is None or (isinstance(rid, str) and not rid.strip()):
            raise RuleError(f"rule without 'id' (name: {spec.get('name')!r}); "
                            f"every rule needs a unique id like OTR-001")
        rid = str(rid).strip()
        if not RULE_ID_RE.match(rid):
            raise RuleError(f"rule {rid}: invalid id (allowed characters: A-Z a-z 0-9 _ . -)")
        self.id = rid
        unknown = set(spec) - TOP_LEVEL_KEYS
        if unknown:
            raise RuleError(self._unknown_msg("rule key", sorted(unknown)[0], TOP_LEVEL_KEYS))

        name = spec.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RuleError(f"rule {rid}: 'name' is required (non-empty string)")
        self.name = name.strip()
        sev = str(spec.get("severity", "MEDIUM")).strip().upper()
        if sev not in SEVERITIES:
            raise RuleError(f"rule {rid}: 'severity' must be one of {', '.join(SEVERITIES)}, "
                            f"got {spec.get('severity')!r}")
        self.severity = sev
        self.description = self._opt_str(spec, "description")
        self.recommendation = self._opt_str(spec, "recommendation")
        mitre = spec.get("mitre", [])
        if mitre is None:
            mitre = []
        if not all(isinstance(m, str) and m.strip() for m in _as_list(mitre)):
            raise RuleError(f"rule {rid}: 'mitre' must be a list of technique ids like T0836")
        self.mitre = [m.strip().upper() for m in _as_list(mitre)]
        enabled = spec.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuleError(f"rule {rid}: 'enabled' must be true or false, got {enabled!r}")
        self.enabled = enabled

        match = spec.get("match", {})
        if match is None:
            match = {}
        if not isinstance(match, dict):
            raise RuleError(f"rule {rid}: 'match' must be a mapping of conditions")
        self.protocols: Optional[frozenset] = None
        self._checks: List[Callable[[Any], bool]] = []
        self._compile_match(match)

        self.threshold_count = 0
        self.threshold_seconds = 0.0
        self.group_by: Tuple[str, ...] = ()
        cooldown = spec.get("cooldown_seconds")
        threshold = spec.get("threshold")
        if threshold is not None:
            cooldown = self._compile_threshold(threshold, cooldown)
        self.cooldown = self._number(cooldown, "cooldown_seconds", DEFAULT_COOLDOWN, 0.0)
        self._group_getters = [GROUP_FIELDS[g] for g in self.group_by]
        self.anomaly_type = "CUSTOM_" + re.sub(r"[^A-Z0-9]", "_", rid.upper())
        self.spec = dict(spec)
        self.reset()

    # ------------------------------------------------------------------ compile helpers
    def _unknown_msg(self, what: str, key, allowed) -> str:
        hint = difflib.get_close_matches(str(key), sorted(allowed), n=1)
        return (f"rule {self.id}: unknown {what} '{key}'"
                + (f" (did you mean '{hint[0]}'?)" if hint else "")
                + f"; allowed: {', '.join(sorted(allowed))}")

    def _opt_str(self, spec, key) -> str:
        val = spec.get(key, "")
        if val is None:
            return ""
        if not isinstance(val, str):
            raise RuleError(f"rule {self.id}: '{key}' must be a string")
        return val.strip()

    def _number(self, val, key, default, minimum) -> float:
        if val is None:
            return float(default)
        if not _is_number(val) or not math.isfinite(val) or val < minimum:
            raise RuleError(f"rule {self.id}: '{key}' must be a number >= {minimum}, got {val!r}")
        return float(val)

    def _compile_threshold(self, threshold, cooldown):
        rid = self.id
        if not isinstance(threshold, dict):
            raise RuleError(f"rule {rid}: 'threshold' must be a mapping with count/seconds")
        for key in threshold:
            if key not in THRESHOLD_KEYS:
                raise RuleError(self._unknown_msg("threshold key", key, THRESHOLD_KEYS))
        if "count" not in threshold or "seconds" not in threshold:
            raise RuleError(f"rule {rid}: 'threshold' needs both 'count' and 'seconds'")
        self.threshold_count = _parse_int(threshold["count"], rid, "threshold.count", 1)
        self.threshold_seconds = self._number(threshold["seconds"], "threshold.seconds", 0, 0)
        if self.threshold_seconds <= 0:
            raise RuleError(f"rule {rid}: 'threshold.seconds' must be > 0")
        group_by = threshold.get("group_by") or []
        groups = []
        for g in _as_list(group_by):
            if g not in GROUP_FIELDS:
                raise RuleError(self._unknown_msg("threshold.group_by field", g, GROUP_FIELDS))
            groups.append(g)
        self.group_by = tuple(groups)
        if cooldown is None:
            cooldown = threshold.get("cooldown_seconds")
        return cooldown

    def _compile_match(self, match: dict):
        rid = self.id
        checks: List[Tuple[int, Callable[[Any], bool]]] = []   # (cost, check)
        for key, val in match.items():
            if key not in MATCH_KEYS:
                raise RuleError(self._unknown_msg("match key", key, MATCH_KEYS))
            if val is None or (isinstance(val, (list, tuple)) and not val):
                raise RuleError(f"rule {rid}: match key '{key}' has an empty value")

            if key == "protocol":
                protos = set()
                for p in _as_list(val):
                    if isinstance(p, OTProtocol):
                        protos.add(p)
                        continue
                    pname = str(p).strip().upper().replace("-", "_").replace(" ", "_")
                    if pname not in OTProtocol.__members__:
                        raise RuleError(self._unknown_msg("protocol in 'protocol'", p,
                                                          OTProtocol.__members__))
                    protos.add(OTProtocol[pname])
                self.protocols = frozenset(protos)
                names = frozenset(p.name for p in protos)
                checks.append((0, lambda e, s=names: protocol_name(e) in s))

            elif key == "op":
                known = _known_ops()
                exact, prefixes = set(), []
                for o in _as_list(val):
                    if not isinstance(o, str):
                        raise RuleError(f"rule {rid}: 'op' entries must be strings, got {o!r}")
                    o = o.strip().upper()
                    if not OP_RE.match(o):
                        raise RuleError(f"rule {rid}: invalid op {o!r} in 'op'")
                    if o.endswith("*"):
                        prefixes.append(o[:-1])
                    elif o not in known:
                        raise RuleError(self._unknown_msg("op in 'op'", o, known))
                    else:
                        exact.add(o)
                pre = tuple(prefixes)

                def op_check(e, exact=frozenset(exact), pre=pre):
                    op = event_op(e)
                    return op in exact or (bool(pre) and bool(op) and op.startswith(pre))
                checks.append((2, op_check))

            elif key in ("function_code", "unit_id"):
                codes = frozenset(_parse_int(v, rid, key) for v in _as_list(val))
                if key == "function_code":
                    checks.append((1, lambda e, s=codes: e.function_code in s))
                else:
                    checks.append((1, lambda e, s=codes: e.unit_id in s))

            elif key in ("operation_type", "risk_level"):
                vals = set()
                for v in _as_list(val):
                    if not isinstance(v, str) or not v.strip():
                        raise RuleError(f"rule {rid}: '{key}' entries must be strings")
                    v = v.strip().upper()
                    if key == "risk_level" and v not in RISK_LEVELS:
                        raise RuleError(f"rule {rid}: 'risk_level' must be among "
                                        f"{', '.join(RISK_LEVELS)}, got {v!r}")
                    vals.add(v)
                attr = key
                checks.append((1, lambda e, s=frozenset(vals), a=attr:
                               str(getattr(e, a, "") or "").upper() in s))

            elif key in ("src_ip", "dst_ip"):
                fn = _compile_addresses(val, rid, key)
                if key == "src_ip":
                    checks.append((3, lambda e, f=fn: f(e.src_ip)))
                else:
                    checks.append((3, lambda e, f=fn: f(e.dst_ip)))

            elif key in ("src_port", "dst_port"):
                fn = _compile_ports(val, rid, key)
                attr = key
                checks.append((1, lambda e, f=fn, a=attr: f(getattr(e, a, 0) or 0)))

            elif key == "target":
                regexes = []
                for pattern in _as_list(val):
                    if not isinstance(pattern, str):
                        raise RuleError(f"rule {rid}: 'target' must be a regex string")
                    try:
                        regexes.append(re.compile(pattern))
                    except re.error as exc:
                        raise RuleError(f"rule {rid}: invalid regex in 'target' "
                                        f"{pattern!r}: {exc}") from None

                def target_check(e, regexes=tuple(regexes)):
                    tgt = event_details(e).get("target")
                    if tgt is None:
                        return False
                    tgt = str(tgt)
                    return any(r.search(tgt) for r in regexes)
                checks.append((4, target_check))

            elif key.startswith("value_"):
                if not _is_number(val) or not math.isfinite(val):
                    raise RuleError(f"rule {rid}: '{key}' must be a number, got {val!r}")
                cmp = {
                    "value_gt": lambda v, x: v > x, "value_lt": lambda v, x: v < x,
                    "value_ge": lambda v, x: v >= x, "value_le": lambda v, x: v <= x,
                    "value_eq": lambda v, x: v == x,
                }[key]

                def value_check(e, x=val, cmp=cmp):
                    v = event_details(e).get("value")
                    return _is_number(v) and cmp(v, x)
                checks.append((2, value_check))

            elif key == "details":
                if not isinstance(val, dict) or not val:
                    raise RuleError(f"rule {rid}: 'details' must be a non-empty mapping "
                                    f"of key: expected value")
                items = tuple((str(k), v) for k, v in val.items())

                def details_check(e, items=items):
                    d = event_details(e)
                    for k, v in items:
                        if k not in d or not _strict_eq(d[k], v):
                            return False
                    return True
                checks.append((2, details_check))

            elif key == "is_request":
                if not isinstance(val, bool):
                    raise RuleError(f"rule {rid}: 'is_request' must be true or false")
                checks.append((2, lambda e, want=val: infer_is_request(e) is want))

        checks.sort(key=lambda c: c[0])
        self._checks = [c[1] for c in checks]

    # ------------------------------------------------------------------ runtime
    def reset(self):
        """Forget threshold / cooldown state (e.g. before analysing a new capture)."""
        self._windows: Dict[tuple, deque] = {}
        self._last_alert: Dict[tuple, float] = {}

    def matches(self, event) -> bool:
        for check in self._checks:
            if not check(event):
                return False
        return True

    def _group(self, event) -> tuple:
        if self._group_getters:
            return tuple(g(event) for g in self._group_getters)
        return ()

    def _prune(self, now: float):
        horizon = max(self.threshold_seconds, self.cooldown)
        self._windows = {k: d for k, d in self._windows.items()
                         if d and now - d[-1] <= self.threshold_seconds}
        self._last_alert = {k: t for k, t in self._last_alert.items() if now - t < horizon}

    def process(self, event) -> Optional[SecurityAnomaly]:
        """Evaluate one event (time-ordered stream) -> anomaly or None."""
        if not self.enabled or not self.matches(event):
            return None
        now = event.timestamp
        window_info = None
        if self.threshold_count:
            group = self._group(event)
            dq = self._windows.get(group)
            if dq is None:
                if len(self._windows) >= _MAX_GROUPS:
                    self._prune(now)
                dq = self._windows[group] = deque()
            dq.append(now)
            while dq and now - dq[0] > self.threshold_seconds:
                dq.popleft()
            if len(dq) < self.threshold_count:
                return None
            window_info = (len(dq), dq[0], now)
            dq.clear()
        else:
            group = (event.src_ip, event.dst_ip)
        last = self._last_alert.get(group)
        if last is not None and now - last < self.cooldown:
            return None
        if len(self._last_alert) >= _MAX_GROUPS:
            self._prune(now)
        self._last_alert[group] = now
        return self._anomaly(event, group, window_info)

    def _anomaly(self, event, group, window_info) -> SecurityAnomaly:
        d = event_details(event)
        proto = protocol_name(event)
        evidence: Dict[str, Any] = {
            "rule_id": self.id,
            "rule_name": self.name,
            "matched_event": {
                "function_name": event.function_name,
                "function_code": event.function_code,
                "op": event_op(event) or None,
                "target": d.get("target"),
                "value": d.get("value"),
            },
        }
        if window_info is not None:
            count, start, end = window_info
            evidence.update({
                "count": count, "window_seconds": self.threshold_seconds,
                "threshold_count": self.threshold_count,
                "first_match": start, "last_match": end,
                "group": dict(zip(self.group_by, group)),
            })
        description = self.name + (f": {self.description}" if self.description else "")
        if window_info is not None:
            description += (f" ({window_info[0]} matching events within "
                            f"{self.threshold_seconds:g}s)")
        return SecurityAnomaly(
            timestamp=event.timestamp, anomaly_type=self.anomaly_type, severity=self.severity,
            src_ip=event.src_ip, dst_ip=event.dst_ip, protocol=proto,
            description=description, evidence=evidence,
            mitre_techniques=list(self.mitre) if self.mitre else list(event.mitre_techniques or []),
            confidence=0.8,
            recommendation=self.recommendation or DEFAULT_RECOMMENDATION,
            behavior=(f"{event.function_name or event.function_code} {event.src_ip} -> "
                      f"{event.dst_ip} ({proto}) matched custom rule {self.id}"),
            danger=self.description or f"Matched user-defined rule '{self.name}'.",
        )

    def __repr__(self):
        return f"Rule(id={self.id!r}, severity={self.severity}, enabled={self.enabled})"


# --------------------------------------------------------------------------- engine

class RuleEngine:
    """Evaluate a set of compiled :class:`Rule` objects on a stream of OT events."""

    def __init__(self, rules: list = None):
        self._rules: List[Rule] = []
        self._ids: set = set()
        self._by_proto: Dict[str, List[Rule]] = {}
        self._generic: List[Rule] = []
        for spec in rules or []:
            self.add_rule(spec)

    # ------------------------------------------------------------------ building
    def add_rule(self, spec: Union[dict, Rule]) -> Rule:
        """Compile and add a rule; raises :class:`RuleError` with a helpful message."""
        rule = spec if isinstance(spec, Rule) else Rule(spec)
        if rule.id in self._ids:
            raise RuleError(f"rule {rule.id}: duplicate rule id")
        self._ids.add(rule.id)
        self._rules.append(rule)
        if rule.enabled:
            if rule.protocols is None:
                self._generic.append(rule)
            else:
                for p in rule.protocols:
                    self._by_proto.setdefault(p.name, []).append(rule)
        return rule

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)

    def __len__(self):
        return len(self._rules)

    def reset(self):
        for rule in self._rules:
            rule.reset()

    @staticmethod
    def _load_file(path: Path) -> Optional[list]:
        """Return the list of rule specs of a file, or None (warning logged) if unusable."""
        suffix = path.suffix.lower()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("Rules: cannot read %s: %s", path, exc)
            return None
        if suffix == ".json":
            try:
                data = json.loads(text) if text.strip() else None
            except json.JSONDecodeError as exc:
                logger.warning("Rules: invalid JSON in %s: %s - file skipped", path, exc)
                return None
        elif suffix in (".yml", ".yaml"):
            try:
                import yaml  # optional dependency
            except ImportError:
                logger.warning("Rules: PyYAML is not installed, skipping YAML rule file %s "
                               "(pip install pyyaml, or convert the rules to JSON)", path)
                return None
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                logger.warning("Rules: invalid YAML in %s: %s - file skipped", path, exc)
                return None
        else:
            logger.warning("Rules: unsupported rule file %s (expected %s) - skipped",
                           path, ", ".join(RULE_FILE_SUFFIXES))
            return None
        if data is None:
            return []
        if isinstance(data, dict) and "rules" in data:
            data = data["rules"] if data["rules"] is not None else []
        if not isinstance(data, list):
            logger.warning("Rules: %s must contain a list of rules or a mapping with a "
                           "'rules' list - file skipped", path)
            return None
        return data

    @classmethod
    def from_paths(cls, paths) -> "RuleEngine":
        """Load rules from files and/or directories (``*.yml``, ``*.yaml``, ``*.json``).

        Invalid files and invalid rules are skipped with a warning naming the
        file and the rule id; this method never raises for bad content.
        """
        if isinstance(paths, (str, Path)):
            paths = [paths]
        engine = cls()
        files: List[Path] = []
        for p in paths or []:
            p = Path(p).expanduser()
            if p.is_dir():
                files.extend(sorted(f for f in p.iterdir()
                                    if f.is_file() and f.suffix.lower() in RULE_FILE_SUFFIXES))
            elif p.is_file():
                files.append(p)
            else:
                logger.warning("Rules: path not found: %s", p)
        for f in files:
            specs = cls._load_file(f)
            if specs is None:
                continue
            loaded = 0
            for i, spec in enumerate(specs):
                rid = spec.get("id", f"#{i + 1}") if isinstance(spec, dict) else f"#{i + 1}"
                try:
                    engine.add_rule(spec)
                    loaded += 1
                except RuleError as exc:
                    logger.warning("Rules: %s: skipping invalid rule %s: %s", f, rid, exc)
            logger.info("Rules: loaded %d/%d rule(s) from %s", loaded, len(specs), f)
        return engine

    @classmethod
    def from_default_locations(cls) -> "RuleEngine":
        """Rules from ``~/.ot_pcap_analyzer/rules`` (empty engine if it does not exist)."""
        directory = Path.home() / ".ot_pcap_analyzer" / "rules"
        if directory.is_dir():
            return cls.from_paths([directory])
        return cls()

    # ------------------------------------------------------------------ evaluation
    def evaluate(self, event) -> List[SecurityAnomaly]:
        """Evaluate one event; call for each event in time order."""
        out: List[SecurityAnomaly] = []
        specific = self._by_proto.get(protocol_name(event))
        if specific:
            for rule in specific:
                a = rule.process(event)
                if a is not None:
                    out.append(a)
        for rule in self._generic:
            a = rule.process(event)
            if a is not None:
                out.append(a)
        return out

    def evaluate_many(self, events: Iterable) -> List[SecurityAnomaly]:
        """Convenience: evaluate an iterable of events (sorted by timestamp first)."""
        out: List[SecurityAnomaly] = []
        for event in sorted(events, key=lambda e: e.timestamp):
            out.extend(self.evaluate(event))
        return out
