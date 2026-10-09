"""
Behavioural profiling of OT traffic
===================================

:class:`BehaviorProfiler` looks at the whole list of decoded OT events of a
capture *after* parsing. The beginning of the capture is used as a learning
window ("what normal looks like"); everything after it is compared against
what was learnt:

``OT_NEW_MASTER``          a host starts sending requests to (or publishing on
                           behalf of) a known OT device it never talked to before
``OT_NEW_DEVICE``          an OT server / publisher that did not exist at all
                           during learning
``OT_NEW_FUNCTION``        a known master uses a function code it never used
``OT_POLLING_DEVIATION``   a periodic polling flow stops, is interrupted or
                           turns into a request storm
``OT_VALUE_OUT_OF_RANGE``  a written value / setpoint far outside the learnt range

The analysis is deterministic and runs in O(n log n) (one sort, then linear
passes), so it is fine for captures with hundreds of thousands of events.

The module also exposes a few small helpers (:func:`event_op`,
:func:`infer_is_request`, :func:`is_dangerous`, :func:`numeric_value`) that
interpret the protocol-independent ``event.details`` vocabulary (see
``ot_pcap_analyzer/protocols/base.py``) and fall back gracefully for events
whose ``details`` dict is empty.
"""
from __future__ import annotations

import math
from bisect import bisect_right
from collections import defaultdict
from statistics import median
from typing import Any, Dict, List, Optional, Tuple

from ..models import SecurityAnomaly
from ..utils import logger

# --------------------------------------------------------------------------- helpers

#: Operations that change process values, device state, program or configuration.
DANGEROUS_OPS = frozenset({
    "WRITE", "SETPOINT", "FIRMWARE_UPDATE", "CONFIG_WRITE", "FORCE", "MEMORY_CLEAR",
    "RESTART", "FACTORY_RESET", "SET_IP", "SET_NAME", "CLOCK_SET",
})
DANGEROUS_OP_PREFIXES = ("CONTROL", "PLC_", "PROGRAM_")
DANGEROUS_OP_TYPES = frozenset({"WRITE", "CONTROL", "READ_WRITE"})

#: Operations whose ``details["value"]`` is a value written to the process.
WRITE_LIKE_OPS = frozenset({"WRITE", "SETPOINT", "CONTROL_EXECUTE", "CONTROL_DIRECT"})

#: Publish/subscribe (multicast, layer-2) protocols: the sender is a "publisher".
PUBLISH_PROTOCOLS = frozenset({"IEC_61850_GOOSE", "IEC_61850_SV", "PROFINET_RT"})

EPHEMERAL_PORT_START = 49152


def protocol_name(event) -> str:
    """Name of the event protocol (``OTProtocol.name``), robust to plain strings."""
    proto = getattr(event, "protocol", None)
    name = getattr(proto, "name", None)
    return name if isinstance(name, str) else str(proto)


def event_details(event) -> Dict[str, Any]:
    details = getattr(event, "details", None)
    return details if isinstance(details, dict) else {}


def event_op(event) -> str:
    """Canonical operation of an event.

    Uses ``details["op"]`` when present, otherwise derives ``WRITE`` / ``CONTROL``
    / ``READ`` from ``operation_type``. Returns ``""`` when unknown.
    """
    op = event_details(event).get("op")
    if isinstance(op, str) and op:
        return op.upper()
    op_type = str(getattr(event, "operation_type", "") or "").upper()
    if op_type in ("WRITE", "READ_WRITE"):
        return "WRITE"
    if op_type in ("CONTROL", "READ"):
        return op_type
    return ""


def infer_is_request(event) -> bool:
    """True if the event is a client -> server request.

    Uses ``details["is_request"]`` when known; otherwise the side using the
    higher (ephemeral) port is assumed to be the requester.
    """
    flag = event_details(event).get("is_request")
    if flag is not None:
        return bool(flag)
    try:
        sport = int(event.src_port or 0)
        dport = int(event.dst_port or 0)
    except (TypeError, ValueError):
        return False
    return sport > dport and dport < EPHEMERAL_PORT_START


def is_publication(event) -> bool:
    """True for publish/subscribe traffic (GOOSE, SV, PROFINET RT, ``op=PUBLISH``)."""
    if event_details(event).get("is_request") is True:
        return False
    return event_op(event) == "PUBLISH" or protocol_name(event) in PUBLISH_PROTOCOLS


def is_dangerous(event) -> bool:
    """True for writes, control commands, program / state / configuration changes."""
    op = event_op(event)
    if op in DANGEROUS_OPS or op.startswith(DANGEROUS_OP_PREFIXES):
        return True
    return str(getattr(event, "operation_type", "") or "").upper() in DANGEROUS_OP_TYPES


def is_write_like(event) -> bool:
    return (event_op(event) in WRITE_LIKE_OPS
            or str(getattr(event, "operation_type", "") or "").upper() == "WRITE")


def numeric_value(event) -> Optional[float]:
    """``details["value"]`` as a finite float, or None."""
    value = event_details(event).get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def event_target(event) -> str:
    target = event_details(event).get("target")
    if target is None or target == "":
        return f"{getattr(event, 'data_address', 0)}"
    return str(target)


def _merge_mitre(base: List[str], extra) -> List[str]:
    out = list(base)
    for tech in extra or ():
        if tech not in out:
            out.append(tech)
    return out


def _mad(values: List[float], center: float) -> float:
    return median(abs(v - center) for v in values)


# --------------------------------------------------------------------------- profiler

FlowKey = Tuple[str, str, str]           # (src, dst, protocol)
FuncKey = Tuple[str, str, str, int]      # (src, dst, protocol, function_code)


class _Agg:
    """Aggregation of the detection-window events behind one alert key."""
    __slots__ = ("first", "count", "dangerous", "ops", "fcs", "names", "high_risk", "extra")

    def __init__(self, event):
        self.first = event
        self.count = 0
        self.dangerous = False
        self.high_risk = False
        self.ops: set = set()
        self.fcs: set = set()
        self.names: set = set()
        self.extra: Dict[str, Any] = {}

    def add(self, event):
        self.count += 1
        if not self.dangerous and is_dangerous(event):
            self.dangerous = True
        if str(event.risk_level or "").upper() in ("HIGH", "CRITICAL"):
            self.high_risk = True
        if len(self.fcs) < 32:
            self.fcs.add(event.function_code)
            op = event_op(event)
            if op:
                self.ops.add(op)
            if event.function_name:
                self.names.add(event.function_name)


class BehaviorProfiler:
    """Learn normal OT behaviour from the start of a capture and flag deviations.

    :param learning_fraction: fraction of the capture duration used for learning.
    :param min_learning_seconds: minimum learning duration in seconds.
    :param min_learning_events: minimum number of events in the learning window;
        captures with fewer than twice this number of events are not analysed.
    """

    POLL_MIN_REQUESTS = 10
    POLL_MAX_CV = 0.3
    POLL_GAP_FACTOR = 5.0
    POLL_GAP_MIN_EXTRA = 5.0
    POLL_STORM_PERIODS = 10
    POLL_STORM_FACTOR = 5.0
    VALUE_MIN_SAMPLES = 5
    VALUE_MAD_FACTOR = 6.0

    def __init__(self, learning_fraction: float = 0.3, min_learning_seconds: float = 60.0,
                 min_learning_events: int = 50):
        if not 0.0 <= learning_fraction < 1.0:
            raise ValueError(f"learning_fraction must be in [0, 1), got {learning_fraction}")
        if min_learning_seconds < 0:
            raise ValueError(f"min_learning_seconds must be >= 0, got {min_learning_seconds}")
        if min_learning_events < 1:
            raise ValueError(f"min_learning_events must be >= 1, got {min_learning_events}")
        self.learning_fraction = float(learning_fraction)
        self.min_learning_seconds = float(min_learning_seconds)
        self.min_learning_events = int(min_learning_events)

    # ------------------------------------------------------------------ public
    def analyze(self, events: list) -> List[SecurityAnomaly]:
        """Return the behavioural anomalies of ``events`` (any order)."""
        if not events or len(events) < 2 * self.min_learning_events:
            return []
        evs = sorted(events, key=lambda e: e.timestamp)
        ts = [e.timestamp for e in evs]
        n = len(evs)
        t0, t_end = ts[0], ts[-1]
        learn_end = max(t0 + self.learning_fraction * (t_end - t0),
                        t0 + self.min_learning_seconds,
                        ts[self.min_learning_events - 1])
        split = bisect_right(ts, learn_end)
        if split >= n:
            logger.debug("BehaviorProfiler: capture too short for a detection window "
                         "(%d events, %.1fs)", n, t_end - t0)
            return []

        self._window = {
            "learning_start": t0, "learning_end": learn_end,
            "learning_events": split, "capture_end": t_end,
        }
        learned = self._learn(evs[:split])
        anomalies: List[SecurityAnomaly] = []
        anomalies += self._detect_talkers(evs[split:], learned)
        anomalies += self._detect_polling(evs[split:], learned, learn_end, t_end)
        anomalies += self._detect_values(evs[split:], learned)
        anomalies.sort(key=lambda a: (a.timestamp, a.anomaly_type, a.src_ip, a.dst_ip))
        logger.debug("BehaviorProfiler: %d anomalies (learning %d events until %.3f)",
                     len(anomalies), split, learn_end)
        return anomalies

    # ------------------------------------------------------------------ learning
    def _learn(self, learn_events) -> Dict[str, Any]:
        endpoints = set()                                   # (ip, protocol)
        talkers: set = set()                                # FlowKey
        peers: Dict[Tuple[str, str], set] = defaultdict(set)  # (dst, proto) -> {src}
        func_keys: set = set()                              # FuncKey
        funcs_by_flow: Dict[FlowKey, set] = defaultdict(set)
        poll_ts: Dict[FuncKey, List[float]] = defaultdict(list)
        values: Dict[Tuple[str, str, str], List[float]] = defaultdict(list)

        for e in learn_events:
            proto = protocol_name(e)
            src, dst = e.src_ip, e.dst_ip
            endpoints.add((src, proto))
            endpoints.add((dst, proto))
            req = infer_is_request(e)
            if req or is_publication(e):
                talkers.add((src, dst, proto))
                if len(peers[(dst, proto)]) < 64:
                    peers[(dst, proto)].add(src)
                func_keys.add((src, dst, proto, e.function_code))
                funcs_by_flow[(src, dst, proto)].add(e.function_code)
            if req:
                poll_ts[(src, dst, proto, e.function_code)].append(e.timestamp)
            if event_details(e).get("is_request") is not False and is_write_like(e):
                v = numeric_value(e)
                if v is not None:
                    values[(dst, proto, event_target(e))].append(v)

        polling: Dict[FuncKey, Dict[str, float]] = {}
        for flow, times in poll_ts.items():
            if len(times) < self.POLL_MIN_REQUESTS:
                continue
            intervals = [b - a for a, b in zip(times, times[1:])]
            mean = sum(intervals) / len(intervals)
            if mean <= 0:
                continue
            std = math.sqrt(sum((x - mean) ** 2 for x in intervals) / len(intervals))
            cv = std / mean
            period = median(intervals)
            if cv < self.POLL_MAX_CV and period > 0:
                polling[flow] = {"period": period, "cv": cv, "samples": len(times),
                                 "last": times[-1]}

        ranges: Dict[Tuple[str, str, str], Dict[str, float]] = {}
        for key, vals in values.items():
            if len(vals) < self.VALUE_MIN_SAMPLES:
                continue
            med = median(vals)
            mad = _mad(vals, med)
            ranges[key] = {"min": min(vals), "max": max(vals), "median": med, "mad": mad,
                           "mad_eff": max(mad, 0.01 * abs(med), 1e-9), "samples": len(vals)}

        return {"endpoints": endpoints, "talkers": talkers, "peers": peers,
                "func_keys": func_keys, "funcs_by_flow": funcs_by_flow, "polling": polling, "ranges": ranges}

    # ------------------------------------------------------------------ detection
    def _base_evidence(self, **extra) -> Dict[str, Any]:
        ev = dict(self._window)
        ev.update(extra)
        return ev

    def _detect_talkers(self, det_events, learned) -> List[SecurityAnomaly]:
        endpoints = learned["endpoints"]
        talkers = learned["talkers"]
        func_keys = learned["func_keys"]
        new_master: Dict[FlowKey, _Agg] = {}
        new_device: Dict[Tuple[str, str], _Agg] = {}
        new_func: Dict[FuncKey, _Agg] = {}

        for e in det_events:
            req = infer_is_request(e)
            pub = (not req) and is_publication(e)
            if not (req or pub):
                continue
            proto = protocol_name(e)
            key = (e.src_ip, e.dst_ip, proto)
            if key not in talkers:
                if (e.dst_ip, proto) in endpoints:
                    agg = new_master.get(key)
                    if agg is None:
                        agg = new_master[key] = _Agg(e)
                        agg.extra["publication"] = pub
                    agg.add(e)
                else:
                    # unknown server (request) or unknown publisher (publication)
                    dev = (e.src_ip if pub else e.dst_ip, proto)
                    if dev in endpoints:
                        continue
                    agg = new_device.get(dev)
                    if agg is None:
                        agg = new_device[dev] = _Agg(e)
                        agg.extra["publication"] = pub
                        agg.extra["peers"] = set()
                    agg.add(e)
                    peer = e.dst_ip if pub else e.src_ip
                    if len(agg.extra["peers"]) < 16:
                        agg.extra["peers"].add(peer)
                continue
            if pub and event_details(e).get("cyclic") is True:
                continue
            fkey = key + (e.function_code,)
            if fkey not in func_keys:
                agg = new_func.get(fkey)
                if agg is None:
                    agg = new_func[fkey] = _Agg(e)
                agg.add(e)

        out: List[SecurityAnomaly] = []
        for (src, dst, proto), agg in new_master.items():
            out.append(self._new_master_anomaly(src, dst, proto, agg, learned))
        for (ip, proto), agg in new_device.items():
            out.append(self._new_device_anomaly(ip, proto, agg))
        for (src, dst, proto, fc), agg in new_func.items():
            out.append(self._new_function_anomaly(src, dst, proto, fc, agg, learned))
        return out

    def _new_master_anomaly(self, src, dst, proto, agg: _Agg, learned) -> SecurityAnomaly:
        e = agg.first
        pub = agg.extra.get("publication", False)
        severity = "HIGH" if agg.dangerous else "MEDIUM"
        known = sorted(learned["peers"].get((dst, proto), ()))[:10]
        role = f"new {proto} publisher" if pub else f"new {proto} master"
        if pub:
            desc = (f"New {proto} publisher: {src} started publishing to {dst} after the "
                    f"learning window; this publisher was never seen for that destination during "
                    f"learning (known publishers: {', '.join(known) or 'none'}). "
                    f"{agg.count} frame(s) observed.")
        else:
            desc = (f"{src} started sending {proto} requests to {dst}, a device that was "
                    f"already active during learning but never polled by this host "
                    f"(known masters: {', '.join(known) or 'none'}). {agg.count} request(s), "
                    f"operations: {', '.join(sorted(agg.ops)) or 'unknown'}"
                    + (" - including writes/control/state changes." if agg.dangerous else "."))
        evidence = self._base_evidence(
            requester=src, server=dst, protocol=proto, role="publisher" if pub else "master",
            first_seen=e.timestamp, event_count=agg.count,
            function_codes=sorted(agg.fcs), function_names=sorted(agg.names)[:10],
            operations=sorted(agg.ops), write_or_control=agg.dangerous, known_peers=known)
        return SecurityAnomaly(
            timestamp=e.timestamp, anomaly_type="OT_NEW_MASTER", severity=severity,
            src_ip=src, dst_ip=dst, protocol=proto, description=desc, evidence=evidence,
            mitre_techniques=["T0848", "T0855"],
            confidence=0.8 if agg.dangerous else 0.65,
            recommendation=(f"Confirm whether {src} is an authorised engineering station / "
                            f"HMI / IED for {dst}. If not, isolate it, review what it changed "
                            f"and restrict {proto} access to the known masters (ACL / firewall)."),
            behavior=f"{role} {src} -> {dst}",
            danger=("A rogue master can send unauthorised commands to field devices."
                    if not pub else
                    "A rogue publisher can inject spoofed status/trip messages to subscribers."),
            ot_impact=("Possible unauthorised process manipulation"
                       if agg.dangerous else "Unauthorised access to process data"),
        )

    def _new_device_anomaly(self, ip, proto, agg: _Agg) -> SecurityAnomaly:
        e = agg.first
        pub = agg.extra.get("publication", False)
        peers = sorted(agg.extra.get("peers", ()))
        what = "publisher" if pub else "server"
        desc = (f"{ip} appeared as a {proto} {what} after the learning window; it was not seen "
                f"with this protocol during learning. "
                + (f"Publishing to {', '.join(peers)}." if pub
                   else f"Contacted by {', '.join(peers)}."))
        evidence = self._base_evidence(
            device=ip, protocol=proto, role=what, first_seen=e.timestamp,
            event_count=agg.count, peers=peers, function_codes=sorted(agg.fcs),
            operations=sorted(agg.ops))
        return SecurityAnomaly(
            timestamp=e.timestamp, anomaly_type="OT_NEW_DEVICE", severity="LOW",
            src_ip=e.src_ip, dst_ip=e.dst_ip, protocol=proto, description=desc,
            evidence=evidence, mitre_techniques=[], confidence=0.5,
            recommendation=(f"Check the asset inventory for {ip}. A new {proto} {what} may be a "
                            f"legitimate commissioning change or a rogue / simulated device."),
            behavior=f"new {proto} {what} {ip}",
            danger="Unknown OT devices can be rogue devices or signs of network changes.",
            ot_impact="Asset inventory drift",
        )

    def _new_function_anomaly(self, src, dst, proto, fc, agg: _Agg, learned) -> SecurityAnomaly:
        e = agg.first
        severity = "HIGH" if (agg.dangerous or agg.high_risk) else "MEDIUM"
        known = sorted(learned["funcs_by_flow"].get((src, dst, proto), ()))[:32]
        op = event_op(e) or str(e.operation_type or "")
        desc = (f"{src} used {proto} function {fc} ({e.function_name or 'unknown'}, "
                f"op {op or 'unknown'}) towards {dst} for the first time; during learning "
                f"this master only used function codes {known}. {agg.count} occurrence(s).")
        evidence = self._base_evidence(
            requester=src, server=dst, protocol=proto, function_code=fc,
            function_name=e.function_name, op=op, risk_level=e.risk_level,
            first_seen=e.timestamp, event_count=agg.count, known_function_codes=known,
            target=event_details(e).get("target"))
        return SecurityAnomaly(
            timestamp=e.timestamp, anomaly_type="OT_NEW_FUNCTION", severity=severity,
            src_ip=src, dst_ip=dst, protocol=proto, description=desc, evidence=evidence,
            mitre_techniques=_merge_mitre(["T0855"], e.mitre_techniques),
            confidence=0.75 if severity == "HIGH" else 0.6,
            recommendation=(f"Verify with operations/engineering whether {e.function_name or fc} "
                            f"from {src} to {dst} was a planned action (maintenance, change "
                            f"request). If not, investigate the source host."),
            behavior=f"new function {fc} on {proto} {src} -> {dst}",
            danger=("New write/control/program functions can alter the process or the device."
                    if severity == "HIGH" else "Unusual function use may indicate reconnaissance."),
            ot_impact=("Possible unauthorised command" if severity == "HIGH"
                       else "Changed communication pattern"),
        )

    def _detect_polling(self, det_events, learned, learn_end: float,
                        t_end: float) -> List[SecurityAnomaly]:
        polling = learned["polling"]
        if not polling:
            return []
        det_ts: Dict[FuncKey, List[float]] = defaultdict(list)
        first_ev: Dict[FuncKey, Any] = {}
        for e in det_events:
            key = (e.src_ip, e.dst_ip, protocol_name(e), e.function_code)
            if key in polling and infer_is_request(e):
                det_ts[key].append(e.timestamp)
                first_ev.setdefault(key, e)

        out: List[SecurityAnomaly] = []
        for key, prof in polling.items():
            src, dst, proto, fc = key
            period = prof["period"]
            times = det_ts.get(key, [])
            gap_limit = max(self.POLL_GAP_FACTOR * period, period + self.POLL_GAP_MIN_EXTRA)

            # (a) silences: from the last learnt request through detection to capture end
            seq = [prof["last"]] + times + [t_end]
            gaps = []
            for i in range(len(seq) - 1):
                gap = seq[i + 1] - seq[i]
                if gap > gap_limit:
                    gaps.append((seq[i], seq[i + 1], gap, i + 1 == len(seq) - 1))
            if gaps:
                g_start, g_end, gap, is_end = gaps[0]
                stopped = gaps[-1][3]
                kind = "STOPPED" if is_end else "INTERRUPTED"
                longest = max(g[2] for g in gaps)
                ts_alert = max(g_start + gap_limit, learn_end)
                if kind == "STOPPED":
                    desc = (f"Periodic {proto} polling {src} -> {dst} (function {fc}, every "
                            f"~{period:.3g}s) stopped at {g_start:.3f}; no request during the "
                            f"last {gap:.1f}s of the capture.")
                else:
                    desc = (f"Periodic {proto} polling {src} -> {dst} (function {fc}, every "
                            f"~{period:.3g}s) was interrupted for {gap:.1f}s "
                            f"({len(gaps)} silence(s) > {gap_limit:.1f}s"
                            + (", polling finally stopped" if stopped else "") + ").")
                out.append(SecurityAnomaly(
                    timestamp=ts_alert, anomaly_type="OT_POLLING_DEVIATION", severity="MEDIUM",
                    src_ip=src, dst_ip=dst, protocol=proto, description=desc,
                    evidence=self._base_evidence(
                        deviation=kind, requester=src, server=dst, protocol=proto,
                        function_code=fc, expected_period=period, period_cv=prof["cv"],
                        learning_requests=prof["samples"], gap_threshold=gap_limit,
                        gap_start=g_start, gap_end=g_end, gap_seconds=gap,
                        gap_count=len(gaps), longest_gap=longest,
                        polling_resumed=not stopped, detection_requests=len(times)),
                    mitre_techniques=["T0814", "T0815"], confidence=0.65,
                    recommendation=("Check that the master (SCADA/HMI) and the device are "
                                    "healthy; loss of polling means loss of view. Look for "
                                    "denial-of-service, network failure or a master that was "
                                    "replaced / stopped."),
                    behavior=f"polling {kind.lower()} {src} -> {dst}",
                    danger="Operators may lose visibility of the process (loss of view).",
                    ot_impact="Loss of view / loss of control",
                ))

            # (b) storms: too many requests in a sliding window of N periods
            if len(times) > self.POLL_STORM_FACTOR * self.POLL_STORM_PERIODS:
                window = self.POLL_STORM_PERIODS * period
                limit = self.POLL_STORM_FACTOR * self.POLL_STORM_PERIODS
                i = 0
                first_hit = None
                max_count = 0
                for j, t in enumerate(times):
                    while t - times[i] > window:
                        i += 1
                    cnt = j - i + 1
                    if cnt > limit:
                        if first_hit is None:
                            first_hit = (times[i], t)
                        max_count = max(max_count, cnt)
                if first_hit is not None:
                    out.append(SecurityAnomaly(
                        timestamp=first_hit[1], anomaly_type="OT_POLLING_DEVIATION",
                        severity="MEDIUM", src_ip=src, dst_ip=dst, protocol=proto,
                        description=(f"Polling storm on {proto} {src} -> {dst} (function {fc}): "
                                     f"up to {max_count} requests within {window:.3g}s where "
                                     f"~{self.POLL_STORM_PERIODS} were expected "
                                     f"(learnt period {period:.3g}s)."),
                        evidence=self._base_evidence(
                            deviation="STORM", requester=src, server=dst, protocol=proto,
                            function_code=fc, expected_period=period, period_cv=prof["cv"],
                            learning_requests=prof["samples"], window_seconds=window,
                            expected_in_window=self.POLL_STORM_PERIODS,
                            max_in_window=max_count, storm_start=first_hit[0],
                            detection_requests=len(times)),
                        mitre_techniques=["T0814"], confidence=0.7,
                        recommendation=("Identify why the request rate exploded (misconfigured "
                                        "master, flooding tool, replay). Excessive request rates "
                                        "can saturate PLC communication processors."),
                        behavior=f"request storm {src} -> {dst}",
                        danger="Request floods can exhaust device resources (denial of service).",
                        ot_impact="Possible denial of control / view",
                    ))
        return out

    def _detect_values(self, det_events, learned) -> List[SecurityAnomaly]:
        ranges = learned["ranges"]
        if not ranges:
            return []
        hits: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for e in det_events:
            if event_details(e).get("is_request") is False or not is_write_like(e):
                continue
            v = numeric_value(e)
            if v is None:
                continue
            key = (e.dst_ip, protocol_name(e), event_target(e))
            prof = ranges.get(key)
            if prof is None:
                continue
            if prof["min"] <= v <= prof["max"]:
                continue
            dev = abs(v - prof["median"])
            if dev <= self.VALUE_MAD_FACTOR * prof["mad_eff"]:
                continue
            hit = hits.get(key)
            if hit is None:
                hits[key] = {"event": e, "value": v, "occurrences": 1, "max_dev": dev,
                             "extreme": v, "values": [v]}
            else:
                hit["occurrences"] += 1
                if len(hit["values"]) < 10:
                    hit["values"].append(v)
                if dev > hit["max_dev"]:
                    hit["max_dev"], hit["extreme"] = dev, v

        out: List[SecurityAnomaly] = []
        for (dst, proto, target), hit in hits.items():
            e = hit["event"]
            prof = ranges[(dst, proto, target)]
            v = hit["value"]
            desc = (f"{e.src_ip} wrote {v:g} to {target} on {dst} ({proto}); during learning the "
                    f"values written there stayed within [{prof['min']:g}, {prof['max']:g}] "
                    f"(median {prof['median']:g}). Deviation = "
                    f"{hit['max_dev'] / prof['mad_eff']:.1f} x MAD; "
                    f"{hit['occurrences']} out-of-range write(s).")
            out.append(SecurityAnomaly(
                timestamp=e.timestamp, anomaly_type="OT_VALUE_OUT_OF_RANGE", severity="HIGH",
                src_ip=e.src_ip, dst_ip=dst, protocol=proto, description=desc,
                evidence=self._base_evidence(
                    target=target, value=v, learned_min=prof["min"], learned_max=prof["max"],
                    learned_median=prof["median"], learned_mad=prof["mad"],
                    learned_samples=prof["samples"],
                    deviation_mads=hit["max_dev"] / prof["mad_eff"],
                    extreme_value=hit["extreme"], occurrences=hit["occurrences"],
                    values=hit["values"], function_code=e.function_code,
                    function_name=e.function_name, op=event_op(e)),
                mitre_techniques=["T0836", "T0831"], confidence=0.8,
                recommendation=(f"Verify the physical process at {dst} ({target}) and confirm "
                                f"with operations that a value of {v:g} is intended; check the "
                                f"engineering limits and who issued the write ({e.src_ip})."),
                behavior=f"out-of-range write {v:g} to {target}",
                danger="Setpoints outside the normal range can damage equipment or endanger safety.",
                ot_impact="Possible manipulation of control / unsafe process state",
            ))
        return out
