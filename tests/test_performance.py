"""Performance regressions and correctness of multi-segment HTTP handling.

Time limits are deliberately generous (10x the measured time) so the tests are
stable on slow CI machines while still catching O(n^2) regressions, which made
these captures take minutes.
"""
import time

import pcap_factory as pf


def _timed(analyze, path):
    t = time.perf_counter()
    a = analyze(str(path))
    return a, time.perf_counter() - t


def test_long_http_upload_is_linear(tmp_path, analyze):
    b = pf._Builder()
    b.tcp(pf.HMI, pf.WEB, 51000, 80, b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 2800000\r\n\r\n")
    for _ in range(2000):
        b.tcp(pf.HMI, pf.WEB, 51000, 80, b"A" * 1400, dt=0.001)
    a, dt = _timed(analyze, b.write(tmp_path / "upload.pcap"))
    assert a.packets_parsed == 2001
    assert dt < 15, f"2,000-segment HTTP upload took {dt:.1f}s"


def test_long_text_stream_on_other_port_is_fast(tmp_path, analyze):
    b = pf._Builder()
    for _ in range(2000):
        b.tcp(pf.HMI, pf.WEB, 51000, 9000, b"A" * 1400, dt=0.001)
    _, dt = _timed(analyze, b.write(tmp_path / "text.pcap"))
    assert dt < 15, f"text stream took {dt:.1f}s (post-exploitation regexes must stay linear)"


def test_webshell_body_split_across_segments_is_detected(tmp_path, analyze):
    body = b"<?php system($_GET['c']); eval(base64_decode($_POST['x'])); ?>" + b" " * 40
    hdr = b"POST /uploads/x.php HTTP/1.1\r\nHost: web\r\nContent-Type: application/x-www-form-urlencoded\r\n" \
          b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
    b = pf._Builder()
    b.tcp(pf.ATTACKER, pf.WEB, 55000, 80, hdr)
    b.tcp(pf.ATTACKER, pf.WEB, 55000, 80, body[:20])
    b.tcp(pf.ATTACKER, pf.WEB, 55000, 80, body[20:])
    a = analyze(str(b.write(tmp_path / "split.pcap")))
    types = {x.anomaly_type for x in a.anomalies}
    assert any("PHP" in t or "WEBSHELL" in t for t in types), types


def test_chunked_request_completes(tmp_path, analyze):
    b = pf._Builder()
    b.tcp(pf.ATTACKER, pf.WEB, 55001, 80,
          b"POST /cmd HTTP/1.1\r\nHost: web\r\nTransfer-Encoding: chunked\r\n\r\n")
    b.tcp(pf.ATTACKER, pf.WEB, 55001, 80, b"20\r\ncmd=cat /etc/passwd;whoami;id;ls \r\n")
    b.tcp(pf.ATTACKER, pf.WEB, 55001, 80, b"0\r\n\r\n")
    a = analyze(str(b.write(tmp_path / "chunked.pcap")))
    tracker = a.threat_detector.http_session_tracker
    sid = tracker._make_session_id(pf.ATTACKER, pf.WEB, 55001, 80)
    assert tracker.is_http_complete(sid)


def test_throughput_mixed_capture(captures, analyze):
    a, dt = _timed(analyze, captures["attacks"])
    assert a.packets_parsed / dt > 500, f"{a.packets_parsed / dt:.0f} packets/s"
