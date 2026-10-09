"""Behavioural tests for content / HTTP decoders and HTTP session tracking in ot_pcap_analyzer.parsers."""
import base64
import binascii
import gzip
import random
import zlib
from urllib.parse import quote

import pytest

from ot_pcap_analyzer import parsers
from ot_pcap_analyzer.parsers import (
    ContentDecoder, EnhancedHTTPStreamDecoder, HTTPSessionTracker, HTTPStreamDecoder,
)

SHELL = b"<?php system($_GET['c']); ?>"
TEXT = b"The quick brown fox jumps over the lazy dog, again and again."


# =========================================================== ContentDecoder: single decoders
def test_gzip_roundtrip_and_failure():
    d = ContentDecoder()
    assert d.decode_gzip(gzip.compress(TEXT)) == (TEXT, True, "")
    out, ok, err = d.decode_gzip(b"not gzip at all")
    assert out == b"not gzip at all" and ok is False and err


def test_deflate_zlib_and_raw():
    d = ContentDecoder()
    assert d.decode_deflate(zlib.compress(TEXT)) == (TEXT, True, "")
    raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw_data = raw.compress(TEXT) + raw.flush()
    assert d.decode_deflate(raw_data) == (TEXT, True, "")
    out, ok, err = d.decode_deflate(b"\x00\x01garbage")
    assert ok is False and out == b"\x00\x01garbage" and err


@pytest.mark.parametrize("method,encode", [
    ("decode_gzip", gzip.compress),
    ("decode_deflate", zlib.compress),
])
def test_compression_output_is_size_limited(method, encode):
    d = ContentDecoder(max_output_size=10)
    out, ok, err = getattr(d, method)(encode(TEXT))
    assert ok and err == "truncated" and out == TEXT[:10]


def test_raw_deflate_output_is_size_limited():
    c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    data = c.compress(TEXT) + c.flush()
    out, ok, err = ContentDecoder(max_output_size=5).decode_deflate(data)
    assert (out, ok, err) == (TEXT[:5], True, "truncated")


def test_brotli_without_library_reports_failure():
    if parsers.HAS_BROTLI:
        pytest.skip("brotli installed")
    assert ContentDecoder().decode_brotli(b"xyz") == (b"xyz", False, "brotli not installed")


def test_base64_handles_whitespace_and_missing_padding():
    d = ContentDecoder()
    enc = base64.b64encode(b"hello!").rstrip(b"=")  # 'aGVsbG8h' (no padding needed) -> use odd one
    assert d.decode_base64(enc) == (b"hello!", True, "")
    enc2 = base64.b64encode(b"hi").rstrip(b"=")
    assert d.decode_base64(enc2) == (b"hi", True, "")
    wrapped = base64.b64encode(TEXT)
    wrapped = wrapped[:20] + b"\r\n" + wrapped[20:40] + b" " + wrapped[40:]
    assert d.decode_base64(wrapped) == (TEXT, True, "")


def test_base64_falls_back_to_urlsafe_alphabet():
    raw = bytes([0xfb, 0xff, 0xfe, 0xfa]) * 4
    enc = base64.urlsafe_b64encode(raw)
    assert b"-" in enc or b"_" in enc
    assert ContentDecoder().decode_base64(enc) == (raw, True, "")


def test_hex_decoding_with_prefixes_and_errors():
    d = ContentDecoder()
    assert d.decode_hex(binascii.hexlify(SHELL)) == (SHELL, True, "")
    escaped = "".join(f"\\x{b:02x}" for b in b"abc").encode()
    assert d.decode_hex(escaped) == (b"abc", True, "")
    assert d.decode_hex(b"0x41 0x42") == (b"AB", True, "")
    out, ok, err = d.decode_hex(b"abc")  # odd length
    assert out == b"abc" and ok is False and err


def test_url_decoding():
    assert ContentDecoder().decode_url(b"cmd%3D%2Fbin%2Fsh%20-c") == (b"cmd=/bin/sh -c", True, "")


def test_decode_single_dispatch_and_unknown():
    d = ContentDecoder()
    assert d.decode_single(gzip.compress(TEXT), "gzip") == (TEXT, True, "")
    assert d.decode_single(b"abc", "rot13") == (b"abc", False, "Unknown encoding: rot13")


# =========================================================== ContentDecoder: detection
@pytest.mark.parametrize("data,expected", [
    (b"", "none"),
    (b"x", "none"),
    (gzip.compress(TEXT), "gzip"),
    (zlib.compress(TEXT), "deflate"),
    (zlib.compress(TEXT, 1), "deflate"),
    (zlib.compress(TEXT, 9), "deflate"),
    (quote(SHELL.decode(), safe="").encode(), "url"),
    (b"%41%42", "url"),                       # dense url encoding (ratio > 0.1)
    (base64.b64encode(TEXT), "base64"),
    (b"  " + base64.b64encode(TEXT) + b"\n", "base64"),
    (b"plain readable text without encoding", "none"),
    (b"short==", "none"),
])
def test_detect_encoding(data, expected):
    assert ContentDecoder().detect_encoding(data) == expected


def test_detect_encoding_sparse_percent_is_not_url():
    data = b"a" * 100 + b"%20" + b"b" * 100
    assert ContentDecoder().detect_encoding(data) == "none"


# Regression test: parsers.py ContentDecoder.detect_encoding checks BASE64_PATTERN before HEX_PATTERN; every hex string also matches the base64 alphabet, so 'hex' is unr
def test_detect_encoding_recognises_hex():
    assert ContentDecoder().detect_encoding(binascii.hexlify(SHELL)) == "hex"


# =========================================================== ContentDecoder: multi-layer
def test_multilayer_auto_base64_then_gzip():
    data = base64.b64encode(gzip.compress(SHELL))
    r = ContentDecoder().decode_multilayer(data)
    assert r["final_payload"] == SHELL
    assert [s["encoding"] for s in r["steps"]] == ["base64", "gzip"]
    assert [s["layer"] for s in r["steps"]] == [1, 2]
    assert r["total_layers"] == 2 and r["success"] is True
    assert r["steps"][0]["input_size"] == len(data)
    assert r["steps"][1]["output_size"] == len(SHELL)
    assert "system" in r["steps"][1]["output_preview"]


def test_multilayer_respects_max_layers():
    data = TEXT
    for _ in range(4):
        data = base64.b64encode(data)
    r = ContentDecoder(max_layers=2).decode_multilayer(data)
    assert r["total_layers"] == 2
    expected = base64.b64decode(base64.b64decode(data))
    assert r["final_payload"] == expected
    full = ContentDecoder(max_layers=5).decode_multilayer(data)
    assert full["final_payload"] == TEXT and full["total_layers"] == 4


def test_multilayer_nothing_to_decode():
    r = ContentDecoder().decode_multilayer(b"hello world")
    assert r == {"final_payload": b"hello world", "steps": [], "success": False, "total_layers": 0}


def test_multilayer_forced_encodings_in_order():
    data = quote(base64.b64encode(SHELL).decode(), safe="").encode()
    r = ContentDecoder().decode_multilayer(data, forced_encodings=["url", "base64"])
    assert r["final_payload"] == SHELL
    assert [s["encoding"] for s in r["steps"]] == ["url", "base64"]


def test_multilayer_forced_failure_stops_chain():
    r = ContentDecoder().decode_multilayer(b"not compressed", forced_encodings=["gzip", "base64"])
    assert r["final_payload"] == b"not compressed"
    assert len(r["steps"]) == 1 and r["steps"][0]["success"] is False and r["steps"][0]["error"]
    assert r["success"] is False


def test_multilayer_forced_respects_max_layers():
    data = base64.b64encode(base64.b64encode(TEXT))
    r = ContentDecoder(max_layers=1).decode_multilayer(data, forced_encodings=["base64", "base64"])
    assert r["total_layers"] == 1 and r["final_payload"] == base64.b64encode(TEXT)


def test_multilayer_gzip_bomb_is_truncated():
    bomb = gzip.compress(b"<" * 100_000)  # not base64/hex/url, so no further layers
    r = ContentDecoder(max_output_size=1000).decode_multilayer(bomb)
    assert len(r["final_payload"]) == 1000
    assert r["steps"][0]["error"] == "truncated" and r["steps"][0]["success"]


# =========================================================== HTTPStreamDecoder
def test_decode_chunked_basic_and_extensions():
    d = HTTPStreamDecoder()
    assert d.decode_chunked(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n") == (b"Wikipedia", True, "")
    assert d.decode_chunked(b"4;name=v\r\nWiki\r\nA\r\n0123456789\r\n0\r\n\r\n") == (
        b"Wiki0123456789", True, "")


@pytest.mark.parametrize("body,expected", [
    (b"4\r\nWiki\r\nzz\r\nmore\r\n0\r\n\r\n", b"Wiki"),   # invalid size line stops decoding
    (b"4\r\nWiki\r\n20\r\nshort", b"Wiki"),               # truncated chunk
    (b"no crlf at all", b""),
    (b"", b""),
])
def test_decode_chunked_malformed_returns_partial(body, expected):
    assert HTTPStreamDecoder().decode_chunked(body) == (expected, True, "")


def test_parse_headers():
    h = HTTPStreamDecoder().parse_headers(
        b"Host: example.com\r\nContent-Type:  text/html \r\n\r\nX-Empty:\r\nbogus line\r\nA: b: c")
    assert h == {"host": "example.com", "content-type": "text/html", "x-empty": "", "a": "b: c"}


def test_decode_stream_request_with_gzip_body():
    body = gzip.compress(SHELL)
    raw = (b"POST /upload.php HTTP/1.1\r\nHost: web\r\nContent-Encoding: gzip\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    r = HTTPStreamDecoder().decode_stream(raw, "1.1.1.1", "2.2.2.2", 1234, 80, 5.0)
    assert r["type"] == "request" and r["method"] == "POST" and r["uri"] == "/upload.php"
    assert r["http_version"] == "1.1" and r["content_length"] == len(body)
    assert r["content_encoding"] == "gzip" and r["is_chunked"] is False
    assert r["body_raw"] == body and r["body_final"] == SHELL
    assert r["decode_success"] and r["decode_steps"][0]["encoding"] == "gzip"
    assert (r["src_ip"], r["dst_port"], r["timestamp"]) == ("1.1.1.1", 80, 5.0)
    assert r["parse_error"] == ""


def test_decode_stream_chunked_gzip_response():
    body = gzip.compress(TEXT)
    chunked = b"%x\r\n" % 10 + body[:10] + b"\r\n" + b"%x\r\n" % (len(body) - 10) + body[10:] + b"\r\n0\r\n\r\n"
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" + chunked)
    r = HTTPStreamDecoder().decode_stream(raw)
    assert r["type"] == "response" and r["status_code"] == 200 and r["status_text"] == "OK"
    assert r["is_chunked"] and r["body_decoded"] == body and r["body_final"] == TEXT
    assert [(s["layer"], s["encoding"]) for s in r["decode_steps"]] == [(1, "chunked"), (2, "gzip")]


def test_decode_stream_auto_decodes_base64_body():
    raw = b"POST /x HTTP/1.0\r\nHost: a\r\n\r\n" + base64.b64encode(SHELL)
    r = HTTPStreamDecoder().decode_stream(raw)
    assert r["body_final"] == SHELL
    assert [s["encoding"] for s in r["decode_steps"]] == ["base64"]


def test_decode_stream_plain_body_has_no_steps():
    r = HTTPStreamDecoder().decode_stream(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno")
    assert r["status_code"] == 404 and r["status_text"] == "Not Found"
    assert r["body_final"] == b"no" and r["decode_steps"] == [] and r["decode_success"] is False


def test_decode_stream_accepts_bare_lf_boundary():
    r = HTTPStreamDecoder().decode_stream(b"GET /a?b=1 HTTP/1.1\nHost: h\n\nbody")
    assert r["type"] == "request" and r["uri"] == "/a?b=1" and r["body_raw"] == b"body"
    assert r["headers"] == {"host": "h"}


@pytest.mark.parametrize("raw,error", [
    (b"GET / HTTP/1.1\r\nHost: x", "No header/body boundary found"),
    (b"FOO bar\r\n\r\n", "Invalid HTTP first line"),
    (b"\x00\x01\x02\r\n\r\n", "Invalid HTTP first line"),
])
def test_decode_stream_parse_errors(raw, error):
    r = HTTPStreamDecoder().decode_stream(raw)
    assert r["parse_error"] == error and r["type"] == "unknown"


def test_decode_stream_non_numeric_content_length():
    r = HTTPStreamDecoder().decode_stream(b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n")
    assert r["content_length"] == 0 and r["parse_error"] == ""


# ------------------------------------------------------- extract_payload_with_explanation
def _explain(raw):
    d = HTTPStreamDecoder()
    return d.extract_payload_with_explanation(d.decode_stream(raw, "10.0.0.1", "10.0.0.2", 4444, 80, 7.0))


def test_explanation_for_encoded_webshell():
    body = base64.b64encode(b"<?php eval($_POST['x']); system('id'); ?>")
    r = _explain(b"POST /shell.php HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n" + body)
    assert r["detected_type"] == "WEBSHELL" and r["risk_level"] == "CRITICAL"
    assert {"WEBSHELL_EVAL", "WEBSHELL_SYSTEM"} <= set(r["detection_patterns"])
    assert r["decode_explanation"] == [f"Layer 1: base64 ({len(body)} -> {len(r['final_payload'])} bytes)"]
    assert r["total_layers"] == 1 and r["raw_size"] == len(body)
    assert "decoded through 1 layers" in r["behavior_summary"]
    assert r["sha256_hash"] and len(r["sha256_hash"]) == 64
    assert (r["http_method"], r["http_uri"], r["content_type"]) == ("POST", "/shell.php", "text/plain")
    assert (r["src_ip"], r["dst_port"], r["timestamp"]) == ("10.0.0.1", 80, 7.0)


@pytest.mark.parametrize("body,dtype,risk", [
    (b"<?php echo 'hello'; ?>", "PHP_SCRIPT", "HIGH"),
    (b"<% out.println(1); %>", "JSP_SCRIPT", "HIGH"),
    (b"<html><script>alert(1)</script></html>", "JAVASCRIPT", "MEDIUM"),
    (b"MZ\x90\x00\x03\x00\x00\x00", "PE_BINARY", "CRITICAL"),
    (b"name=alice&age=30", "UNKNOWN", "LOW"),
    (b"run powershell now", "WEBSHELL", "CRITICAL"),
])
def test_explanation_payload_classification(body, dtype, risk):
    r = _explain(b"POST /x HTTP/1.1\r\nHost: h\r\n\r\n" + body)
    assert (r["detected_type"], r["risk_level"]) == (dtype, risk)
    if dtype in ("PHP_SCRIPT", "JSP_SCRIPT"):
        assert "server-side script" in r["behavior_summary"]
    if dtype == "PE_BINARY":
        assert "executable binary" in r["behavior_summary"]
    if dtype == "UNKNOWN":
        assert r["behavior_summary"] == ""


# Regression test: parsers.py extract_payload_with_explanation compares body[:2] with the 4-byte b'\\x7fELF', so ELF binaries are never detected
def test_explanation_detects_elf_binary():
    r = _explain(b"POST /x HTTP/1.1\r\nHost: h\r\n\r\n\x7fELF\x02\x01\x01\x00")
    assert r["detected_type"] == "ELF_BINARY"


def test_explanation_empty_body_and_fallbacks():
    d = HTTPStreamDecoder()
    r = d.extract_payload_with_explanation({})
    assert r["final_payload"] == b"" and r["sha256_hash"] == "" and r["detected_type"] == "UNKNOWN"
    r = d.extract_payload_with_explanation({"body_raw": b"<?php phpinfo(); ?>"})
    assert r["final_payload"] == b"<?php phpinfo(); ?>" and r["detected_type"] == "PHP_SCRIPT"
    r = d.extract_payload_with_explanation({"body_decoded": b"x", "body_raw": b"y",
                                            "decode_steps": [{"success": False}]})
    assert r["final_payload"] == b"x" and r["decode_explanation"] == []


# =========================================================== EnhancedHTTPStreamDecoder
def test_enhanced_empty_and_benign_payload():
    d = EnhancedHTTPStreamDecoder()
    assert d.analyze_http_payload(b"") == {"threat_level": "NONE", "risk_score": 0}
    r = d.analyze_http_payload(b"user=bob&page=2", uri="/index", method="GET")
    assert r["threat_level"] == "NONE" and r["risk_score"] == 0 and r["detected_threats"] == []


def test_enhanced_known_webshell_china_chopper():
    r = EnhancedHTTPStreamDecoder().analyze_http_payload(b"<?php @eval($_POST['pass']);?>")
    assert any(w["name"] == "china_chopper" for w in r["webshell_indicators"])
    assert "KNOWN_WEBSHELL_CHINA_CHOPPER" in r["detected_threats"]
    assert "PHP_EVAL" in r["detected_threats"]
    assert r["threat_level"] == "CRITICAL" and r["risk_score"] == 100


def test_enhanced_base64_layer_reveals_shell_command():
    payload = base64.b64encode(b"system('cat /etc/shadow; whoami');")
    r = EnhancedHTTPStreamDecoder().analyze_http_payload(payload)
    assert r["decode_chain"] == ["base64"] and r["obfuscation_layers"] == 1
    cmds = {c["command"]: c["severity"] for c in r["shell_commands"]}
    assert cmds["cat /etc/shadow"] == "CRITICAL" and cmds["whoami"] == "MEDIUM"
    assert {"function": "system", "severity": "CRITICAL"} in r["php_dangerous_funcs"]
    assert r["threat_level"] == "CRITICAL"


def test_enhanced_gzip_and_url_layers():
    d = EnhancedHTTPStreamDecoder()
    r = d.analyze_http_payload(gzip.compress(b"bash -c 'id'"))
    assert r["decode_chain"] == ["gzip"]
    assert any(c["command"] == "bash -c" for c in r["shell_commands"])
    assert "BINARY_GZIP_COMPRESSED" in r["detected_threats"] and r["binary_detected"]
    url = quote("passthru('ls');", safe="").encode()
    r = d.analyze_http_payload(url)
    assert r["decode_chain"] == ["url"]
    assert any(f["function"] == "passthru" for f in r["php_dangerous_funcs"])


def test_enhanced_escaped_hex_layer():
    hexed = "".join(f"\\x{b:02x}" for b in b"shell_exec('uname -a');").encode()
    r = EnhancedHTTPStreamDecoder().analyze_http_payload(hexed)
    assert r["decode_chain"][0] == "hex"
    assert any(f["function"] == "shell_exec" for f in r["php_dangerous_funcs"])


def test_enhanced_obfuscation_patterns_in_decoded_layer():
    inner = b"$$fn = chr(101).chr(118); eval(gzinflate($x)); $s='\\x65\\x76\\x61';"
    r = EnhancedHTTPStreamDecoder().analyze_http_payload(base64.b64encode(inner))
    for t in ("OBFUSCATION_VARIABLE_VARIABLE", "OBFUSCATION_CHR_CONCAT",
              "OBFUSCATION_EVAL_CHAIN", "OBFUSCATION_HEX_STRING"):
        assert t in r["detected_threats"]


# Regression test: parsers.py EnhancedHTTPStreamDecoder._detect_obfuscation_patterns eval-chain regex [\\$a-zA-Z_]+ excludes digits, so the canonical eval(base64_decode(
def test_enhanced_eval_base64_decode_chain_is_flagged():
    r = EnhancedHTTPStreamDecoder().analyze_http_payload(base64.b64encode(b"eval(base64_decode($_POST['z']));"))
    assert "OBFUSCATION_EVAL_CHAIN" in r["detected_threats"]


def test_enhanced_multipart_upload_detection():
    body = (b"------b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"cat.jpg.php\"\r\n"
            b"Content-Type: application/x-php\r\n\r\n<?php echo 1; ?>\r\n------b--")
    r = EnhancedHTTPStreamDecoder().analyze_http_payload(
        body, uri="/upload/avatar", method="POST",
        headers={"content-type": "multipart/form-data; boundary=----b"})
    assert r["file_upload_detected"] is True
    for t in ("FILE_UPLOAD_DANGEROUS_EXT_PHP", "FILE_UPLOAD_DOUBLE_EXTENSION", "SUSPICIOUS_POST_PATH_UPLOAD"):
        assert t in r["detected_threats"]
    # without the multipart header no upload is assumed
    r2 = EnhancedHTTPStreamDecoder().analyze_http_payload(body, method="GET")
    assert r2["file_upload_detected"] is False


def test_enhanced_binary_and_entropy():
    d = EnhancedHTTPStreamDecoder()
    r = d.analyze_http_payload(b"\x7fELF\x02\x01\x01" + b"\x00" * 30)
    assert r["binary_detected"] and "BINARY_ELF_BINARY" in r["detected_threats"]
    rnd = random.Random(7)
    noise = bytes(b for b in rnd.randbytes(8000) if b not in (0x25, 0x1f))[:4096]
    r = d.analyze_http_payload(noise)
    assert "HIGH_ENTROPY_PAYLOAD" in r["detected_threats"]


def test_enhanced_cache_hit_and_lru_eviction():
    d = EnhancedHTTPStreamDecoder(max_cache_size=2)
    r1 = d.analyze_http_payload(b"payload-one system(")
    assert d.analyze_http_payload(b"payload-one system(") is r1
    d.analyze_http_payload(b"payload-two")
    d.analyze_http_payload(b"payload-one system(")  # refresh one -> two becomes LRU
    d.analyze_http_payload(b"payload-three")
    assert len(d.detection_cache) == 2
    hashes = set(d.detection_cache)
    assert r1["payload_hash"] in hashes
    import hashlib
    assert hashlib.sha256(b"payload-two").hexdigest() not in hashes


@pytest.mark.parametrize("score,level", [
    (0, "NONE"), (19, "NONE"), (20, "LOW"), (39, "LOW"), (40, "MEDIUM"),
    (60, "HIGH"), (79, "HIGH"), (80, "CRITICAL"), (100, "CRITICAL"),
])
def test_enhanced_threat_level_thresholds(score, level):
    assert EnhancedHTTPStreamDecoder()._determine_threat_level(score) == level


def test_enhanced_risk_score_components():
    d = EnhancedHTTPStreamDecoder()
    base = {"webshell_indicators": [], "php_dangerous_funcs": [], "shell_commands": [],
            "obfuscation_layers": 0, "file_upload_detected": False, "binary_detected": False,
            "detected_threats": []}
    assert d._calculate_risk_score(base) == 0
    r = dict(base, shell_commands=[{"command": "ipconfig", "severity": "LOW"}],
             php_dangerous_funcs=[{"function": "fwrite", "severity": "MEDIUM"}],
             obfuscation_layers=1, detected_threats=["a", "b"])
    assert d._calculate_risk_score(r) == 5 + 10 + 15 + 10
    r = dict(base, webshell_indicators=[{}], binary_detected=True, file_upload_detected=True)
    assert d._calculate_risk_score(r) == 100


# =========================================================== HTTPSessionTracker
C, S = "10.0.0.1", "10.0.0.2"


def _add(t, data, seq, ts=1.0, sport=40000, dport=80, src=C, dst=S):
    t.add_packet(src, dst, sport, dport, seq, data, ts)
    return t._make_session_id(src, dst, sport, dport)


def test_session_unknown_and_partial_headers():
    t = HTTPSessionTracker()
    assert t.is_http_complete("nope") is False
    assert t.get_session_data("nope") == {}
    sid = _add(t, b"GET /index HTTP/1.1\r\nHost: a\r\n", 1000)
    assert t.is_http_complete(sid) is False
    _add(t, b"\r\n", 1000 + 30)
    assert t.is_http_complete(sid) is True
    assert t.sessions[sid]["http_method"] == "GET"


def test_session_content_length_completion():
    t = HTTPSessionTracker()
    hdr = b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n"
    sid = _add(t, hdr + b"0123", 1)
    assert t.sessions[sid]["content_length"] == 10
    assert t.sessions[sid]["body_received_bytes"] == 4
    assert t.is_http_complete(sid) is False
    _add(t, b"456789", 1 + len(hdr) + 4)
    assert t.is_http_complete(sid) is True
    data = t.get_session_data(sid)
    assert data["body_raw"] == b"0123456789" and data["is_complete"] is True
    assert data["content_length_expected"] == 10 and data["body_received_bytes"] == 10


def test_session_out_of_order_segments_reassembled():
    t = HTTPSessionTracker()
    part1 = b"POST /a HTTP/1.1\r\nContent-Length: 4\r\n"
    part2 = b"\r\nabcd"
    sid = _add(t, part2, 100 + len(part1))
    _add(t, part1, 100)
    assert t.is_http_complete(sid) is True
    assert t.get_session_data(sid)["body_raw"] == b"abcd"


def test_session_get_with_content_length_waits_for_body():
    t = HTTPSessionTracker()
    sid = _add(t, b"GET /q HTTP/1.1\r\nContent-Length: 3\r\n\r\n", 1)
    assert t.is_http_complete(sid) is False
    _add(t, b"abc", 1 + 39)
    assert t.is_http_complete(sid) is True


def test_session_chunked_completion():
    t = HTTPSessionTracker()
    hdr = b"POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
    sid = _add(t, hdr + b"5\r\nhello\r\n", 1)
    assert t.sessions[sid]["is_chunked"] is True
    assert t.is_http_complete(sid) is False
    _add(t, b"0\r\n\r\n", 1 + len(hdr) + 10)
    assert t.is_http_complete(sid) is True
    assert t.get_session_data(sid)["body_final"] == b"hello"


# Regression test: parsers.py HTTPSessionTracker.is_http_complete treats any b'0\\r\\n' in the stream tail as the terminating chunk, so a chunk size line like '10\\r\\n'
def test_session_chunk_size_ending_in_zero_is_not_terminator():
    t = HTTPSessionTracker()
    sid = _add(t, b"POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123", 1)
    assert t.is_http_complete(sid) is False


def test_session_200_response_without_length_or_body_is_incomplete():
    t = HTTPSessionTracker()
    sid = _add(t, b"HTTP/1.1 200 OK\r\nServer: s\r\n\r\n", 1, sport=80, dport=40000, src=S, dst=C)
    assert t.is_http_complete(sid) is False


# Regression test: parsers.py HTTPSessionTracker.add_packet stores the first token of a status line ('HTTP/1.1') as http_method, so the response branch of is_http_comple
@pytest.mark.parametrize("status", [204, 304, 100])
def test_session_bodyless_responses_complete(status):
    t = HTTPSessionTracker()
    sid = _add(t, b"HTTP/1.1 %d X\r\nServer: s\r\n\r\n" % status, 1, sport=80, dport=40000, src=S, dst=C)
    assert t.is_http_complete(sid) is True


def test_session_response_without_length_completes_on_body():
    t = HTTPSessionTracker()
    sid = _add(t, b"HTTP/1.1 200 OK\r\nServer: s\r\n\r\n", 1, sport=80, dport=40000, src=S, dst=C)
    assert t.is_http_complete(sid) is False
    _add(t, b"<html>", 1 + 30, sport=80, dport=40000, src=S, dst=C)
    assert t.is_http_complete(sid) is True


def test_session_response_with_content_length():
    t = HTTPSessionTracker()
    sid = _add(t, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 1, sport=80, dport=40000, src=S, dst=C)
    assert t.is_http_complete(sid) is True
    assert t.get_session_data(sid)["status_code"] == 200


def test_session_non_http_long_stream_never_completes():
    t = HTTPSessionTracker()
    seq = 1
    for _ in range(70):
        sid = _add(t, b"\x01" * 1024, seq)
        seq += 1024
    assert t.sessions[sid]["headers_received"] is False
    assert t.is_http_complete(sid) is False


def test_session_analysis_queue_and_listing():
    t = HTTPSessionTracker()
    s1 = _add(t, b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n", 1, sport=1)
    s2 = _add(t, b"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n", 1, sport=2)
    s3 = _add(t, b"\x16\x03\x01binary tls junk\r\n\r\n", 1, sport=3)
    assert s3 in t.sessions
    assert set(t.get_complete_sessions_for_analysis()) == {s1, s2}
    t.mark_analyzed(s1)
    assert t.get_complete_sessions_for_analysis() == [s2]
    listing = t.get_all_sessions()
    assert {d["session_id"] for d in listing} == {s1, s2}  # non-HTTP stream excluded
    assert all(d["tcp_stats"]["total_segments"] == 1 for d in listing)


def test_session_cleanup_and_clear():
    t = HTTPSessionTracker(session_timeout=10.0)
    old = _add(t, b"GET /old HTTP/1.1\r\n\r\n", 1, ts=100.0, sport=1)
    new = _add(t, b"GET /new HTTP/1.1\r\n\r\n", 1, ts=105.0, sport=2)
    t.mark_analyzed(old)
    t.cleanup_old_sessions(111.0)
    assert old not in t.sessions and new in t.sessions
    assert old not in t.analyzed_sessions
    t.cleanup_old_sessions(115.0)  # exactly at timeout: kept
    assert new in t.sessions
    t.mark_analyzed(new)
    t.clear()
    assert t.sessions == {} and t.analyzed_sessions == set()
