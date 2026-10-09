"""Capture file readers (PCAP / PCAPNG) and link-layer handling."""
import struct

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap, PcapNgWriter, CookedLinux  # noqa: F401

from ot_pcap_analyzer.parsers import iter_capture
import pcap_factory as pf


def _modbus_pkt(ts=1_767_225_600.5):
    p = Ether(src=pf.MAC_HMI, dst=pf.MAC_PLC) / IP(src=pf.HMI, dst=pf.PLC) / TCP(sport=50000, dport=502, flags="PA") / \
        Raw(pf.modbus(1, 1, 3, struct.pack(">HH", 0, 10)))
    p.time = ts
    return p


def test_pcap_little_endian_roundtrip(tmp_path):
    path = tmp_path / "a.pcap"
    wrpcap(str(path), [_modbus_pkt()])
    recs = list(iter_capture(str(path)))
    assert len(recs) == 1
    assert recs[0].linktype == 1
    assert abs(recs[0].ts - 1_767_225_600.5) < 1e-6


def test_pcap_big_endian_and_nanosecond(tmp_path):
    raw = bytes(_modbus_pkt())
    path = tmp_path / "be_ns.pcap"
    hdr = struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack(">IIII", 1_767_225_600, 250_000_000, len(raw), len(raw)) + raw
    path.write_bytes(hdr + rec)
    recs = list(iter_capture(str(path)))
    assert len(recs) == 1 and recs[0].data == raw
    assert abs(recs[0].ts - 1_767_225_600.25) < 1e-6


def test_pcapng_little_endian(tmp_path):
    path = tmp_path / "a.pcapng"
    w = PcapNgWriter(str(path))
    w.write(_modbus_pkt())
    w.write(_modbus_pkt(ts=1_767_225_601.0))
    w.close()
    recs = list(iter_capture(str(path)))
    assert len(recs) == 2
    assert recs[0].linktype == 1
    assert abs(recs[1].ts - 1_767_225_601.0) < 1e-3


def _pcapng_block(endian, btype, body):
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    blen = 12 + len(body)
    return struct.pack(endian + "II", btype, blen) + body + struct.pack(endian + "I", blen)


def test_pcapng_big_endian_with_tsresol_and_spb(tmp_path):
    raw = bytes(_modbus_pkt())
    e = ">"
    shb = b"\x0a\x0d\x0d\x0a" + struct.pack(">I", 28) + b"\x1a\x2b\x3c\x4d" + struct.pack(">HHq", 1, 0, -1) + struct.pack(">I", 28)
    # IDB with if_tsresol = 9 (nanoseconds)
    idb_body = struct.pack(e + "HHI", 1, 0, 65535) + struct.pack(e + "HH", 9, 1) + b"\x09\x00\x00\x00" + struct.pack(e + "HH", 0, 0)
    ts = 1_767_225_600_123_000_000
    epb_body = struct.pack(e + "IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(raw), len(raw)) + raw
    spb_body = struct.pack(e + "I", len(raw)) + raw
    path = tmp_path / "be.pcapng"
    path.write_bytes(shb + _pcapng_block(e, 1, idb_body) + _pcapng_block(e, 6, epb_body) + _pcapng_block(e, 3, spb_body))
    recs = list(iter_capture(str(path)))
    assert len(recs) == 2
    assert recs[0].data == raw and recs[1].data == raw
    assert abs(recs[0].ts - 1_767_225_600.123) < 1e-6


def test_linux_cooked_capture_is_analyzed(tmp_path, analyze):
    p = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x00\x0c\x29\x11\x11\x11\x00\x00", proto=0x0800) / \
        IP(src=pf.HMI, dst=pf.PLC) / TCP(sport=50000, dport=502, flags="PA") / Raw(pf.modbus(1, 1, 6, struct.pack(">HH", 300, 5)))
    p.time = 1_767_225_600.0
    path = tmp_path / "sll.pcap"
    wrpcap(str(path), [p], linktype=113)
    a = analyze(str(path))
    assert a.protocol_counts["MODBUS_TCP"] == 1
    assert a.ot_events[0].function_code == 6


@pytest.mark.parametrize("content,exc", [
    (b"\x00" * 10, ValueError),            # too short
    (b"\xde\xad\xbe\xef" + b"\x00" * 40, ValueError),  # bad magic
])
def test_invalid_files_raise(tmp_path, content, exc):
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(exc):
        list(iter_capture(str(path)))


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        list(iter_capture("/nonexistent/x.pcap"))


def test_truncated_pcap_stops_cleanly(tmp_path):
    path = tmp_path / "t.pcap"
    wrpcap(str(path), [_modbus_pkt(), _modbus_pkt()])
    data = path.read_bytes()
    path.write_bytes(data[:-10])
    assert len(list(iter_capture(str(path)))) == 1


def test_ethernet_padding_is_not_treated_as_payload(tmp_path, analyze):
    # Pure ACK followed by a 12-byte link-layer trailer that happens to look like
    # a Modbus request: bytes beyond the IP total length must be ignored.
    trailer = pf.modbus(1, 1, 3, struct.pack(">HH", 0, 1))
    p = Ether(src=pf.MAC_HMI, dst=pf.MAC_PLC) / IP(src=pf.HMI, dst=pf.PLC) / TCP(sport=50000, dport=502, flags="A") / Raw(trailer)
    raw = bytearray(bytes(p))
    struct.pack_into(">H", raw, 14 + 2, 40)  # IP total length excludes the trailer
    path = tmp_path / "pad.pcap"
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(hdr + struct.pack("<IIII", 1_767_225_600, 0, len(raw), len(raw)) + bytes(raw))
    a = analyze(str(path))
    assert a.packets_parsed == 1
    assert len(a.ot_events) == 0
