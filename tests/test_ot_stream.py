"""OT TCP stream reassembly: several PDUs per segment, PDUs split across segments."""
import struct

from scapy.all import IP, TCP, Ether, Raw, wrpcap

from ot_pcap_analyzer.ot_stream import (OTStreamReassembler, frame_dnp3, frame_enip, frame_iec104,
                                        frame_modbus, frame_mqtt, frame_opcua, frame_tpkt)
import pcap_factory as pf

READ = pf.modbus(1, 1, 3, struct.pack(">HH", 0, 10))
WRITE = pf.modbus(2, 1, 6, struct.pack(">HH", 300, 7))


def test_framers_compute_pdu_lengths():
    assert frame_modbus(READ) == len(READ)
    assert frame_tpkt(pf.s7_job(0x04, b"\x01")) == len(pf.s7_job(0x04, b"\x01"))
    assert frame_iec104(pf.iec104_i(45)) == len(pf.iec104_i(45))
    assert frame_enip(pf.enip_rr(0x4C)) == len(pf.enip_rr(0x4C))
    assert frame_dnp3(pf.dnp3(0x01)) == 10 + 6 + 2
    assert frame_opcua(pf.opcua_msg(631)) == len(pf.opcua_msg(631))
    assert frame_mqtt(pf.mqtt_publish()) == len(pf.mqtt_publish())
    assert frame_modbus(b"\x00\x01") is None          # need more data
    assert frame_modbus(b"\x00\x01\x12\x34\x00\x06\x01") == -1  # bad protocol id


def test_multiple_pdus_in_one_segment():
    r = OTStreamReassembler()
    assert r.feed(("a", "b", 1, 502), 1000, READ + WRITE, frame_modbus) == [READ, WRITE]


def test_pdu_split_across_segments():
    r = OTStreamReassembler()
    assert r.feed(("a", "b", 1, 502), 1000, READ[:5], frame_modbus) == []
    assert r.feed(("a", "b", 1, 502), 1005, READ[5:] + WRITE[:3], frame_modbus) == [READ]
    assert r.feed(("a", "b", 1, 502), 1000 + len(READ) + 3, WRITE[3:], frame_modbus) == [WRITE]


def test_retransmission_is_ignored():
    r = OTStreamReassembler()
    assert r.feed(("a", "b", 1, 502), 1000, READ, frame_modbus) == [READ]
    assert r.feed(("a", "b", 1, 502), 1000, READ, frame_modbus) == []
    assert r.stats["retransmissions"] == 1


def test_gap_flushes_partial_data():
    r = OTStreamReassembler()
    assert r.feed(("a", "b", 1, 502), 1000, READ[:5], frame_modbus) == []
    # segment after a capture gap: partial data is handed over, new PDU parsed
    assert r.feed(("a", "b", 1, 502), 5000, WRITE, frame_modbus) == [READ[:5], WRITE]


def test_unaligned_data_passes_through():
    r = OTStreamReassembler()
    assert r.feed(("a", "b", 1, 502), 1000, b"\xff" * 20, frame_modbus) == [b"\xff" * 20]


def _write(path, pkts):
    for i, p in enumerate(pkts):
        p.time = 1_767_225_600 + i * 0.01
    wrpcap(str(path), pkts)


def _seg(seq, payload, sport=50000, dport=502, flags="PA"):
    return Ether() / IP(src=pf.HMI, dst=pf.PLC) / TCP(sport=sport, dport=dport, seq=seq, flags=flags) / Raw(payload)


def test_analyzer_counts_every_pdu(tmp_path, analyze):
    path = tmp_path / "pipelined.pcap"
    iframe = pf.iec104_i(45)
    sframe = bytes([0x68, 4, 0x01, 0, 0x02, 0])
    _write(path, [
        _seg(1000, READ + WRITE),                                    # 2 PDUs in 1 segment
        _seg(1000 + len(READ + WRITE), READ[:4]),                    # PDU split ...
        _seg(1004 + len(READ + WRITE), READ[4:]),                    # ... across 2 segments
        _seg(1000 + 2 * len(READ) + len(WRITE), READ),               # (new PDU)
        _seg(1000 + 2 * len(READ) + len(WRITE), READ),               # retransmission
        _seg(7000, iframe + sframe, sport=50001, dport=2404),        # IEC-104 I + S frame
    ])
    a = analyze(str(path))
    assert a.protocol_counts["MODBUS_TCP"] == 4
    assert a.function_counts["MODBUS_TCP"][6] == 1
    assert a.protocol_counts["IEC_104"] == 2


def test_mqtt_over_tls_is_not_decoded(tmp_path, analyze):
    path = tmp_path / "tls.pcap"
    tls_hello = b"\x16\x03\x01\x00\x50" + b"\x01" * 80
    _write(path, [_seg(1000, tls_hello, dport=8883)])
    a = analyze(str(path))
    assert a.protocol_counts.get("MQTT", 0) == 0
