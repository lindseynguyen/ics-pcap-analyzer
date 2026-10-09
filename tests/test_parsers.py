"""Unit tests for the OT/IT protocol parsers."""
import copy
import struct

import pytest

from ot_pcap_analyzer import constants
from ot_pcap_analyzer.parsers import ProtocolParser as P
import pcap_factory as pf

A, B = "10.0.0.1", "10.0.0.2"


def modbus(payload, sport=50000, dport=502):
    return P.parse_modbus_tcp(payload, 1.0, A, B, sport, dport, 1)


# ------------------------------------------------------------------ Modbus
def test_modbus_read_request():
    e = modbus(pf.modbus(7, 1, 3, struct.pack(">HH", 100, 10)))
    assert (e.function_code, e.operation_type, e.data_address, e.data_count) == (3, "READ", 100, 10)


def test_modbus_write_single_register():
    e = modbus(pf.modbus(7, 1, 6, struct.pack(">HH", 300, 1234)))
    assert e.operation_type == "WRITE" and e.data_address == 300 and "Value=1234" in e.notes


def test_modbus_response_is_not_counted_as_write():
    e = modbus(pf.modbus(7, 1, 6, struct.pack(">HH", 300, 1234)), sport=502, dport=50000)
    assert e.operation_type == "RESPONSE" and e.risk_level == "LOW"
    assert "(Response)" in e.function_name


def test_modbus_exception_response():
    e = modbus(pf.modbus(7, 1, 0x81, b"\x01"), sport=502, dport=50000)
    assert e.operation_type == "ERROR" and "ILLEGAL_FUNCTION" in e.function_name


def test_modbus_broadcast_write_is_critical():
    e = modbus(pf.modbus(7, 0, 6, struct.pack(">HH", 300, 1)))
    assert e.risk_level == "CRITICAL" and "BROADCAST" in e.notes and "T0806" in e.mitre_techniques


def test_modbus_rejects_garbage():
    assert modbus(b"\xff" * 20) is None
    assert modbus(b"\x00") is None


def test_parsers_do_not_mutate_constant_tables():
    before = copy.deepcopy(constants.MODBUS_FUNCTIONS)
    for _ in range(3):
        modbus(pf.modbus(7, 0, 15, struct.pack(">HHB", 0, 2000, 1) + b"\x01"))
        modbus(pf.modbus(7, 1, 90, b"\x00"))
    assert constants.MODBUS_FUNCTIONS == before


# ------------------------------------------------------------------ S7comm
@pytest.mark.parametrize("func,name", [(0x04, "Read Variable"), (0x05, "Write Variable"),
                                       (0x1A, "Request Download"), (0x29, "PLC Stop"),
                                       (0xF0, "Setup Communication")])
def test_s7_job_function_code(func, name):
    e = P.parse_s7comm(pf.s7_job(func, b"\x00" * 4), 1.0, A, B, 50000, 102, 1)
    assert e.function_code == func and e.function_name == name


def test_s7_ackdata_is_response():
    e = P.parse_s7comm(pf.s7_ackdata(0x04), 1.0, B, A, 102, 50000, 1)
    assert e.function_code == 0x04 and e.operation_type == "RESPONSE"


def test_s7_userdata_group():
    param = b"\x00\x01\x12\x04\x11\x44\x01\x00"  # CPU functions group (4)
    s7 = struct.pack(">BBHHHH", 0x32, 0x07, 0, 1, len(param), 0) + param
    tpkt = struct.pack(">BBH", 3, 0, 7 + len(s7)) + b"\x02\xf0\x80" + s7
    e = P.parse_s7comm(tpkt, 1.0, A, B, 50000, 102, 1)
    assert "CPU functions" in e.function_name


# ------------------------------------------------------------------ DNP3
@pytest.mark.parametrize("fc,name", [(0x01, "Read"), (0x0D, "Cold Restart"), (0x12, "Stop Application")])
def test_dnp3_function_code(fc, name):
    e = P.parse_dnp3(pf.dnp3(fc), 1.0, A, B, 50000, 20000, 1)
    assert e is not None, "DNP3 start bytes 0x05 0x64 must be recognized"
    assert e.function_code == fc and e.function_name == name
    assert "DNP3Dst=10" in e.notes and "DNP3Src=1" in e.notes


def test_dnp3_link_only_frame():
    frame = b"\x05\x64\x05\xc9" + struct.pack("<HH", 10, 1) + b"\x00\x00"
    e = P.parse_dnp3(frame, 1.0, A, B, 50000, 20000, 1)
    assert e.operation_type == "LINK"


# ------------------------------------------------------------------ EtherNet/IP
def test_enip_cip_service_unconnected():
    e = P.parse_enip(pf.enip_rr(0x4D), 1.0, A, B, 50000, 44818, 1)
    assert "Write Tag" in e.function_name and e.operation_type == "WRITE"


def test_enip_cip_service_connected():
    cip = bytes([0x4C, 0x02, 0x20, 0x06, 0x24, 0x01])
    data_item = struct.pack("<H", 1) + cip  # sequence count + CIP
    cpf = struct.pack("<IHH", 0, 0, 2) + struct.pack("<HHI", 0xA1, 4, 0x1234) + struct.pack("<HH", 0xB1, len(data_item)) + data_item
    pkt = struct.pack("<HHII8sI", 0x0070, len(cpf), 1, 0, b"\x00" * 8, 0) + cpf
    e = P.parse_enip(pkt, 1.0, A, B, 50000, 44818, 1)
    assert "Read Tag" in e.function_name


def test_enip_cip_reply_is_response():
    e = P.parse_enip(pf.enip_rr(0x4D | 0x80), 1.0, B, A, 44818, 50000, 1)
    assert e.operation_type == "RESPONSE"


# ------------------------------------------------------------------ IEC 104
def test_iec104_frames():
    i = P.parse_iec104(pf.iec104_i(45), 1.0, A, B, 50000, 2404, 1)
    u = P.parse_iec104(pf.iec104_u(0x07), 1.0, A, B, 50000, 2404, 1)
    s = P.parse_iec104(bytes([0x68, 4, 0x01, 0, 0x02, 0]), 1.0, A, B, 50000, 2404, 1)
    assert i.function_code == 45 and i.operation_type == "CONTROL"
    assert "STARTDT act" in u.function_name and "U-Frame" in u.notes
    assert s.operation_type == "ACK"


# ------------------------------------------------------------------ BACnet
@pytest.mark.parametrize("service,name", [(12, "ReadProperty"), (15, "WriteProperty"), (20, "ReinitializeDevice")])
def test_bacnet_confirmed_service(service, name):
    e = P.parse_bacnet(pf.bacnet_confirmed(service, invoke=7), 1.0, A, B, 47808, 47808, 1)
    assert name in e.function_name, e.function_name


def test_bacnet_whois():
    e = P.parse_bacnet(pf.bacnet_whois(), 1.0, A, "10.0.0.255", 47808, 47808, 1)
    assert "Who-Is" in e.function_name


# ------------------------------------------------------------------ MQTT / OPC UA
def test_mqtt_connect_and_publish():
    c = P.parse_mqtt(pf.mqtt_connect(), 1.0, A, B, 50000, 1883, 1)
    p = P.parse_mqtt(pf.mqtt_publish(), 1.0, A, B, 50000, 1883, 1)
    assert c.function_name == "CONNECT" and p.function_name == "PUBLISH"


@pytest.mark.parametrize("sid,name,op", [(631, "ReadRequest", "READ"), (673, "WriteRequest", "WRITE"),
                                         (712, "CallRequest", "CONTROL"), (527, "BrowseRequest", "READ")])
def test_opcua_service_nodeids(sid, name, op):
    e = P.parse_opc_ua(pf.opcua_msg(sid), 1.0, A, B, 50000, 4840, 1)
    assert name in e.function_name and e.operation_type == op


def test_opcua_hello_endpoint():
    e = P.parse_opc_ua(pf.opcua_hello(), 1.0, A, B, 50000, 4840, 1)
    assert e.function_name == "Hello"


# ------------------------------------------------------------------ DNS / HTTP / ARP
def test_dns_query_parsing():
    from scapy.all import DNS, DNSQR
    d = P.parse_dns(bytes(DNS(rd=1, qd=DNSQR(qname="historian.plant.local", qtype="TXT"))), 1.0, A, B, 5353, 53)
    assert d["queries"][0]["name"] == "historian.plant.local" and d["queries"][0]["type_name"] == "TXT"


def test_dns_compression_loop_terminates():
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    assert P.parse_dns(payload, 1.0, A, B, 5353, 53) is not None


def test_http_malformed_content_length():
    h = P.parse_http_request(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: abc\r\n\r\nbody", 1.0, A, B, 5, 80)
    assert h is not None and h["content_length"] == 0 and h["body"] == "body"


def test_arp_parsing():
    from scapy.all import ARP, Ether
    f = bytes(Ether(src=pf.MAC_ATT, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=pf.MAC_ATT, psrc=pf.PLC, pdst=pf.PLC))
    d = P.parse_arp(f, 1.0)
    assert d["sender_ip"] == pf.PLC and d["is_gratuitous"] and d["opcode_name"] == "ARP_REPLY"


def test_vendor_lookup_longest_prefix():
    assert constants.get_vendor("00:1b:1b:22:22:22") == "Siemens"
    assert constants.get_vendor("70-B3-D5-80-12-34") == "Omron"
    assert constants.get_vendor("") == "Unknown"
