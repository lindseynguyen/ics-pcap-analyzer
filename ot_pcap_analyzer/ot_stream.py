"""
OT PCAP Analyzer - OT TCP stream reassembly
===========================================

Industrial protocols over TCP are length-prefixed, but a TCP segment does not
have to contain exactly one protocol data unit (PDU):

* one segment can carry several PDUs (e.g. pipelined Modbus requests, an
  IEC-104 I-frame followed by an S-frame), and
* one PDU can be split across several segments (large S7 / OPC UA messages).

The analyzer used to parse each segment as a single PDU, so it missed every
PDU after the first and mis-parsed split ones. ``OTStreamReassembler`` keeps a
small per-direction buffer, follows TCP sequence numbers and cuts the byte
stream into complete PDUs using each protocol's own length field.

Design goals: never lose data compared with the old per-segment behaviour
(unrecognised or truncated data is still handed to the parser as-is), bounded
memory, and O(1) work per segment.
"""

import struct
from collections import OrderedDict
from typing import Callable, Dict, List, Optional, Tuple

# A framer inspects the start of a buffer and returns:
#   int > 0 -> length of the first complete PDU (may exceed len(buf): need more data)
#   None    -> not enough bytes yet to know the length
#   -1      -> the buffer does not start with a valid PDU header
Framer = Callable[[bytes], Optional[int]]

NEED_MORE = None
INVALID = -1


def frame_modbus(buf: bytes) -> Optional[int]:
    if len(buf) < 7:
        return NEED_MORE
    if buf[2] != 0 or buf[3] != 0:          # protocol id must be 0
        return INVALID
    length = struct.unpack(">H", buf[4:6])[0]
    if not 2 <= length <= 254:
        return INVALID
    return 6 + length


def frame_tpkt(buf: bytes) -> Optional[int]:  # S7comm / ISO-on-TCP (RFC 1006)
    if len(buf) < 4:
        return NEED_MORE
    if buf[0] != 3 or buf[1] != 0:
        return INVALID
    length = struct.unpack(">H", buf[2:4])[0]
    return length if length >= 7 else INVALID


def frame_iec104(buf: bytes) -> Optional[int]:
    if len(buf) < 2:
        return NEED_MORE
    if buf[0] != 0x68 or buf[1] < 4:
        return INVALID
    return 2 + buf[1]


def frame_enip(buf: bytes) -> Optional[int]:
    if len(buf) < 24:
        return NEED_MORE
    return 24 + struct.unpack("<H", buf[2:4])[0]


def frame_dnp3(buf: bytes) -> Optional[int]:
    if len(buf) < 3:
        return NEED_MORE
    if buf[0] != 0x05 or buf[1] != 0x64 or buf[2] < 5:
        return INVALID
    user_data = buf[2] - 5
    # 10-byte header (incl. CRC) + data blocks of up to 16 bytes, each with a 2-byte CRC
    return 10 + user_data + 2 * ((user_data + 15) // 16)


def frame_opcua(buf: bytes) -> Optional[int]:
    if len(buf) < 8:
        return NEED_MORE
    if not buf[0:3].isalpha() or not buf[0:3].isupper():
        return INVALID
    size = struct.unpack("<I", buf[4:8])[0]
    return size if 8 <= size <= 16 * 1024 * 1024 else INVALID


def frame_mqtt(buf: bytes) -> Optional[int]:
    if len(buf) < 2:
        return NEED_MORE
    if (buf[0] >> 4) == 0:                  # packet type 0 is reserved
        return INVALID
    remaining, multiplier = 0, 1
    for i in range(1, 5):
        if i >= len(buf):
            return NEED_MORE
        byte = buf[i]
        remaining += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return 1 + i + remaining
        multiplier *= 128
    return INVALID                          # more than 4 length bytes


# Server port -> framer
OT_TCP_FRAMERS: Dict[int, Framer] = {
    502: frame_modbus,
    102: frame_tpkt,
    20000: frame_dnp3,
    44818: frame_enip,
    2404: frame_iec104,
    4840: frame_opcua,
    1883: frame_mqtt,
}


class _FlowState:
    __slots__ = ("next_seq", "buf", "last_seq", "last_payload")

    def __init__(self):
        self.next_seq: Optional[int] = None
        self.buf = b""
        self.last_seq: Optional[int] = None
        self.last_payload = b""


class OTStreamReassembler:
    """Per-direction TCP reassembly into protocol PDUs for OT protocols."""

    def __init__(self, max_buffer: int = 256 * 1024, max_flows: int = 20_000):
        self.max_buffer = max_buffer
        self.max_flows = max_flows
        self._flows: "OrderedDict[Tuple, _FlowState]" = OrderedDict()
        self.stats = {"segments": 0, "pdus": 0, "retransmissions": 0,
                      "multi_pdu_segments": 0, "reassembled_pdus": 0, "resyncs": 0}

    def feed(self, flow_key: Tuple, seq: int, payload: bytes, framer: Framer,
             syn: bool = False, fin_or_rst: bool = False) -> List[bytes]:
        """Add a TCP segment and return the complete PDUs it finishes, in order."""
        self.stats["segments"] += 1
        state = self._flows.get(flow_key)
        if state is None:
            state = _FlowState()
            self._flows[flow_key] = state
            if len(self._flows) > self.max_flows:
                self._flows.popitem(last=False)   # evict least recently used flow
        else:
            self._flows.move_to_end(flow_key)

        if syn:
            state.next_seq = (seq + 1) & 0xFFFFFFFF
            state.buf = b""
            return []

        pdus: List[bytes] = []
        if payload:
            # Exact retransmission of the previous segment: ignore it
            if seq == state.last_seq and payload == state.last_payload:
                self.stats["retransmissions"] += 1
            else:
                if state.next_seq is not None and seq != state.next_seq and state.buf:
                    # Gap / out-of-order / capture loss: hand over what we have
                    self.stats["resyncs"] += 1
                    pdus.append(state.buf)
                    state.buf = b""
                had_partial = bool(state.buf)
                state.buf += payload
                state.last_seq, state.last_payload = seq, payload
                state.next_seq = (seq + len(payload)) & 0xFFFFFFFF
                pdus.extend(self._extract(state, framer, had_partial))

        if fin_or_rst:
            if state.buf:
                pdus.append(state.buf)       # flush any incomplete tail
            self._flows.pop(flow_key, None)
        return pdus

    def _extract(self, state: _FlowState, framer: Framer, had_partial: bool) -> List[bytes]:
        out: List[bytes] = []
        buf = state.buf
        while buf:
            length = framer(buf)
            if length == INVALID:
                # Not aligned on a PDU boundary (mid-stream start, unknown data):
                # pass it through unchanged, exactly like the old behaviour.
                out.append(buf)
                buf = b""
                break
            if length is NEED_MORE or length > len(buf):
                if len(buf) > self.max_buffer:   # runaway length field: give up
                    out.append(buf)
                    buf = b""
                break
            out.append(buf[:length])
            buf = buf[length:]
        state.buf = buf
        if len(out) > 1:
            self.stats["multi_pdu_segments"] += 1
        if had_partial and out:
            self.stats["reassembled_pdus"] += 1
        self.stats["pdus"] += len(out)
        return out

    def flush(self) -> List[Tuple[Tuple, bytes]]:
        """Return incomplete tails of all flows (call at end of capture)."""
        tails = [(key, st.buf) for key, st in self._flows.items() if st.buf]
        self._flows.clear()
        return tails
