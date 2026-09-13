"""H.265/HEVC RTP depacketizer (RFC 7798).

Same shape as the H.264 one: single NAL units pass through, AP
(aggregation packets) are split, FU (fragmentation units) are
reassembled. VPS/SPS/PPS from the SDP fmtp `sprop-vps/sprop-sps/sprop-pps`
are decoded up front for the caller to prepend before the first frame.
"""
from __future__ import annotations

import base64

from ..rtp import RtpPacket

NAL_TYPE_AP = 48
NAL_TYPE_FU = 49
IRAP_NAL_TYPES = set(range(16, 24))  # BLA_W_LP .. RSV_IRAP_VCL23


def _nal_type(header_byte0: int) -> int:
    return (header_byte0 >> 1) & 0x3F


def _decode_b64_list(fmtp: dict, key: str) -> list[bytes]:
    raw = fmtp.get(key)
    if not raw:
        return []
    nals = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            nals.append(base64.b64decode(chunk + "=" * (-len(chunk) % 4)))
        except Exception:
            continue
    return nals


def sprop_parameter_sets(fmtp: dict) -> list[bytes]:
    """VPS, then SPS, then PPS - the order decoders expect them in."""
    return (
        _decode_b64_list(fmtp, "sprop-vps")
        + _decode_b64_list(fmtp, "sprop-sps")
        + _decode_b64_list(fmtp, "sprop-pps")
    )


class H265Depacketizer:
    def __init__(self, fmtp: dict | None = None) -> None:
        self.fmtp = fmtp or {}
        self.extra_nals = sprop_parameter_sets(self.fmtp)
        self._fu_buf: bytearray | None = None
        self._last_seq: int | None = None

    def feed(self, rtp: RtpPacket) -> list[bytes]:
        data = rtp.payload
        if len(data) < 2:
            return []

        nal_type = _nal_type(data[0])
        out: list[bytes] = []

        if nal_type == NAL_TYPE_AP:
            out.extend(self._parse_ap(data))
        elif nal_type == NAL_TYPE_FU:
            nal = self._parse_fu(data, rtp.sequence)
            if nal is not None:
                out.append(nal)
        else:
            out.append(bytes(data))

        self._last_seq = rtp.sequence
        return out

    @staticmethod
    def _parse_ap(data: bytes) -> list[bytes]:
        nals = []
        offset = 2  # skip 2-byte PayloadHdr
        n = len(data)
        while offset + 2 <= n:
            size = (data[offset] << 8) | data[offset + 1]
            offset += 2
            if offset + size > n:
                break
            nals.append(data[offset:offset + size])
            offset += size
        return nals

    def _parse_fu(self, data: bytes, seq: int) -> bytes | None:
        if len(data) < 3:
            return None
        payload_hdr = data[0:2]
        fu_header = data[2]
        start = bool(fu_header & 0x80)
        end = bool(fu_header & 0x40)
        fu_type = fu_header & 0x3F

        new_b0 = (payload_hdr[0] & 0x81) | (fu_type << 1)
        new_b1 = payload_hdr[1]

        if start:
            self._fu_buf = bytearray([new_b0, new_b1])
            self._fu_buf.extend(data[3:])
            return None

        if self._fu_buf is None:
            return None

        if self._last_seq is not None and seq != (self._last_seq + 1) & 0xFFFF:
            self._fu_buf = None
            return None

        self._fu_buf.extend(data[3:])

        if end:
            nal = bytes(self._fu_buf)
            self._fu_buf = None
            return nal

        return None

    @staticmethod
    def is_keyframe_nal(nal: bytes) -> bool:
        return len(nal) >= 1 and _nal_type(nal[0]) in IRAP_NAL_TYPES
