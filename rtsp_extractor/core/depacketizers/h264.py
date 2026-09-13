"""H.264 / RFC 6184 RTP depacketizer.

Reconstructs NAL units from RTP payloads (single NAL, STAP-A aggregation,
FU-A fragmentation) and hands back raw NAL units (no Annex-B start code -
the decoder module adds those). SPS/PPS carried out-of-band in the SDP
``fmtp: sprop-parameter-sets`` are decoded up front so the caller can
prepend them before the first frame.
"""
from __future__ import annotations

import base64

from ..rtp import RtpPacket

NAL_TYPE_STAP_A = 24
NAL_TYPE_FU_A = 28
IDR_NAL_TYPES = {5}
SPS_PPS_TYPES = {7, 8}


def sprop_parameter_sets(fmtp: dict) -> list[bytes]:
    """Decode SDP fmtp `sprop-parameter-sets=<b64>,<b64>,...` into raw NAL units."""
    raw = fmtp.get("sprop-parameter-sets")
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


class H264Depacketizer:
    def __init__(self, fmtp: dict | None = None) -> None:
        self.fmtp = fmtp or {}
        self.extra_nals = sprop_parameter_sets(self.fmtp)
        self._fu_buf: bytearray | None = None
        self._fu_nal_header: int | None = None
        self._last_seq: int | None = None

    def feed(self, rtp: RtpPacket) -> list[bytes]:
        data = rtp.payload
        if not data:
            return []

        nal_type = data[0] & 0x1F
        out: list[bytes] = []

        if nal_type == NAL_TYPE_STAP_A:
            out.extend(self._parse_stap_a(data))
        elif nal_type == NAL_TYPE_FU_A:
            nal = self._parse_fu_a(data, rtp.sequence)
            if nal is not None:
                out.append(nal)
        elif 1 <= nal_type <= 23:
            out.append(bytes(data))
        # else: unsupported aggregation/fragmentation type (STAP-B/MTAP/FU-B) - skip.

        self._last_seq = rtp.sequence
        return out

    @staticmethod
    def _parse_stap_a(data: bytes) -> list[bytes]:
        nals = []
        offset = 1  # skip STAP-A indicator byte
        n = len(data)
        while offset + 2 <= n:
            size = (data[offset] << 8) | data[offset + 1]
            offset += 2
            if offset + size > n:
                break
            nals.append(data[offset:offset + size])
            offset += size
        return nals

    def _parse_fu_a(self, data: bytes, seq: int) -> bytes | None:
        if len(data) < 2:
            return None
        fu_indicator = data[0]
        fu_header = data[1]
        start = bool(fu_header & 0x80)
        end = bool(fu_header & 0x40)
        original_nal_type = fu_header & 0x1F
        nal_header = (fu_indicator & 0xE0) | original_nal_type

        if start:
            self._fu_buf = bytearray([nal_header])
            self._fu_buf.extend(data[2:])
            self._fu_nal_header = nal_header
            return None

        if self._fu_buf is None:
            return None  # missed the start fragment (packet loss) - drop this fragment run

        if self._last_seq is not None and seq != (self._last_seq + 1) & 0xFFFF:
            # Sequence gap mid-fragmentation: the reassembly would be corrupt.
            self._fu_buf = None
            return None

        self._fu_buf.extend(data[2:])

        if end:
            nal = bytes(self._fu_buf)
            self._fu_buf = None
            return nal

        return None

    @staticmethod
    def is_keyframe_nal(nal: bytes) -> bool:
        return bool(nal) and (nal[0] & 0x1F) in IDR_NAL_TYPES
