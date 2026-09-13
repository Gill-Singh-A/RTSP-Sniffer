"""RTP packet header parsing (RFC 3550)."""
from __future__ import annotations

import struct
from dataclasses import dataclass

RTP_HEADER_MIN_LEN = 12


@dataclass
class RtpPacket:
    version: int
    padding: bool
    extension: bool
    marker: bool
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> "RtpPacket | None":
        if len(data) < RTP_HEADER_MIN_LEN:
            return None
        b0, b1 = data[0], data[1]
        version = b0 >> 6
        if version != 2:
            return None
        padding = bool(b0 & 0x20)
        extension = bool(b0 & 0x10)
        csrc_count = b0 & 0x0F
        marker = bool(b1 & 0x80)
        payload_type = b1 & 0x7F
        sequence, timestamp, ssrc = struct.unpack("!HII", data[2:12])

        offset = RTP_HEADER_MIN_LEN + 4 * csrc_count
        if offset > len(data):
            return None

        if extension:
            if offset + 4 > len(data):
                return None
            _profile, ext_len_words = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4 + 4 * ext_len_words
            if offset > len(data):
                return None

        payload = data[offset:]
        if padding and payload:
            pad_len = payload[-1]
            if 0 < pad_len <= len(payload):
                payload = payload[:-pad_len]

        return cls(
            version=version,
            padding=padding,
            extension=extension,
            marker=marker,
            payload_type=payload_type,
            sequence=sequence,
            timestamp=timestamp,
            ssrc=ssrc,
            payload=payload,
        )
