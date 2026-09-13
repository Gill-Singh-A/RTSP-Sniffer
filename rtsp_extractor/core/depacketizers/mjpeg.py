"""Motion-JPEG RTP depacketizer (RFC 2435).

RTP/JPEG carries a stripped-down JPEG (no headers, no huffman tables) plus
just enough metadata (dimensions, quantization tables) per packet to
rebuild a standard JFIF file. This reassembles one such file per frame and
hands it back as a decodable JPEG byte string (feed straight to
cv2.imdecode or a PyAV 'mjpeg' decoder).

Restart-marker (type 64-127) streams are not supported.
"""
from __future__ import annotations

import struct

from ..rtp import RtpPacket

_ZIGZAG = [
    0, 1, 8, 16, 9, 2, 3, 10,
    17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
]

# Default luma/chroma quantization tables, RFC 2435 Appendix A.
_DEFAULT_QTABLE_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]
_DEFAULT_QTABLE_CHROMA = [
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
]


def _dqt_marker(tables: list[bytes]) -> bytes:
    payload = b""
    for table_id, table in enumerate(tables):
        payload += bytes([table_id]) + bytes(table)
    return b"\xff\xdb" + struct.pack(">H", 2 + len(payload)) + payload


def _default_scale_table(q: int, base: list[int]) -> list[int]:
    q = max(1, min(99, q))
    factor = 5000 // q if q < 50 else 200 - q * 2
    out = []
    for v in base:
        val = (v * factor + 50) // 100
        out.append(max(1, min(255, val)))
    return out


def _quant_tables_for_q(q: int) -> tuple[list[int], list[int]]:
    return (
        _default_scale_table(q, _DEFAULT_QTABLE_LUMA),
        _default_scale_table(q, _DEFAULT_QTABLE_CHROMA),
    )


def _zigzag_order(table: list[int]) -> bytes:
    out = [0] * 64
    for i, zz in enumerate(_ZIGZAG):
        out[zz] = table[i]
    return bytes(out)


_HUFF_DC_LUMA_BITS = bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
_HUFF_DC_LUMA_VALS = bytes(range(12))
_HUFF_DC_CHROMA_BITS = bytes([0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0])
_HUFF_DC_CHROMA_VALS = bytes(range(12))
_HUFF_AC_LUMA_BITS = bytes([0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d])
_HUFF_AC_LUMA_VALS = bytes([
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
])
_HUFF_AC_CHROMA_BITS = bytes([0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77])
_HUFF_AC_CHROMA_VALS = bytes([
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
    0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
])


def _dht_marker() -> bytes:
    def table(tc_th: int, bits: bytes, vals: bytes) -> bytes:
        return bytes([tc_th]) + bits + vals

    payload = (
        table(0x00, _HUFF_DC_LUMA_BITS, _HUFF_DC_LUMA_VALS)
        + table(0x10, _HUFF_AC_LUMA_BITS, _HUFF_AC_LUMA_VALS)
        + table(0x01, _HUFF_DC_CHROMA_BITS, _HUFF_DC_CHROMA_VALS)
        + table(0x11, _HUFF_AC_CHROMA_BITS, _HUFF_AC_CHROMA_VALS)
    )
    return b"\xff\xc4" + struct.pack(">H", 2 + len(payload)) + payload


def _sof0_marker(width: int, height: int, has_chroma_subsampling_422: bool) -> bytes:
    # type 0 (4:2:0) sampling per RFC 2435 default; type 1 = 4:2:2.
    y_comp = bytes([1, 0x22 if not has_chroma_subsampling_422 else 0x21, 0])
    cb_comp = bytes([2, 0x11, 1])
    cr_comp = bytes([3, 0x11, 1])
    payload = (
        bytes([8])
        + struct.pack(">H", height)
        + struct.pack(">H", width)
        + bytes([3])
        + y_comp + cb_comp + cr_comp
    )
    return b"\xff\xc0" + struct.pack(">H", 2 + len(payload)) + payload


def _sos_marker() -> bytes:
    payload = bytes([3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0])
    return b"\xff\xda" + struct.pack(">H", 2 + len(payload)) + payload


def build_jpeg_header(
    type_: int,
    q: int,
    width: int,
    height: int,
    qtables: tuple[list[int], list[int]] | None,
) -> bytes:
    """RFC 2435 Appendix A: rebuild a standard JFIF header for one frame."""
    is_422 = type_ == 1
    if qtables is not None:
        luma, chroma = qtables
    else:
        luma, chroma = _quant_tables_for_q(q)

    header = b"\xff\xd8"  # SOI
    header += _dqt_marker([_zigzag_order(luma), _zigzag_order(chroma)])
    header += _sof0_marker(width, height, is_422)
    header += _dht_marker()
    header += _sos_marker()
    return header


class MJPEGDepacketizer:
    """Feed RTP packets in; get complete JPEG images out (one per frame)."""

    def __init__(self, fmtp: dict | None = None) -> None:
        self.fmtp = fmtp or {}
        self._frame_buf = bytearray()
        self._frame_meta: tuple | None = None  # (type, q, width, height)
        self._qtables: tuple[list[int], list[int]] | None = None

    def feed(self, rtp: RtpPacket) -> list[bytes]:
        data = rtp.payload
        if len(data) < 8:
            return []

        frag_offset = (data[1] << 16) | (data[2] << 8) | data[3]
        jtype = data[4]
        q = data[5]
        width = data[6] * 8
        height = data[7] * 8
        offset = 8

        if jtype >= 64:
            return []  # restart-marker streams unsupported

        if q >= 128:
            if frag_offset == 0:
                if offset + 4 > len(data):
                    return []
                _mbz, precision, length = data[offset], data[offset + 1], (data[offset + 2] << 8) | data[offset + 3]
                offset += 4
                table_bytes = data[offset:offset + length]
                offset += length
                if len(table_bytes) >= 128:
                    luma = list(table_bytes[0:64])
                    chroma = list(table_bytes[64:128])
                    self._qtables = (luma, chroma)
            # else: mid-frame, quant table header only appears at offset 0.

        payload = data[offset:]

        if frag_offset == 0:
            self._frame_buf = bytearray()
            self._frame_meta = (jtype, q, width, height)

        if self._frame_meta is None:
            return []  # never saw the start of this frame

        self._frame_buf.extend(payload)

        out: list[bytes] = []
        if rtp.marker:
            jtype, q, width, height = self._frame_meta
            if width and height:
                header = build_jpeg_header(jtype, q, width, height, self._qtables)
                jpeg = header + bytes(self._frame_buf) + b"\xff\xd9"
                out.append(jpeg)
            self._frame_buf = bytearray()
            self._frame_meta = None

        return out

    @staticmethod
    def is_keyframe_nal(_frame: bytes) -> bool:
        return True  # every MJPEG frame is independently decodable
