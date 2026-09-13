from rtsp_extractor.core.depacketizers.mjpeg import MJPEGDepacketizer
from rtsp_extractor.core.rtp import RtpPacket


def _rtp(payload: bytes, seq: int, marker: bool = False) -> RtpPacket:
    return RtpPacket(
        version=2, padding=False, extension=False, marker=marker,
        payload_type=26, sequence=seq, timestamp=0, ssrc=1, payload=payload,
    )


def _jpeg_header(frag_offset: int, q: int, width_blocks: int, height_blocks: int) -> bytes:
    return bytes([
        0,  # type-specific
        (frag_offset >> 16) & 0xFF, (frag_offset >> 8) & 0xFF, frag_offset & 0xFF,
        0,  # type
        q,
        width_blocks,
        height_blocks,
    ])


def test_single_packet_frame_produces_valid_looking_jpeg():
    dep = MJPEGDepacketizer()
    scan_data = b"\x01\x02\x03\x04" * 10
    payload = _jpeg_header(0, q=50, width_blocks=80, height_blocks=60) + scan_data
    out = dep.feed(_rtp(payload, seq=1, marker=True))

    assert len(out) == 1
    jpeg = out[0]
    assert jpeg.startswith(b"\xff\xd8")   # SOI
    assert jpeg.endswith(b"\xff\xd9")     # EOI
    assert b"\xff\xdb" in jpeg            # DQT
    assert b"\xff\xc0" in jpeg            # SOF0
    assert b"\xff\xc4" in jpeg            # DHT
    assert b"\xff\xda" in jpeg            # SOS
    assert scan_data in jpeg


def test_multi_packet_frame_reassembled_in_order():
    dep = MJPEGDepacketizer()
    part1 = b"\xAA" * 16
    part2 = b"\xBB" * 16

    pkt1 = _jpeg_header(0, q=50, width_blocks=80, height_blocks=60) + part1
    pkt2 = _jpeg_header(len(part1), q=50, width_blocks=80, height_blocks=60) + part2

    assert dep.feed(_rtp(pkt1, seq=1)) == []
    out = dep.feed(_rtp(pkt2, seq=2, marker=True))

    assert len(out) == 1
    assert part1 + part2 in out[0]


def test_no_frame_emitted_without_marker():
    dep = MJPEGDepacketizer()
    payload = _jpeg_header(0, q=50, width_blocks=80, height_blocks=60) + b"\x01" * 8
    assert dep.feed(_rtp(payload, seq=1, marker=False)) == []
