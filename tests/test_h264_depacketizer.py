from rtsp_extractor.core.depacketizers.h264 import H264Depacketizer, sprop_parameter_sets
from rtsp_extractor.core.rtp import RtpPacket


def _rtp(payload: bytes, seq: int, marker: bool = False) -> RtpPacket:
    return RtpPacket(
        version=2, padding=False, extension=False, marker=marker,
        payload_type=96, sequence=seq, timestamp=0, ssrc=1, payload=payload,
    )


def test_single_nal_passthrough():
    dep = H264Depacketizer()
    nal = b"\x67\x01\x02\x03"  # type 7 (SPS), arbitrary body
    out = dep.feed(_rtp(nal, seq=1))
    assert out == [nal]


def test_stap_a_splits_aggregated_nals():
    dep = H264Depacketizer()
    nal1 = b"\x67\x01\x02"
    nal2 = b"\x68\x03\x04"
    payload = bytes([0x18])
    for nal in (nal1, nal2):
        payload += len(nal).to_bytes(2, "big") + nal
    out = dep.feed(_rtp(payload, seq=1))
    assert out == [nal1, nal2]


def test_fu_a_reassembles_fragments():
    dep = H264Depacketizer()
    fu_indicator = 0x60 | 28   # nri=3, type=FU-A(28)
    start_header = 0x80 | 5    # start bit, original type = 5 (IDR)
    mid_header = 5
    end_header = 0x40 | 5

    start = bytes([fu_indicator, start_header]) + b"AAAA"
    mid = bytes([fu_indicator, mid_header]) + b"BBBB"
    end = bytes([fu_indicator, end_header]) + b"CCCC"

    assert dep.feed(_rtp(start, seq=10)) == []
    assert dep.feed(_rtp(mid, seq=11)) == []
    out = dep.feed(_rtp(end, seq=12, marker=True))

    expected_header = bytes([(fu_indicator & 0xE0) | 5])
    assert out == [expected_header + b"AAAABBBBCCCC"]
    assert H264Depacketizer.is_keyframe_nal(out[0]) is True


def test_fu_a_drops_run_on_sequence_gap():
    dep = H264Depacketizer()
    fu_indicator = 0x60 | 28
    start = bytes([fu_indicator, 0x80 | 1]) + b"AAAA"
    end = bytes([fu_indicator, 0x40 | 1]) + b"CCCC"

    assert dep.feed(_rtp(start, seq=1)) == []
    # seq jumps from 1 to 3 - a packet was lost, fragment run must be abandoned.
    assert dep.feed(_rtp(end, seq=3, marker=True)) == []


def test_sprop_parameter_sets_decoded():
    fmtp = {"sprop-parameter-sets": "J2QAKKwa0A8ARLyoAA==,KO4EYsAA"}
    nals = sprop_parameter_sets(fmtp)
    assert len(nals) == 2
    assert (nals[0][0] & 0x1F) == 7  # SPS
    assert (nals[1][0] & 0x1F) == 8  # PPS
