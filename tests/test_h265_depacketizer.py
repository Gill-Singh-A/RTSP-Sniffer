from rtsp_extractor.core.depacketizers.h265 import H265Depacketizer, sprop_parameter_sets
from rtsp_extractor.core.rtp import RtpPacket


def _rtp(payload: bytes, seq: int, marker: bool = False) -> RtpPacket:
    return RtpPacket(
        version=2, padding=False, extension=False, marker=marker,
        payload_type=98, sequence=seq, timestamp=0, ssrc=1, payload=payload,
    )


def test_single_nal_passthrough():
    dep = H265Depacketizer()
    nal = b"\x26\x01\x02\x03"  # type 19 (IDR_W_RADL), layer/tid arbitrary
    out = dep.feed(_rtp(nal, seq=1))
    assert out == [nal]


def test_ap_splits_aggregated_nals():
    dep = H265Depacketizer()
    vps = b"\x40\x01\xAA"  # type 32
    sps = b"\x42\x01\xBB"  # type 33
    payload = bytes([0x60, 0x00])  # PayloadHdr, type=48 (AP)
    for nal in (vps, sps):
        payload += len(nal).to_bytes(2, "big") + nal
    out = dep.feed(_rtp(payload, seq=1))
    assert out == [vps, sps]


def test_fu_reassembles_fragments():
    dep = H265Depacketizer()
    payload_hdr = bytes([0x62, 0x01])  # type=49 (FU)
    fu_type = 19  # IDR_W_RADL

    start = payload_hdr + bytes([0x80 | fu_type]) + b"AAAA"
    mid = payload_hdr + bytes([fu_type]) + b"BBBB"
    end = payload_hdr + bytes([0x40 | fu_type]) + b"CCCC"

    assert dep.feed(_rtp(start, seq=10)) == []
    assert dep.feed(_rtp(mid, seq=11)) == []
    out = dep.feed(_rtp(end, seq=12, marker=True))

    assert len(out) == 1
    nal = out[0]
    assert nal[2:] == b"AAAABBBBCCCC"
    assert (nal[0] >> 1) & 0x3F == fu_type
    assert nal[1] == payload_hdr[1]
    assert H265Depacketizer.is_keyframe_nal(nal) is True


def test_sprop_parameter_sets_order_vps_sps_pps():
    fmtp = {
        "sprop-vps": "QAEMAf//AWAAAAMAsAAAAwAAAwB7rAk=",
        "sprop-sps": "QgEBAWAAAAMAsAAAAwAAAwB7oAPAgBDlja5JMvTcBAQEAg==",
        "sprop-pps": "RAHA8vA8kA==",
    }
    nals = sprop_parameter_sets(fmtp)
    assert len(nals) == 3
    types = [(n[0] >> 1) & 0x3F for n in nals]
    assert types == [32, 33, 34]
