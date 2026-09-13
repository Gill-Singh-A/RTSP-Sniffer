from rtsp_extractor.core.sdp import parse_sdp

H264_SDP = (
    "v=0\r\n"
    "o=- 2252106731 2252106731 IN IP4 0.0.0.0\r\n"
    "s=Media Server\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "t=0 0\r\n"
    "a=control:*\r\n"
    "a=range:npt=now-\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=control:trackID=0\r\n"
    "a=framerate:25.000000\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 packetization-mode=1;profile-level-id=640028;"
    "sprop-parameter-sets=J2QAKKwa0A8ARLyoAA==,KO4EYsAA\r\n"
    "a=recvonly\r\n"
)

H265_SDP = (
    "v=0\r\n"
    "o=- 2269636147 2269636147 IN IP4 0.0.0.0\r\n"
    "s=Media Server\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "t=0 0\r\n"
    "a=control:*\r\n"
    "m=video 0 RTP/AVP 98\r\n"
    "a=control:trackID=0\r\n"
    "a=framerate:20.000000\r\n"
    "a=rtpmap:98 H265/90000\r\n"
    "a=fmtp:98 profile-id=1;sprop-sps=QgEBAWAAAAMAsAAAAwAAAwB7oAPAgBDlja5JMvTcBAQEAg==;"
    "sprop-pps=RAHA8vA8kA==;sprop-vps=QAEMAf//AWAAAAMAsAAAAwAAAwB7rAk=\r\n"
)


def test_parse_h264_sdp():
    sdp = parse_sdp(H264_SDP)
    assert len(sdp.media) == 1
    media = sdp.media[0]
    assert media.media_type == "video"
    assert media.payload_type == 96
    assert media.codec == "H264"
    assert media.clock_rate == 90000
    assert media.control == "trackID=0"
    assert media.attributes.get("framerate") == "25.000000"
    params = media.fmtp_params()
    assert params["packetization-mode"] == "1"
    assert "sprop-parameter-sets" in params


def test_parse_h265_sdp():
    sdp = parse_sdp(H265_SDP)
    media = sdp.media[0]
    assert media.codec == "H265"
    assert media.payload_type == 98
    params = media.fmtp_params()
    assert "sprop-vps" in params
    assert "sprop-sps" in params
    assert "sprop-pps" in params
