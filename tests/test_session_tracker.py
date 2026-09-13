from rtsp_extractor.core.rtsp_parser import RtspMessage
from rtsp_extractor.core.session_tracker import SessionTracker

SDP_BODY = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 0.0.0.0\r\n"
    "s=Media Server\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "t=0 0\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=control:trackID=0\r\n"
    "a=framerate:25.000000\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=J2QAKKwa0A8ARLyoAA==,KO4EYsAA\r\n"
).encode()


def _req(method, url, cseq):
    return RtspMessage(is_request=True, method=method, url=url, headers={"cseq": str(cseq)})


def _resp(cseq, status=200, headers=None, body=b""):
    headers = dict(headers or {})
    headers["cseq"] = str(cseq)
    return RtspMessage(is_request=False, status_code=status, reason="OK", headers=headers, body=body)


def test_full_setup_flow_produces_track_with_interleaved_channels():
    tracker = SessionTracker(conn_id="conn-1")

    tracker.feed_message(_req("DESCRIBE", "rtsp://cam/", 3), to_server=True)
    tracker.feed_message(
        _resp(3, headers={"content-type": "application/sdp"}, body=SDP_BODY),
        to_server=False,
    )
    assert tracker.sdp is not None
    assert tracker.drain_new_tracks() == []  # DESCRIBE alone creates no track

    tracker.feed_message(_req("SETUP", "rtsp://cam/trackID=0", 4), to_server=True)
    tracker.feed_message(
        _resp(4, headers={
            "transport": "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=343733ED",
            "session": "168558900000;timeout=60",
        }),
        to_server=False,
    )

    new_tracks = tracker.drain_new_tracks()
    assert len(new_tracks) == 1
    track = new_tracks[0]
    assert track.codec == "H264"
    assert track.clock_rate == 90000
    assert track.transport_proto == "TCP"
    assert (track.rtp_channel, track.rtcp_channel) == (0, 1)
    assert track.ssrc == 0x343733ED
    assert track.session_id == "168558900000"
    assert track.framerate == 25.0
    assert "sprop-parameter-sets" in track.fmtp

    tracker.feed_message(_req("PLAY", "rtsp://cam/", 5), to_server=True)
    tracker.feed_message(_resp(5), to_server=False)
    assert tracker.tracks["trackID=0"].active is True

    assert tracker.track_for_channel(0) is track
    assert tracker.track_for_channel(1) is track
    assert tracker.track_for_channel(2) is None


def test_teardown_deactivates_tracks():
    tracker = SessionTracker(conn_id="conn-1")
    tracker.feed_message(_req("DESCRIBE", "rtsp://cam/", 1), to_server=True)
    tracker.feed_message(
        _resp(1, headers={"content-type": "application/sdp"}, body=SDP_BODY), to_server=False,
    )
    tracker.feed_message(_req("SETUP", "rtsp://cam/trackID=0", 2), to_server=True)
    tracker.feed_message(
        _resp(2, headers={"transport": "RTP/AVP/TCP;unicast;interleaved=0-1"}), to_server=False,
    )
    tracker.drain_new_tracks()

    tracker.feed_message(_req("TEARDOWN", "rtsp://cam/", 3), to_server=True)
    tracker.feed_message(_resp(3), to_server=False)

    assert tracker.torn_down is True
    assert tracker.tracks["trackID=0"].active is False
