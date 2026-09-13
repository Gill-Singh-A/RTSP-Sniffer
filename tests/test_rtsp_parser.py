import struct

from rtsp_extractor.core.rtsp_parser import InterleavedFrame, RtspMessage, RtspStreamParser


def test_parse_request_and_response():
    parser = RtspStreamParser()
    events = parser.feed(
        b"OPTIONS rtsp://1.2.3.4:554 RTSP/1.0\r\n"
        b"CSeq: 1\r\n"
        b"\r\n"
    )
    assert len(events) == 1
    msg = events[0]
    assert isinstance(msg, RtspMessage)
    assert msg.is_request
    assert msg.method == "OPTIONS"
    assert msg.cseq == 1

    parser2 = RtspStreamParser()
    events2 = parser2.feed(
        b"RTSP/1.0 200 OK\r\n"
        b"CSeq: 1\r\n"
        b"Session: 12345;timeout=60\r\n"
        b"\r\n"
    )
    resp = events2[0]
    assert not resp.is_request
    assert resp.status_code == 200
    assert resp.session_id == "12345"


def test_parse_message_with_body():
    parser = RtspStreamParser()
    body = b"v=0\r\ns=Media Server\r\n"
    data = (
        b"RTSP/1.0 200 OK\r\n"
        b"CSeq: 3\r\n"
        b"Content-Type: application/sdp\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"\r\n"
        + body
    )
    events = parser.feed(data)
    assert len(events) == 1
    assert events[0].body == body


def test_parse_split_across_feeds():
    parser = RtspStreamParser()
    full = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"
    assert parser.feed(full[:10]) == []
    events = parser.feed(full[10:])
    assert len(events) == 1


def test_interleaved_frame_mixed_with_rtsp():
    parser = RtspStreamParser()
    rtp_payload = b"\x80\x60" + b"\x00" * 10  # fake minimal RTP-ish bytes
    interleaved = b"$" + bytes([0]) + struct.pack("!H", len(rtp_payload)) + rtp_payload
    rtsp_msg = b"RTSP/1.0 200 OK\r\nCSeq: 5\r\n\r\n"

    events = parser.feed(interleaved + rtsp_msg + interleaved)

    assert len(events) == 3
    assert isinstance(events[0], InterleavedFrame)
    assert events[0].channel == 0
    assert events[0].payload == rtp_payload
    assert isinstance(events[1], RtspMessage)
    assert isinstance(events[2], InterleavedFrame)


def test_interleaved_frame_split_across_feeds():
    parser = RtspStreamParser()
    payload = b"\xAB" * 20
    frame = b"$" + bytes([1]) + struct.pack("!H", len(payload)) + payload

    assert parser.feed(frame[:3]) == []  # not even the length prefix complete
    events = parser.feed(frame[3:])
    assert len(events) == 1
    assert events[0].channel == 1
    assert events[0].payload == payload
