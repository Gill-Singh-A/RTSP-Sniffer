from rtsp_extractor.core.rtp_demux import Demuxer
from rtsp_extractor.core.tcp_rtsp_bridge import TcpRtspBridge, make_conn_id


def test_classifies_client_from_request_line():
    demux = Demuxer(on_frame=lambda *_: None)
    bridge = TcpRtspBridge(demux)

    request = b"OPTIONS rtsp://1.2.3.4:554 RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    conn_id = bridge.handle_segment("10.0.0.5", 50000, "10.0.0.9", 554, seq=1, payload=request)

    state = bridge.connections[conn_id]
    assert state.client_endpoint == ("10.0.0.5", 50000)


def test_same_connection_both_directions_share_conn_id():
    a = make_conn_id(("1.1.1.1", 100), ("2.2.2.2", 554))
    b = make_conn_id(("2.2.2.2", 554), ("1.1.1.1", 100))
    assert a == b


def test_forget_drops_connection_state():
    demux = Demuxer(on_frame=lambda *_: None)
    bridge = TcpRtspBridge(demux)
    conn_id = bridge.handle_segment("10.0.0.5", 1, "10.0.0.9", 554, seq=1, payload=b"OPTIONS x RTSP/1.0\r\n\r\n")
    assert conn_id in bridge.connections
    bridge.forget(conn_id)
    assert conn_id not in bridge.connections
