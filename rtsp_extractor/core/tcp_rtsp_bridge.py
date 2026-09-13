"""Shared TCP-connection bookkeeping used by both the offline pcap reader
and the live capture: reassembles each TCP connection per direction,
figures out which endpoint is the RTSP client, and forwards the resulting
byte stream to a `Demuxer`. One instance covers a whole capture (file or
live interface); connections are looked up by a caller-supplied conn_id.
"""
from __future__ import annotations

from .rtp_demux import Demuxer
from .tcp_reassembly import TcpConnectionReassembler

_RTSP_METHODS = (
    b"OPTIONS ", b"DESCRIBE ", b"SETUP ", b"PLAY ", b"PAUSE ", b"TEARDOWN ",
    b"ANNOUNCE ", b"RECORD ", b"GET_PARAMETER ", b"SET_PARAMETER ", b"REDIRECT ",
)


def _looks_like_request(payload: bytes) -> bool:
    return payload.startswith(_RTSP_METHODS)


def _looks_like_response(payload: bytes) -> bool:
    return payload.startswith(b"RTSP/")


def make_conn_id(src_ep: tuple, dst_ep: tuple) -> str:
    return "_".join(f"{ip}-{port}" for ip, port in sorted((src_ep, dst_ep)))


class _ConnState:
    def __init__(self) -> None:
        self.reassembler = TcpConnectionReassembler()
        self.client_endpoint: tuple | None = None  # (ip, port)


class TcpRtspBridge:
    def __init__(self, demux: Demuxer) -> None:
        self.demux = demux
        self.connections: dict[str, _ConnState] = {}

    def handle_segment(self, src_ip: str, sport: int, dst_ip: str, dport: int, seq: int, payload: bytes) -> str:
        """Feed one TCP segment; returns the conn_id it was attributed to."""
        src_ep = (src_ip, sport)
        dst_ep = (dst_ip, dport)
        conn_id = make_conn_id(src_ep, dst_ep)

        state = self.connections.get(conn_id)
        if state is None:
            state = _ConnState()
            self.connections[conn_id] = state

        direction_key = f"{src_ep}->{dst_ep}"
        reassembled = state.reassembler.add(direction_key, seq, payload)
        if not reassembled:
            return conn_id

        if state.client_endpoint is None:
            if _looks_like_request(reassembled) or _looks_like_request(payload):
                state.client_endpoint = src_ep
            elif _looks_like_response(reassembled) or _looks_like_response(payload):
                state.client_endpoint = dst_ep
            elif dport == 554:
                state.client_endpoint = src_ep
            elif sport == 554:
                state.client_endpoint = dst_ep

        if state.client_endpoint is None:
            to_server = True  # best-effort guess until classified
            client_ip = None
        else:
            to_server = src_ep == state.client_endpoint
            client_ip = state.client_endpoint[0]

        self.demux.feed_tcp(conn_id, to_server, reassembled, client_ip=client_ip)
        return conn_id

    def forget(self, conn_id: str) -> None:
        self.connections.pop(conn_id, None)
