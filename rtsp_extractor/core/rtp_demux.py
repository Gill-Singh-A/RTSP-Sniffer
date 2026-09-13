"""Matches RTP packets to negotiated tracks and feeds their pipelines.

One `Demuxer` owns every RTSP connection seen in a capture (or live
session). For each connection it runs an `RtspStreamParser` per direction
and a `SessionTracker`; once SETUP negotiates a track it builds a
`TrackPipeline` and keeps routing that track's RTP (interleaved `$` frames
or, for UDP transport, packets matched by port) into it.
"""
from __future__ import annotations

import logging

from .rtp import RtpPacket
from .rtsp_parser import InterleavedFrame, RtspMessage, RtspStreamParser
from .session_tracker import SessionTracker
from .track_pipeline import TrackPipeline

logger = logging.getLogger(__name__)


class ConnectionState:
    def __init__(self, conn_id) -> None:
        self.conn_id = conn_id
        self.parser_to_server = RtspStreamParser()
        self.parser_to_client = RtspStreamParser()
        self.tracker = SessionTracker(conn_id)
        self.pipelines: dict[str, TrackPipeline] = {}  # track_id -> pipeline


class Demuxer:
    def __init__(self, on_frame, on_track_started=None, on_track_ended=None) -> None:
        self.on_frame = on_frame  # callback(track, frame_ndarray)
        self.on_track_started = on_track_started  # callback(track)
        self.on_track_ended = on_track_ended  # callback(track) - flushed & finalized (TEARDOWN or idle reap)
        self._connections: dict[object, ConnectionState] = {}
        self._udp_port_map: dict[tuple, tuple] = {}  # (client_ip, port) -> (conn_id, track_id)

    def _connection(self, conn_id) -> ConnectionState:
        state = self._connections.get(conn_id)
        if state is None:
            state = ConnectionState(conn_id)
            self._connections[conn_id] = state
        return state

    # -- TCP (RTSP control + interleaved RTP) -----------------------------

    def feed_tcp(self, conn_id, to_server: bool, payload: bytes, client_ip: str | None = None) -> None:
        if not payload:
            return
        state = self._connection(conn_id)
        parser = state.parser_to_server if to_server else state.parser_to_client

        for event in parser.feed(payload):
            if isinstance(event, RtspMessage):
                torn_down = state.tracker.feed_message(event, to_server=to_server)
                for track in state.tracker.drain_new_tracks():
                    self._start_pipeline(state, track, client_ip)
                if torn_down:
                    self._finalize_connection(state)
            elif isinstance(event, InterleavedFrame):
                self._handle_interleaved(state, event)

    def _handle_interleaved(self, state: ConnectionState, frame: InterleavedFrame) -> None:
        track = state.tracker.track_for_channel(frame.channel)
        if track is None:
            return
        if track.rtcp_channel == frame.channel:
            return  # RTCP - not decoded
        rtp = RtpPacket.parse(frame.payload)
        if rtp is None:
            return
        pipeline = state.pipelines.get(track.track_id)
        if pipeline is not None:
            pipeline.handle_rtp(rtp)

    # -- UDP (RTP delivered as its own transport) -------------------------

    def register_udp_hint(self, client_ip: str, port: int, conn_id, track_id: str) -> None:
        self._udp_port_map[(client_ip, port)] = (conn_id, track_id)

    def feed_udp(self, dst_ip: str, dst_port: int, payload: bytes) -> None:
        key = (dst_ip, dst_port)
        target = self._udp_port_map.get(key)
        if target is None:
            return
        conn_id, track_id = target
        state = self._connections.get(conn_id)
        if state is None:
            return
        rtp = RtpPacket.parse(payload)
        if rtp is None:
            return
        pipeline = state.pipelines.get(track_id)
        if pipeline is not None:
            pipeline.handle_rtp(rtp)

    # -- shared -------------------------------------------------------------

    def _start_pipeline(self, state: ConnectionState, track, client_ip: str | None) -> None:
        if track.track_id in state.pipelines:
            return
        pipeline = TrackPipeline(track, self.on_frame)
        if not pipeline.supported:
            logger.warning("unsupported codec %r for track %s - skipping", track.codec, track.label)
            return
        state.pipelines[track.track_id] = pipeline
        if track.transport_proto == "UDP" and client_ip and track.client_rtp_port:
            self.register_udp_hint(client_ip, track.client_rtp_port, state.conn_id, track.track_id)
        if self.on_track_started:
            self.on_track_started(track)

    def _finalize_connection(self, state: ConnectionState) -> None:
        """Flush every track's pipeline (decoder + output sink) so its file
        is left in a valid, playable state - used on TEARDOWN and on idle
        reap, the two ways a live session ends without the whole process
        exiting."""
        for pipeline in state.pipelines.values():
            pipeline.flush()
            if self.on_track_ended:
                self.on_track_ended(pipeline.track)
        state.pipelines = {}

    def flush_all(self) -> None:
        for state in self._connections.values():
            self._finalize_connection(state)

    def flush_and_forget(self, conn_id) -> None:
        """Flush a single connection's pipelines and drop its state - for
        live capture, once a session has gone idle for too long."""
        state = self._connections.pop(conn_id, None)
        if state is None:
            return
        self._finalize_connection(state)

    def all_tracks(self):
        for state in self._connections.values():
            for pipeline in state.pipelines.values():
                yield pipeline.track
