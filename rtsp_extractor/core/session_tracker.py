"""Tracks RTSP sessions on a control connection and turns them into Tracks.

One instance covers a single control connection ("conn_id" - an opaque key
supplied by the caller, e.g. the reassembled TCP 4-tuple, or an RTSP
connection id for interleaved-over-TCP). It watches the request/response
exchange (matched by CSeq) and produces `Track` objects once a SETUP has
been acknowledged, describing exactly how to find and depacketize that
track's RTP.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .rtsp_parser import RtspMessage
from .sdp import SessionDescription, parse_sdp


def parse_transport_header(value: str) -> dict:
    """``RTP/AVP/TCP;unicast;interleaved=0-1`` -> dict of params."""
    params: dict = {}
    # A Transport header may list multiple comma-separated transport specs;
    # we only care about the first one a server actually accepted.
    first = value.split(",", 1)[0]
    parts = first.split(";")
    if parts:
        params["_protocol"] = parts[0].strip()
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip().lower()] = v.strip()
        else:
            params[part.lower()] = True
    return params


def _int_pair(value: str) -> tuple[int, int] | None:
    if not value or "-" not in value:
        return None
    a, _, b = value.partition("-")
    try:
        return int(a), int(b)
    except ValueError:
        return None


@dataclass
class Track:
    conn_id: object
    track_id: str            # e.g. "trackID=0", used to match SDP control -> SETUP url
    media_type: str
    codec: str | None
    clock_rate: int | None
    fmtp: dict
    transport_proto: str      # "TCP" (interleaved) or "UDP"
    framerate: float | None = None
    rtp_channel: int | None = None
    rtcp_channel: int | None = None
    client_rtp_port: int | None = None
    client_rtcp_port: int | None = None
    server_rtp_port: int | None = None
    server_rtcp_port: int | None = None
    ssrc: int | None = None
    session_id: str | None = None
    active: bool = False

    @property
    def label(self) -> str:
        return f"{self.conn_id}-{self.track_id}"


@dataclass
class _PendingRequest:
    method: str
    url: str


class SessionTracker:
    def __init__(self, conn_id) -> None:
        self.conn_id = conn_id
        self._pending: dict[int, _PendingRequest] = {}
        self.sdp: SessionDescription | None = None
        self.tracks: dict[str, Track] = {}  # track_id -> Track
        self.new_tracks: list[Track] = []    # tracks newly ready since last drain
        self.torn_down = False

    def _media_for_url(self, url: str) -> object | None:
        """Match a SETUP URL's trailing trackID/control fragment to an SDP media block."""
        if self.sdp is None:
            return None
        suffix = url.rsplit("/", 1)[-1]
        for media in self.sdp.media:
            if media.control and (media.control == suffix or media.control == url):
                return media
        # Fall back: single-media SDP, or couldn't match by control - use order.
        if len(self.sdp.media) == 1:
            return self.sdp.media[0]
        return None

    def on_request(self, message: RtspMessage) -> None:
        cseq = message.cseq
        if cseq is not None and message.method:
            self._pending[cseq] = _PendingRequest(method=message.method, url=message.url or "")

    def on_response(self, message: RtspMessage) -> bool:
        """Returns True exactly when this response just completed a TEARDOWN -
        the caller's cue to finalize (flush + close) this connection's tracks."""
        cseq = message.cseq
        if cseq is None or cseq not in self._pending:
            return False
        pending = self._pending.pop(cseq)
        if message.status_code != 200:
            return False

        if pending.method == "DESCRIBE" and message.content_type and "sdp" in message.content_type.lower():
            self.sdp = parse_sdp(message.body.decode("utf-8", errors="replace"))

        elif pending.method == "SETUP":
            self._handle_setup_ok(pending.url, message)

        elif pending.method == "TEARDOWN":
            self.torn_down = True
            for track in self.tracks.values():
                track.active = False
            return True

        return False

    def _handle_setup_ok(self, url: str, message: RtspMessage) -> None:
        transport_header = message.headers.get("transport", "")
        transport = parse_transport_header(transport_header)
        media = self._media_for_url(url)

        track_id = url.rsplit("/", 1)[-1]
        track = self.tracks.get(track_id)
        if track is None:
            framerate = None
            if media and media.attributes.get("framerate"):
                try:
                    framerate = float(media.attributes["framerate"])
                except (TypeError, ValueError):
                    framerate = None
            track = Track(
                conn_id=self.conn_id,
                track_id=track_id,
                media_type=media.media_type if media else "video",
                codec=media.codec if media else None,
                clock_rate=media.clock_rate if media else None,
                fmtp=media.fmtp_params() if media else {},
                transport_proto="TCP" if "TCP" in transport.get("_protocol", "") else "UDP",
                framerate=framerate,
            )
            self.tracks[track_id] = track

        proto = transport.get("_protocol", "")
        track.transport_proto = "TCP" if "TCP" in proto else "UDP"
        track.session_id = message.session_id

        if track.transport_proto == "TCP":
            chans = _int_pair(transport.get("interleaved", ""))
            if chans:
                track.rtp_channel, track.rtcp_channel = chans
        else:
            client_ports = _int_pair(transport.get("client_port", ""))
            server_ports = _int_pair(transport.get("server_port", ""))
            if client_ports:
                track.client_rtp_port, track.client_rtcp_port = client_ports
            if server_ports:
                track.server_rtp_port, track.server_rtcp_port = server_ports

        ssrc_hex = transport.get("ssrc")
        if ssrc_hex:
            try:
                track.ssrc = int(ssrc_hex, 16)
            except ValueError:
                pass

        track.active = True
        self.new_tracks.append(track)

    def feed_message(self, message: RtspMessage, to_server: bool) -> bool:
        """Returns True exactly when this message just completed a TEARDOWN."""
        if to_server and message.is_request:
            self.on_request(message)
        elif (not to_server) and (not message.is_request):
            return self.on_response(message)
        return False

    def drain_new_tracks(self) -> list:
        tracks, self.new_tracks = self.new_tracks, []
        return tracks

    def track_for_channel(self, channel: int) -> Track | None:
        for track in self.tracks.values():
            if track.rtp_channel == channel or track.rtcp_channel == channel:
                return track
        return None
