"""Incremental RTSP message / interleaved-RTP framing parser.

RTSP control connections carry two kinds of data once a session is playing:

- Plain-text RTSP requests/responses (RFC 2326), each ending in a blank
  line, optionally followed by a body of ``Content-Length`` bytes.
- For ``RTP/AVP/TCP`` (interleaved) transport, binary frames of the form
  ``'$' <channel:1> <length:2, big-endian> <payload:length>`` multiplexed
  into the very same byte stream.

This parser is fed raw bytes (per direction, in order) via ``feed()`` and
yields whichever complete units it can extract, buffering the rest for the
next call. It never blocks and does no I/O itself, so the exact same
instance works for an offline reassembled pcap stream or a live socket.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

INTERLEAVED_MAGIC = 0x24  # ord('$')


@dataclass
class RtspMessage:
    is_request: bool
    method: str | None = None
    url: str | None = None
    status_code: int | None = None
    reason: str | None = None
    headers: dict = field(default_factory=dict)  # lower-cased header name -> value
    body: bytes = b""

    @property
    def cseq(self) -> int | None:
        v = self.headers.get("cseq")
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    @property
    def session_id(self) -> str | None:
        v = self.headers.get("session")
        if v is None:
            return None
        return v.split(";", 1)[0].strip()

    @property
    def content_type(self) -> str | None:
        return self.headers.get("content-type")


@dataclass
class InterleavedFrame:
    channel: int
    payload: bytes


def _parse_headers(raw: bytes) -> dict:
    headers: dict = {}
    text = raw.decode("iso-8859-1", errors="replace")
    for line in text.split("\r\n"):
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return headers


def _parse_start_line(line: str) -> RtspMessage | None:
    parts = line.split(" ", 2)
    if len(parts) < 2:
        return None

    if parts[0].upper().startswith("RTSP/"):
        # Response: RTSP/1.0 200 OK
        try:
            status_code = int(parts[1])
        except ValueError:
            return None
        reason = parts[2] if len(parts) > 2 else ""
        return RtspMessage(is_request=False, status_code=status_code, reason=reason)

    if len(parts) == 3 and parts[2].upper().startswith("RTSP/"):
        # Request: METHOD url RTSP/1.0
        return RtspMessage(is_request=True, method=parts[0].upper(), url=parts[1])

    return None


class RtspStreamParser:
    """Stateful incremental parser for one direction of one TCP connection."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list:
        self._buf.extend(data)
        events: list = []
        while True:
            event = self._try_parse_one()
            if event is None:
                break
            events.append(event)
        return events

    def _try_parse_one(self):
        if not self._buf:
            return None

        if self._buf[0] == INTERLEAVED_MAGIC:
            if len(self._buf) < 4:
                return None
            channel = self._buf[1]
            (length,) = struct.unpack("!H", self._buf[2:4])
            if len(self._buf) < 4 + length:
                return None
            payload = bytes(self._buf[4:4 + length])
            del self._buf[:4 + length]
            return InterleavedFrame(channel=channel, payload=payload)

        header_end = bytes(self._buf).find(b"\r\n\r\n")
        if header_end == -1:
            # Guard against being permanently stuck on garbage that will
            # never contain a header terminator.
            if len(self._buf) > 1 << 20:
                del self._buf[:]
            return None

        header_block = bytes(self._buf[:header_end])
        lines = header_block.split(b"\r\n")
        start_line = lines[0].decode("iso-8859-1", errors="replace").strip()
        message = _parse_start_line(start_line)
        if message is None:
            # Not a recognizable RTSP start line - drop the line and retry,
            # rather than getting stuck (e.g. stray bytes/resync).
            nl = bytes(self._buf).find(b"\r\n")
            if nl == -1:
                del self._buf[:]
            else:
                del self._buf[:nl + 2]
            return self._try_parse_one()

        message.headers = _parse_headers(b"\r\n".join(lines[1:]))

        content_length = 0
        if "content-length" in message.headers:
            try:
                content_length = int(message.headers["content-length"])
            except ValueError:
                content_length = 0

        body_start = header_end + 4
        if len(self._buf) < body_start + content_length:
            return None  # wait for the rest of the body

        message.body = bytes(self._buf[body_start:body_start + content_length])
        del self._buf[:body_start + content_length]
        return message
