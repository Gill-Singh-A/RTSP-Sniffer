"""Minimal SDP parser (RFC 4566) - just enough to drive RTSP media setup.

Feed it the SDP body from an RTSP DESCRIBE reply; get back one
MediaDescription per "m=" line with its rtpmap/fmtp attributes parsed out.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MediaDescription:
    media_type: str          # "video", "audio", ...
    port: int
    proto: str                # "RTP/AVP"
    fmt: str                  # payload type number as it appeared, e.g. "96"
    attributes: dict = field(default_factory=dict)  # name -> value (last wins for repeats handled via rtpmap/fmtp keyed by fmt)
    rtpmap: dict = field(default_factory=dict)       # payload_type(int) -> (encoding_name, clock_rate)
    fmtp: dict = field(default_factory=dict)         # payload_type(int) -> {param: value}
    control: str | None = None

    @property
    def payload_type(self) -> int | None:
        try:
            return int(self.fmt.split()[0])
        except (ValueError, IndexError):
            return None

    @property
    def codec(self) -> str | None:
        pt = self.payload_type
        if pt is not None and pt in self.rtpmap:
            return self.rtpmap[pt][0].upper()
        return None

    @property
    def clock_rate(self) -> int | None:
        pt = self.payload_type
        if pt is not None and pt in self.rtpmap:
            return self.rtpmap[pt][1]
        return None

    def fmtp_params(self) -> dict:
        pt = self.payload_type
        if pt is not None and pt in self.fmtp:
            return self.fmtp[pt]
        return {}


@dataclass
class SessionDescription:
    session_attributes: dict = field(default_factory=dict)
    session_control: str | None = None
    media: list = field(default_factory=list)  # list[MediaDescription]


def _parse_fmtp_value(raw: str) -> dict:
    params = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip()] = v.strip()
        else:
            params[part] = True
    return params


def parse_sdp(text: str) -> SessionDescription:
    sdp = SessionDescription()
    current: MediaDescription | None = None

    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        if key == "m":
            # m=<media> <port> <proto> <fmt> ...
            parts = value.split()
            if len(parts) < 4:
                continue
            current = MediaDescription(
                media_type=parts[0],
                port=int(parts[1]) if parts[1].isdigit() else 0,
                proto=parts[2],
                fmt=" ".join(parts[3:]),
            )
            sdp.media.append(current)
        elif key == "a":
            attr_name, _, attr_value = value.partition(":")
            attr_name = attr_name.strip()
            attr_value = attr_value.strip()

            target = current if current is not None else None

            if attr_name == "control":
                if current is not None:
                    current.control = attr_value
                else:
                    sdp.session_control = attr_value
                continue

            if attr_name == "rtpmap" and current is not None:
                # rtpmap:<pt> <encoding>/<clockrate>[/<params>]
                pt_str, _, rest = attr_value.partition(" ")
                bits = rest.split("/")
                encoding = bits[0] if bits else ""
                clock_rate = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 0
                try:
                    current.rtpmap[int(pt_str)] = (encoding, clock_rate)
                except ValueError:
                    pass
                continue

            if attr_name == "fmtp" and current is not None:
                pt_str, _, rest = attr_value.partition(" ")
                try:
                    current.fmtp[int(pt_str)] = _parse_fmtp_value(rest)
                except ValueError:
                    pass
                continue

            attrs = current.attributes if current is not None else sdp.session_attributes
            attrs[attr_name] = attr_value if attr_value else True

    return sdp
