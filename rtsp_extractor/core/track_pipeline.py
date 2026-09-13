"""Per-track pipeline: RTP packets in, decoded BGR frames out.

Wires together: RTP sequencing -> depacketizer -> access-unit assembly
(grouped by the RTP marker bit, the standard "last packet of a frame"
signal) -> decoder. One instance is created per negotiated media track.
"""
from __future__ import annotations

import logging

from .decoder import AnnexBDecoder, av_codec_name, decode_jpeg
from .depacketizers.h264 import H264Depacketizer
from .depacketizers.h265 import H265Depacketizer
from .depacketizers.mjpeg import MJPEGDepacketizer
from .rtp import RtpPacket
from .session_tracker import Track

logger = logging.getLogger(__name__)

_DEPACKETIZERS = {
    "H264": H264Depacketizer,
    "H265": H265Depacketizer,
    "HEVC": H265Depacketizer,
    "JPEG": MJPEGDepacketizer,
}


def make_depacketizer(codec: str, fmtp: dict):
    cls = _DEPACKETIZERS.get((codec or "").upper())
    if cls is None:
        return None
    return cls(fmtp)


class TrackPipeline:
    def __init__(self, track: Track, on_frame) -> None:
        self.track = track
        self.on_frame = on_frame  # callback(track, frame_ndarray)
        self.depacketizer = make_depacketizer(track.codec, track.fmtp)
        self.is_mjpeg = (track.codec or "").upper() == "JPEG"
        self.decoder = None
        if self.depacketizer is not None and not self.is_mjpeg:
            av_name = av_codec_name(track.codec)
            if av_name:
                try:
                    self.decoder = AnnexBDecoder(av_name)
                except Exception:
                    logger.exception("failed to create decoder for %s", track.codec)

        self._au_buf: list[bytes] = []
        self._sent_extra_nals = False
        self._last_seq: int | None = None
        self.frame_count = 0

    @property
    def supported(self) -> bool:
        return self.depacketizer is not None and (self.is_mjpeg or self.decoder is not None)

    def handle_rtp(self, rtp: RtpPacket) -> None:
        if not self.supported:
            return

        if self._last_seq is not None:
            expected = (self._last_seq + 1) & 0xFFFF
            if rtp.sequence != expected:
                logger.debug(
                    "%s: sequence gap (expected %d, got %d)",
                    self.track.label, expected, rtp.sequence,
                )
        self._last_seq = rtp.sequence

        if self.is_mjpeg:
            for jpeg in self.depacketizer.feed(rtp):
                frame = decode_jpeg(jpeg)
                if frame is not None:
                    self.frame_count += 1
                    self.on_frame(self.track, frame)
            return

        nals = self.depacketizer.feed(rtp)
        self._au_buf.extend(nals)

        if rtp.marker:
            self._flush_access_unit()

    def _flush_access_unit(self) -> None:
        if not self._au_buf:
            return
        nals = self._au_buf
        self._au_buf = []

        has_keyframe = any(self.depacketizer.is_keyframe_nal(n) for n in nals)
        prefix: list[bytes] = []
        if not self._sent_extra_nals or has_keyframe:
            prefix = list(self.depacketizer.extra_nals)
            self._sent_extra_nals = True

        frames = self.decoder.decode_access_unit(prefix + nals)
        for frame in frames:
            self.frame_count += 1
            self.on_frame(self.track, frame)

    def flush(self) -> None:
        if not self.is_mjpeg and self.decoder is not None:
            self._flush_access_unit()
            for frame in self.decoder.flush():
                self.frame_count += 1
                self.on_frame(self.track, frame)
