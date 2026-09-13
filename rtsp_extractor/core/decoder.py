"""Decode reconstructed elementary streams to raw frames.

H.264/H.265 go through PyAV (ffmpeg bindings); MJPEG frames are already
complete JPEG images so OpenCV can decode them directly. Both return BGR
numpy arrays, ready for cv2.imshow/VideoWriter.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

START_CODE = b"\x00\x00\x00\x01"

_CODEC_TO_AV_NAME = {
    "H264": "h264",
    "H265": "hevc",
    "HEVC": "hevc",
}


def av_codec_name(sdp_codec: str) -> str | None:
    return _CODEC_TO_AV_NAME.get(sdp_codec.upper()) if sdp_codec else None


class AnnexBDecoder:
    """Wraps a PyAV CodecContext; feed it one complete access unit at a time."""

    def __init__(self, codec_name: str) -> None:
        import av  # deferred import: only needed once we actually decode

        self._av = av
        self.codec_context = av.CodecContext.create(codec_name, "r")

    def decode_access_unit(self, nals: list[bytes]) -> list:
        if not nals:
            return []
        annex_b = b"".join(START_CODE + nal for nal in nals)
        packet = self._av.packet.Packet(annex_b)
        try:
            frames = self.codec_context.decode(packet)
        except Exception:
            logger.exception("decode error, skipping access unit")
            return []
        return [frame.to_ndarray(format="bgr24") for frame in frames]

    def flush(self) -> list:
        try:
            frames = self.codec_context.decode(None)
        except Exception:
            return []
        return [frame.to_ndarray(format="bgr24") for frame in frames]


def decode_jpeg(jpeg_bytes: bytes):
    import numpy as np
    import cv2

    arr = np.frombuffer(jpeg_bytes, dtype=np.uint8)
    frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    return frame
