"""Per-track display/save sink: cv2.imshow window, or an mp4 file when
running headless (no DISPLAY, or --save/--headless was requested).
"""
from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)


def _safe_filename(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", label)


def has_display() -> bool:
    if os.name == "nt":
        return True  # Windows always has a desktop session available to cv2
    return bool(os.environ.get("DISPLAY"))


class TrackSink:
    """One instance per track. `write(frame)` shows or records it."""

    def __init__(self, track, output_dir: str, headless: bool) -> None:
        import cv2  # deferred import

        self._cv2 = cv2
        self.track = track
        self.headless = headless
        self.output_dir = output_dir
        self._window_name = f"RTSP-Sniffer: {track.label}"
        self._writer = None
        self._output_path = None

        if headless:
            os.makedirs(output_dir, exist_ok=True)
            self._output_path = os.path.join(output_dir, f"{_safe_filename(track.label)}.mp4")
        else:
            cv2.namedWindow(self._window_name, cv2.WINDOW_NORMAL)

    def write(self, frame) -> None:
        if frame is None:
            return
        if self.headless:
            if self._writer is None:
                height, width = frame.shape[:2]
                fps = self.track.framerate or 25.0
                fourcc = self._cv2.VideoWriter_fourcc(*"mp4v")
                self._writer = self._cv2.VideoWriter(self._output_path, fourcc, fps, (width, height))
                logger.info("recording %s -> %s (%dx%d @ %.1ffps)", self.track.label, self._output_path, width, height, fps)
            self._writer.write(frame)
        else:
            self._cv2.imshow(self._window_name, frame)
            self._cv2.waitKey(1)

    def close(self) -> None:
        if self._writer is not None:
            self._writer.release()
            self._writer = None
        elif not self.headless:
            self._cv2.destroyWindow(self._window_name)


class ViewerManager:
    """Owns one TrackSink per track, created lazily on first frame."""

    def __init__(self, output_dir: str = "output", headless: bool | None = None) -> None:
        self.output_dir = output_dir
        self.headless = headless if headless is not None else not has_display()
        self._sinks: dict[str, TrackSink] = {}

    def on_frame(self, track, frame) -> None:
        sink = self._sinks.get(track.label)
        if sink is None:
            sink = TrackSink(track, self.output_dir, self.headless)
            self._sinks[track.label] = sink
        sink.write(frame)

    def close(self) -> None:
        for sink in self._sinks.values():
            sink.close()
        self._sinks.clear()
