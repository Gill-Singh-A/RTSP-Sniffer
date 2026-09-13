#!/usr/bin/env python3
"""Phase 2 entrypoint: sniff a live interface, find RTSP sessions as they
start, and display (or save) each detected stream in near real time.

    sudo python cli_live.py -i eth0
    sudo python cli_live.py -i eth0 --headless -o output/

Needs to capture raw packets, so it needs root / CAP_NET_RAW (run with
sudo, or `sudo setcap cap_net_raw+ep $(which python3)` once).
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from rtsp_extractor.core.live_capture import LiveCapture
from rtsp_extractor.viewer import ViewerManager

REAP_INTERVAL_SECONDS = 10.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--iface", required=True, help="Network interface to sniff (e.g. eth0)")
    parser.add_argument("-o", "--output-dir", default="output", help="Where to save video when headless (default: ./output)")
    parser.add_argument("--headless", action="store_true", help="Force saving to file instead of trying to open cv2 windows")
    parser.add_argument(
        "--idle-timeout", type=float, default=90.0,
        help="Seconds of silence before a session is considered dead and flushed (default: 90)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("cli_live")

    viewer = ViewerManager(output_dir=args.output_dir, headless=args.headless or None)
    frame_counts: dict[str, int] = {}

    def on_track_started(track):
        logger.info(
            "session started: %s codec=%s fps=%s transport=%s",
            track.label, track.codec, track.framerate, track.transport_proto,
        )

    def on_frame(track, frame):
        frame_counts[track.label] = frame_counts.get(track.label, 0) + 1
        viewer.on_frame(track, frame)

    def on_track_ended(track):
        logger.info("session ended: %s (%d frames)", track.label, frame_counts.get(track.label, 0))
        viewer.close_track(track)

    capture = LiveCapture(
        args.iface, on_frame=on_frame, on_track_started=on_track_started, on_track_ended=on_track_ended,
    )

    stopping = False

    def handle_sigint(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    logger.info("sniffing on %s (Ctrl-C to stop) ...", args.iface)
    try:
        capture.start()
    except PermissionError:
        logger.error("permission denied opening %s - live capture needs root/CAP_NET_RAW", args.iface)
        return 1
    except OSError as exc:
        logger.error("failed to start capture on %s: %s", args.iface, exc)
        return 1

    try:
        while not stopping:
            time.sleep(REAP_INTERVAL_SECONDS)
            reaped = capture.reap_idle_sessions(timeout=args.idle_timeout)
            for conn_id in reaped:
                logger.info("session %s went idle - flushed", conn_id)
    finally:
        capture.stop()
        viewer.close()

    for label, count in frame_counts.items():
        logger.info("%s: frames decoded=%d", label, count)
    logger.info("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
