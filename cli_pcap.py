#!/usr/bin/env python3
"""Phase 1 entrypoint: find every RTSP session in a pcap/pcapng file,
reconstruct its video, and display (or save) each detected stream.

    python cli_pcap.py capture.pcap
    python cli_pcap.py capture.pcap --headless -o output/
"""
from __future__ import annotations

import argparse
import logging
import sys

from rtsp_extractor.core.pcap_reader import process_pcap
from rtsp_extractor.viewer import ViewerManager


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="Path to a .pcap/.pcapng capture file")
    parser.add_argument("-o", "--output-dir", default="output", help="Where to save video when headless (default: ./output)")
    parser.add_argument("--headless", action="store_true", help="Force saving to file instead of trying to open cv2 windows")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("cli_pcap")

    viewer = ViewerManager(output_dir=args.output_dir, headless=args.headless or None)
    seen_tracks = []
    frame_counts: dict[str, int] = {}

    def on_track_started(track):
        seen_tracks.append(track)
        logger.info(
            "session started: %s codec=%s fps=%s transport=%s",
            track.label, track.codec, track.framerate, track.transport_proto,
        )

    def on_frame(track, frame):
        frame_counts[track.label] = frame_counts.get(track.label, 0) + 1
        viewer.on_frame(track, frame)

    logger.info("reading %s ...", args.pcap)
    try:
        process_pcap(args.pcap, on_frame=on_frame, on_track_started=on_track_started)
    finally:
        viewer.close()

    if not seen_tracks:
        logger.warning("no RTSP media sessions found in %s", args.pcap)
        return 1

    for track in seen_tracks:
        logger.info("%s: codec=%s frames decoded=%d", track.label, track.codec, frame_counts.get(track.label, 0))

    logger.info("done. %d track(s) processed.", len(seen_tracks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
