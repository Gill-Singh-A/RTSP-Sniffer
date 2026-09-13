# RTSP Stream Extractor & Viewer

## Purpose

A tool that inspects network traffic for RTSP sessions, locates the associated
RTP media streams, reconstructs the video, and displays it. Two delivery
modes, built in sequence:

1. **Phase 1 — Offline (pcap/pcapng file)**: parse a capture file, find RTSP
   sessions, extract and decode the RTP video streams they negotiated,
   display/save each detected stream.
2. **Phase 2 — Live (interface sniffing)**: same pipeline, but fed from a live
   capture on a network interface in near real time.

Only build Phase 2 after Phase 1 is solid — the depacketization/decoding core
is shared between both.

---

## How RTSP/RTP actually works (context for implementation)

- RTSP itself (TCP, usually port 554) is just signaling: `DESCRIBE`, `SETUP`,
  `PLAY`, `TEARDOWN`. It carries an **SDP** blob describing the media
  (codec, payload type, sometimes `fmtp` with SPS/PPS for H.264).
- `SETUP` responses/requests reveal the **transport**: client/server RTP+RTCP
  ports (UDP case) or interleaved channel numbers (TCP case, media multiplexed
  inside the RTSP TCP connection with `$` framing).
- The real video travels as **RTP packets** on those negotiated
  ports/channels. RTP payload format depends on codec:
  - H.264 → RFC 6184 (FU-A fragmentation, STAP-A aggregation, etc.)
  - H.265 → RFC 7798 (similar idea, different NAL header size)
  - MJPEG → RFC 2435
- To get playable video you must: match RTP packets to the right
  session (by port or SSRC), depacketize into NAL units / JPEG frames per the
  RFC, reassemble into an Annex-B elementary stream (or raw JPEGs), then decode.
- OpenCV's job is only the *last step* — displaying decoded frames
  (`cv2.imshow`) or doing analysis on them. It does not depacketize RTP.

---

## Recommended architecture

```
capture source (pcap file OR live iface)
        │
        ▼
[RTSP session tracker]  — parses RTSP requests/responses, extracts SDP,
                           tracks transport (ports/channels) per session
        │
        ▼
[RTP stream demux]       — matches packets to sessions by port/SSRC,
                           handles TCP-interleaved framing too
        │
        ▼
[Depacketizer]           — per-codec (H.264/H.265/MJPEG) RFC-specific logic,
                           reassembles into elementary stream / frames
        │
        ▼
[Decoder]                — PyAV (ffmpeg bindings) or subprocess ffmpeg pipe,
                           decodes Annex-B stream to raw frames
        │
        ▼
[Display / Output]        — cv2.imshow per stream window, and/or
                           save to .mp4 / .jpg sequence per session
```

## Suggested libraries

- **scapy** — pcap parsing (offline) and live sniffing (`sniff()`), easiest
  to prototype with. Alternative: `pyshark` (wraps tshark) if scapy's TCP
  reassembly proves painful.
- **PyAV** (`av`) — decode raw H.264/H.265 Annex-B byte streams to frames
  without shelling out. Preferred over raw ffmpeg subprocess for robustness.
- **opencv-python** — display (`cv2.imshow`), frame saving, any post-decode
  analysis/overlay.
- Avoid trying to get OpenCV's own `VideoCapture` to open RTP/RTSP directly
  from a pcap — it expects a live network/URL source, not extracted packets.

## Project layout (suggested)

```
rtsp_extractor/
  core/
    rtsp_parser.py       # RTSP request/response + SDP parsing
    session_tracker.py   # maps RTSP sessions -> transport info
    rtp_demux.py         # matches RTP packets to sessions
    depacketizers/
      h264.py
      h265.py
      mjpeg.py
    decoder.py           # PyAV wrapper: bytes in -> frames out
  cli_pcap.py             # Phase 1 entrypoint: python cli_pcap.py capture.pcap
  cli_live.py             # Phase 2 entrypoint: python cli_live.py -i eth0
  viewer.py               # cv2 display + optional save-to-file
  tests/
    fixtures/             # small sample pcaps with known-good RTSP+RTP
```

---

## Phase 1 — Pcap file mode

**Goal:** `python cli_pcap.py capture.pcap` finds every RTSP session in the
file, reconstructs each into a viewable/saveable video.

Steps:
1. Read pcap with scapy, reassemble TCP streams for RTSP control connections
   (port 554 by default, but don't hardcode — detect by RTSP request lines).
2. Parse SETUP/PLAY exchanges, extract SDP (codec, payload type) and
   transport (UDP ports or interleaved channel IDs).
3. For UDP transport: filter subsequent packets by matched port pairs. For
   TCP-interleaved: demux `$`-framed data within the same TCP stream.
4. Depacketize per codec into an elementary stream.
5. Decode via PyAV, display each detected stream in its own `cv2` window
   (or, if running headless, save to `output/<session_id>.mp4`).
6. Handle multiple concurrent RTSP sessions in one file — label windows/
   files by stream identifier (e.g. source IP:port or SDP media description).

**Deliverable for this phase:** CLI tool + a couple of test pcaps (can be
generated with `ffmpeg`/`vlc` streaming to a local RTSP server while
capturing with `tcpdump`) proving end-to-end reconstruction works for at
least H.264.

## Phase 2 — Live sniffing mode

**Goal:** `python cli_live.py -i eth0` does the same detection/reconstruction
in real time.

Additional concerns vs Phase 1:
- Use scapy's `sniff()` with a callback, or `AsyncSniffer`, non-blocking.
- Sessions can start/stop mid-capture — need session lifecycle handling
  (start on SETUP/PLAY, clean up on TEARDOWN or timeout).
- Depacketizer/decoder must work incrementally (streaming), not batch —
  reuse Phase 1 depacketizer logic but feed it packet-by-packet instead of
  all at once.
- Consider a bounded queue + worker thread per stream so packet capture
  never blocks on decode/display.
- Add basic drop/reorder handling using RTP sequence numbers and timestamps
  (real networks reorder more than pcaps captured close to the source).
- Needs elevated privileges (root/CAP_NET_RAW) — document this in README.

---

## Non-goals / out of scope (for now)

- Decrypting SRTP/encrypted RTSP streams (this is for cleartext RTP; add a
  note if SRTP is detected but don't attempt to break encryption).
- Audio stream handling (video-only for v1; can extend depacketizers later).
- RTSP-over-HTTP tunneling.

## Notes

- Use only on traffic you're authorized to capture/analyze.
- Keep the RTSP/SDP parser and depacketizers unit-testable in isolation from
  scapy/pcap plumbing — feed them raw bytes in tests, not live captures.
