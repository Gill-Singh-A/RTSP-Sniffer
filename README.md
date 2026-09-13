# RTSP Stream Extractor & Viewer

Inspects network traffic for RTSP sessions, locates the RTP media streams
they negotiate, reconstructs the video, and displays or saves it — from a
pcap/pcapng file (Phase 1) or a live interface (Phase 2).

## Status

- **Phase 1 (offline pcap/pcapng) — done and validated.** Tested against
  two real captures: a single-session H.264 stream and an 85-session
  capture mixing H.264 and H.265 across dozens of concurrent cameras. See
  [Validation results](#validation-results).
- **Phase 2 (live interface sniffing) — implemented, unit-tested, not yet
  validated against a live capture.** Starting a real capture needs
  root/`CAP_NET_RAW` on the box doing the sniffing; that hasn't been
  exercised end-to-end yet.

## Architecture

```
capture source (pcap file OR live iface)
        │
        ▼
[TCP reassembly]         — per-direction, sequence-number based
        │                  (tcp_reassembly.py, tcp_rtsp_bridge.py)
        ▼
[RTSP session tracker]   — parses RTSP requests/responses, extracts SDP,
                            tracks transport (interleaved channels or UDP
                            ports) per session
        │                  (rtsp_parser.py, sdp.py, session_tracker.py)
        ▼
[RTP demux]               — matches packets to sessions by interleaved
                            channel or UDP port, dispatches to a track's
                            pipeline
        │                  (rtp_demux.py)
        ▼
[Depacketizer]             — per-codec RFC-specific reassembly into NAL
                            units / JPEG frames
        │                  (depacketizers/h264.py, h265.py, mjpeg.py)
        ▼
[Decoder]                  — PyAV for H.264/H.265 Annex-B, OpenCV for MJPEG
        │                  (decoder.py, track_pipeline.py)
        ▼
[Display / Output]          — cv2.imshow per stream window, or
                            output/<session-label>.mp4 when headless
                             (viewer.py)
```

`Demuxer` (in `rtp_demux.py`) is the piece that ties a connection's RTSP
session tracker to per-track `TrackPipeline`s and is shared, unmodified,
between the offline and live paths. `TcpRtspBridge` (in
`tcp_rtsp_bridge.py`) is the other shared piece: it reassembles TCP,
decides which endpoint is the RTSP client (by request-line sniffing, not
a hardcoded port), and hands the byte stream to the `Demuxer`.

## Project layout

```
rtsp_extractor/
  core/
    rtp.py                 RTP header parsing (RFC 3550)
    sdp.py                 SDP parsing (RFC 4566)
    rtsp_parser.py          Incremental RTSP message / interleaved-$-frame parser
    session_tracker.py       RTSP session -> Track (codec, transport, channels/ports)
    tcp_reassembly.py        Per-direction TCP stream reassembly
    tcp_rtsp_bridge.py        Shared TCP connection -> Demuxer glue (pcap + live)
    rtp_demux.py             Track routing + per-connection state
    track_pipeline.py         RTP -> depacketizer -> decoder -> frame, per track
    decoder.py                PyAV (H.264/H.265) + OpenCV (MJPEG) decode
    depacketizers/
      h264.py                 RFC 6184 (FU-A, STAP-A, single NAL)
      h265.py                 RFC 7798 (FU, AP, single NAL)
      mjpeg.py                 RFC 2435
    pcap_reader.py            Phase 1: scapy PcapReader -> TcpRtspBridge
    live_capture.py            Phase 2: scapy AsyncSniffer -> TcpRtspBridge
cli_pcap.py                  Phase 1 entrypoint
cli_live.py                   Phase 2 entrypoint
viewer.py                     cv2 display / mp4 save sink
tests/                        Unit tests (parsers, depacketizers, tracker) — no
                             scapy/pcap plumbing needed, all fed raw bytes
```

## Installation

```
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Needs `scapy`, `av` (PyAV/ffmpeg bindings), `opencv-python`, `numpy`.
Live mode additionally needs libpcap and packet-capture privileges (see
below).

## Usage

### Phase 1 — pcap file

```
python cli_pcap.py capture.pcapng
python cli_pcap.py capture.pcapng --headless -o output/
```

Every RTSP session found gets its own output: an `cv2.imshow` window if
a display is available, otherwise `output/<client_ip-port_server_ip-port>-<trackID>.mp4`.
Headless is auto-detected (no `$DISPLAY` on Linux) but can be forced with
`--headless`.

### Phase 2 — live interface

```
sudo python cli_live.py -i eth0
sudo python cli_live.py -i eth0 --headless -o output/
```

Needs to open a raw socket, so it needs root or `CAP_NET_RAW`
(`sudo setcap cap_net_raw+ep $(which python3)` once, as an alternative to
running under `sudo` every time — note this grants the capability to
*that* interpreter for *any* script it runs). Sessions that go quiet for
`--idle-timeout` seconds (default 90) without a `TEARDOWN` are flushed
and cleaned up automatically, since live traffic has no natural
"end of file".

## How it works

- **RTSP parsing** (`rtsp_parser.py`) is a single incremental parser that
  handles both plain-text RTSP request/response framing *and* the binary
  `$`-prefixed interleaved-RTP framing used by `RTP/AVP/TCP` transport, in
  the same byte stream — because on real cameras (see below) both
  actually mix on the same TCP connection. It's fed bytes via `feed()`
  and buffers whatever's incomplete, so it works identically for an
  offline reassembled stream or a live socket.
- **Digest authentication** in the captured exchange is only *read*
  (matched CSeq -> method, so a `SETUP`'s reply can be tied back to its
  request) — never solved or replayed. The tool only reconstructs
  already-authenticated traffic it observes.
- **Session tracking** (`session_tracker.py`) correlates `DESCRIBE` (SDP:
  codec, clock rate, `fmtp` with SPS/PPS/VPS) with `SETUP` (`Transport:`
  header: interleaved channel numbers or UDP client/server ports) to
  build a `Track` per negotiated media, matched to its RTSP connection.
- **Depacketizers** turn RTP payloads into NAL units (H.264/H.265) or full
  JPEG frames (MJPEG), per their RFC. Access units are assembled by
  buffering NALs until the RTP marker bit signals "last packet of this
  frame", then handed to the decoder as one packet — the standard
  boundary ffmpeg's decoders expect, rather than feeding partial frames.
  SPS/PPS/VPS carried out-of-band in `fmtp` are decoded once and
  re-prepended before every keyframe, so the decoder can always init from
  any handed-off elementary stream.

## Testing

```
./venv/bin/pip install pytest
./venv/bin/python -m pytest tests/ -q
```

29 unit tests, none touching scapy or actual pcap files — everything is
fed synthetic raw bytes so the parsing/depacketizing logic is testable in
isolation:

- `test_sdp.py` — SDP parsing against real captured H.264/H.265 SDP bodies
- `test_rtsp_parser.py` — request/response framing, `Content-Length`
  bodies, split-across-reads messages, interleaved `$`-frames mixed with
  RTSP text
- `test_session_tracker.py` — full DESCRIBE/SETUP/PLAY/TEARDOWN flow ->
  `Track` with correct codec/channels/framerate
- `test_h264_depacketizer.py` / `test_h265_depacketizer.py` — single NAL
  passthrough, STAP-A/AP aggregation splitting, FU-A/FU fragment
  reassembly, sequence-gap abandonment, `sprop-*` decoding
- `test_mjpeg_depacketizer.py` — RFC 2435 header reconstruction,
  multi-packet frame reassembly
- `test_tcp_reassembly.py` — in-order, out-of-order/buffered,
  retransmission, partial-overlap, sequence-wraparound cases
- `test_tcp_rtsp_bridge.py` — client-endpoint classification from the
  request line, connection-id symmetry

## Validation results

Run against the two capture files this tool was built and tested with:

| Capture | Sessions | Codec(s) | Notes |
|---|---|---|---|
| `rtsp_login_and_capture.pcapng` (261 KB, 380 pkts) | 1 | H.264 | 1920x1080@25fps, 41 frames decoded |
| `RTSP_Login_&_Capture.pcapng` (109 MB, 89,101 pkts) | 85 | H.264 + H.265 | Resolutions from 1920x1080 to 2560x1440, 20-25fps; ~85s end-to-end |

Both captures use Digest-authenticated `RTP/AVP/TCP` (interleaved)
transport, negotiated over TCP port 554. Every one of the 86 total output
`.mp4` files was verified with `ffprobe` to have a non-zero, correct
frame count and no corruption.

## Non-goals (per project scope)

- Decrypting SRTP/encrypted RTSP — cleartext RTP only.
- Audio streams — video-only for v1.
- RTSP-over-HTTP tunneling.

## Known gaps / next steps

- MJPEG depacketizer (RFC 2435, default quant/huffman tables) is
  implemented and unit-tested against synthetic packets, but neither
  fixture capture uses MJPEG, so it hasn't been exercised against a real
  stream.
- UDP transport (`RTP/AVP` client/server ports rather than interleaved)
  is implemented in `Demuxer`/`session_tracker.py` but likewise untested
  against a real capture — both fixtures negotiate `RTP/AVP/TCP`.
- Live capture (Phase 2) needs a real interface with actual RTSP traffic
  (or a replayed capture + root/`CAP_NET_RAW`) to validate end-to-end;
  not yet done.
- Reorder/drop handling on live capture currently means "sequence gaps
  drop the in-flight FU-A/FU fragment and log a warning" — there's no
  reordering buffer yet, so a reordered (not just dropped) packet on a
  lossy live link will still lose that fragment run.
