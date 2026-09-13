# RTSP Stream Extractor & Viewer

Inspects network traffic for RTSP sessions, locates the RTP media streams
they negotiate, reconstructs the video, and displays or saves it — either
from a `.pcap`/`.pcapng` capture file or by sniffing a live network
interface.

## Features

- Finds RTSP sessions in a capture without assuming port 554 - detected
  from the RTSP request line itself.
- Parses SDP to identify codec, clock rate, and out-of-band SPS/PPS/VPS.
- Handles both `RTP/AVP/TCP` (interleaved, `$`-framed within the RTSP
  connection) and `RTP/AVP` (UDP) transport.
- Depacketizes H.264 (RFC 6184), H.265/HEVC (RFC 7798), and MJPEG
  (RFC 2435) into decodable elementary streams / JPEG frames.
- Decodes via PyAV (H.264/H.265) or OpenCV (MJPEG) and either displays
  each stream live (`cv2.imshow`) or saves it to its own `.mp4`.
- Handles multiple concurrent RTSP sessions in one capture, each tracked
  and saved independently.
- Live mode tolerates real-world packet loss/reordering without crashing,
  and correctly finalizes each session's output whether it ends via
  `TEARDOWN` or simply goes idle.

## Installation

```
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Requires `scapy`, `av` (PyAV/ffmpeg bindings), `opencv-python`, `numpy`.
Live capture additionally needs libpcap and packet-capture privileges
(see below).

## Usage

### Read a capture file

```
python cli_pcap.py capture.pcapng
python cli_pcap.py capture.pcapng --headless -o output/
```

### Sniff a live interface

```
sudo python cli_live.py -i eth0
sudo python cli_live.py -i eth0 --headless -o output/
```

Opening a raw socket needs root or `CAP_NET_RAW`
(`sudo setcap cap_net_raw+ep $(which python3)` is an alternative to
running under `sudo` every time - note this grants the capability to
*that* interpreter for *any* script it runs). Sessions that go quiet for
`--idle-timeout` seconds (default 90) without a `TEARDOWN` are finalized
and cleaned up automatically.

Every RTSP session found gets its own output: a `cv2.imshow` window if a
display is available, otherwise
`output/<client-ip-port_server-ip-port>-<trackID>.mp4`. Headless mode is
auto-detected (no `$DISPLAY` on Linux) but can be forced with
`--headless`.

## Architecture

```
capture source (pcap file OR live iface)
        │
        ▼
[TCP reassembly]          per-direction, sequence-number based
        │
        ▼
[RTSP session tracker]    parses RTSP requests/responses, extracts SDP,
                          tracks transport (interleaved channels or UDP
                          ports) per session
        │
        ▼
[RTP demux]               matches packets to sessions by interleaved
                          channel or UDP port, dispatches to a track
        │
        ▼
[Depacketizer]             per-codec reassembly into NAL units / JPEG
                          frames
        │
        ▼
[Decoder]                  PyAV for H.264/H.265, OpenCV for MJPEG
        │
        ▼
[Display / Output]         cv2.imshow per stream, or an .mp4 per session
```

`Demuxer` ties a connection's RTSP session tracker to per-track decode
pipelines and is shared, unmodified, between the file and live-capture
paths; `TcpRtspBridge` is the other shared piece - it reassembles TCP,
identifies the RTSP client from the request line (not a hardcoded port),
and hands the byte stream to the `Demuxer`.

```
rtsp_extractor/
  core/
    rtp.py                  RTP header parsing (RFC 3550)
    sdp.py                  SDP parsing (RFC 4566)
    rtsp_parser.py            Incremental RTSP message / interleaved-frame parser
    session_tracker.py         RTSP session -> Track (codec, transport, channels/ports)
    tcp_reassembly.py          Per-direction TCP stream reassembly
    tcp_rtsp_bridge.py           Shared TCP connection -> Demuxer glue
    rtp_demux.py               Track routing + per-connection state
    track_pipeline.py            RTP -> depacketizer -> decoder -> frame, per track
    decoder.py                   PyAV (H.264/H.265) + OpenCV (MJPEG) decode
    depacketizers/
      h264.py                    RFC 6184 (FU-A, STAP-A, single NAL)
      h265.py                    RFC 7798 (FU, AP, single NAL)
      mjpeg.py                    RFC 2435
    pcap_reader.py              Capture-file entrypoint: scapy PcapReader -> TcpRtspBridge
    live_capture.py               Live entrypoint: scapy AsyncSniffer -> TcpRtspBridge
cli_pcap.py                    Read-a-capture-file CLI
cli_live.py                     Sniff-a-live-interface CLI
viewer.py                        cv2 display / mp4 save sink
tests/                          Unit tests - no scapy/pcap plumbing needed,
                               everything is fed raw synthetic bytes
```

## How it works

- **RTSP parsing** (`rtsp_parser.py`) is a single incremental parser that
  handles both plain-text RTSP request/response framing *and* the binary
  `$`-prefixed interleaved-RTP framing used by `RTP/AVP/TCP` transport, in
  the same byte stream - real cameras mix both on the same TCP
  connection. It's fed bytes via `feed()` and buffers whatever's
  incomplete, so the same code works for an offline reassembled stream or
  a live socket.
- **Digest authentication** in the observed exchange is only *read*
  (matched by CSeq, so a `SETUP` reply can be tied back to its request) -
  never solved or replayed. The tool reconstructs already-authenticated
  traffic it observes; it does not attempt to authenticate itself.
- **Session tracking** (`session_tracker.py`) correlates `DESCRIBE` (SDP:
  codec, clock rate, `fmtp` with SPS/PPS/VPS) with `SETUP` (`Transport:`
  header: interleaved channel numbers or UDP client/server ports) to
  build a `Track` per negotiated media.
- **Depacketizers** turn RTP payloads into NAL units (H.264/H.265) or full
  JPEG frames (MJPEG), per their RFC. Access units are assembled by
  buffering NALs until the RTP marker bit signals "last packet of this
  frame", then handed to the decoder as one packet - the boundary
  ffmpeg's decoders expect. SPS/PPS/VPS carried out-of-band in `fmtp` are
  decoded once and re-prepended before every keyframe, so the decoder can
  init from any handed-off elementary stream.

## Testing

```
./venv/bin/pip install pytest
./venv/bin/python -m pytest tests/ -q
```

Unit tests cover SDP parsing, RTSP/interleaved-frame parsing, session
tracking end-to-end, H.264/H.265/MJPEG depacketization, TCP reassembly
edge cases (reorder/retransmit/overlap/wraparound), and the shared
TCP-to-RTSP bridge - all fed synthetic raw bytes, independent of scapy or
actual capture files.

## Limitations

- Cleartext RTP only - SRTP/encrypted RTSP is not decrypted.
- Video only; audio tracks are ignored.
- No RTSP-over-HTTP tunneling.
- No reordering buffer: a dropped or reordered RTP packet mid-fragment
  abandons that fragmentation run (logged, not fatal) rather than being
  recovered.
- When a track's SDP omits `a=framerate`, the saved `.mp4` falls back to
  a nominal 25fps container rate; the frames themselves are correct, but
  playback speed may not match wall-clock time for that source.
