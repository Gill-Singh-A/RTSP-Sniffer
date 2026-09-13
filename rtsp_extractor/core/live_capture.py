"""Phase 2: live interface sniffing, feeding the same TCP-reassembly ->
RTSP parsing -> RTP demux -> depacketize -> decode pipeline used for pcap
files (see `pcap_reader.py` / `tcp_rtsp_bridge.py`), but driven by
scapy's AsyncSniffer instead of a file.

Differences from the offline pcap path:
- Packets arrive continuously; there's no "end of file" to flush at, so
  callers should periodically call `LiveCapture.reap_idle_sessions()`.
- A bounded queue decouples the scapy capture thread (which must never
  block) from depacketize/decode work, which happens on a separate worker
  thread.
"""
from __future__ import annotations

import logging
import queue
import threading
import time

from .rtp_demux import Demuxer
from .tcp_rtsp_bridge import TcpRtspBridge

logger = logging.getLogger(__name__)

SESSION_IDLE_TIMEOUT_SECONDS = 90.0


class LiveCapture:
    def __init__(self, iface: str, on_frame, on_track_started=None, queue_size: int = 2048) -> None:
        self.iface = iface
        self.demux = Demuxer(on_frame=on_frame, on_track_started=on_track_started)
        self.bridge = TcpRtspBridge(self.demux)
        self._last_seen: dict[str, float] = {}
        self._queue: "queue.Queue" = queue.Queue(maxsize=queue_size)
        self._sniffer = None
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._dropped = 0

    # -- capture-thread side: must never block --------------------------

    def _on_packet(self, pkt) -> None:
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 500 == 1:
                logger.warning("capture queue full - dropped %d packets so far", self._dropped)

    # -- worker-thread side: does the actual parsing/decoding ------------

    def _worker_loop(self) -> None:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        while not self._stop.is_set():
            try:
                pkt = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if IP in pkt:
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue

            if TCP in pkt:
                tcp = pkt["TCP"]
                conn_id = self.bridge.handle_segment(
                    src_ip, tcp.sport, dst_ip, tcp.dport, int(tcp.seq), bytes(tcp.payload),
                )
                self._last_seen[conn_id] = time.monotonic()
            elif UDP in pkt:
                udp = pkt["UDP"]
                payload = bytes(udp.payload)
                if payload:
                    self.demux.feed_udp(dst_ip, int(udp.dport), payload)

    def reap_idle_sessions(self, timeout: float = SESSION_IDLE_TIMEOUT_SECONDS) -> list:
        """Flush and forget connections that have gone quiet (TEARDOWN missed,
        camera dropped off, etc). Returns the conn_ids reaped."""
        now = time.monotonic()
        stale = [cid for cid, ts in self._last_seen.items() if now - ts > timeout]
        for cid in stale:
            self.demux.flush_and_forget(cid)
            self.bridge.forget(cid)
            self._last_seen.pop(cid, None)
        return stale

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        from scapy.all import AsyncSniffer

        self._stop.clear()
        self._worker = threading.Thread(target=self._worker_loop, name="rtsp-sniffer-worker", daemon=True)
        self._worker.start()
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._on_packet, store=False)
        self._sniffer.start()
        logger.info("live capture started on %s", self.iface)

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=5)
        self.demux.flush_all()
        logger.info("live capture stopped (%d packets dropped due to backpressure)", self._dropped)
