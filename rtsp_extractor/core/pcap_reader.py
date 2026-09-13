"""Offline pcap/pcapng ingestion: scapy -> TCP reassembly -> Demuxer.

Streams the capture packet-by-packet (no full-file load), reassembles
each TCP connection per direction, and feeds the bytes to a `Demuxer`
instance which does RTSP parsing, session tracking and RTP depacketizing.
"""
from __future__ import annotations

import logging

from .rtp_demux import Demuxer
from .tcp_rtsp_bridge import TcpRtspBridge

logger = logging.getLogger(__name__)


def process_pcap(path: str, on_frame, on_track_started=None, progress_every: int = 0):
    """Read `path`, decode every RTSP+RTP session found, call on_frame(track, ndarray) per frame."""
    from scapy.all import PcapReader
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    demux = Demuxer(on_frame=on_frame, on_track_started=on_track_started)
    bridge = TcpRtspBridge(demux)

    packet_count = 0
    with PcapReader(path) as reader:
        for pkt in reader:
            packet_count += 1
            if progress_every and packet_count % progress_every == 0:
                logger.info("processed %d packets", packet_count)

            if IP in pkt:
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue

            if TCP in pkt:
                tcp = pkt["TCP"]
                bridge.handle_segment(src_ip, tcp.sport, dst_ip, tcp.dport, int(tcp.seq), bytes(tcp.payload))
            elif UDP in pkt:
                udp = pkt["UDP"]
                payload = bytes(udp.payload)
                if payload:
                    demux.feed_udp(dst_ip, int(udp.dport), payload)

    demux.flush_all()
    return demux
