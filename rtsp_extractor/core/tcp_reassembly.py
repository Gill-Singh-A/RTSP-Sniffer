"""Minimal per-direction TCP stream reassembly, sequence-number based.

Not a general-purpose TCP stack: no SYN/FIN tracking, no window handling.
Just enough to turn "packets in capture order, maybe reordered or
retransmitted" into "one ordered byte stream per direction", which is all
the RTSP parser needs.
"""
from __future__ import annotations

SEQ_MODULO = 1 << 32


def _seq_delta(a: int, b: int) -> int:
    """a - b, wrapping around the 32-bit TCP sequence space, sign-preserving."""
    d = (a - b) % SEQ_MODULO
    if d >= SEQ_MODULO // 2:
        d -= SEQ_MODULO
    return d


class DirectionalReassembler:
    def __init__(self) -> None:
        self._expected: int | None = None
        self._pending: dict[int, bytes] = {}

    def add(self, seq: int, payload: bytes) -> bytes:
        """Feed one segment; returns newly-contiguous bytes (maybe empty)."""
        if not payload:
            return b""

        if self._expected is None:
            self._expected = seq

        delta = _seq_delta(seq, self._expected)

        if delta > 0:
            # Ahead of what we need - stash it for later.
            if seq not in self._pending:
                self._pending[seq] = payload
            return b""

        if delta < 0:
            # Starts before what we need; drop the already-seen prefix.
            skip = -delta
            if skip >= len(payload):
                return b""  # fully-seen retransmission
            payload = payload[skip:]
            seq = self._expected

        out = bytearray(payload)
        self._expected = seq + len(payload)

        # Pull in any buffered segments that are now contiguous.
        while True:
            nxt = self._pending.pop(self._expected, None)
            if nxt is None:
                # Also check for overlapping buffered segments starting earlier.
                match = None
                for pend_seq in list(self._pending):
                    d = _seq_delta(pend_seq, self._expected)
                    if d <= 0 < d + len(self._pending[pend_seq]):
                        match = pend_seq
                        break
                if match is None:
                    break
                seg = self._pending.pop(match)
                skip = -_seq_delta(match, self._expected)
                seg = seg[skip:]
                if not seg:
                    continue
                out.extend(seg)
                self._expected += len(seg)
                continue
            out.extend(nxt)
            self._expected += len(nxt)

        return bytes(out)


class TcpConnectionReassembler:
    """Two DirectionalReassemblers, one per flow direction."""

    def __init__(self) -> None:
        self.directions: dict[str, DirectionalReassembler] = {}

    def add(self, direction_key: str, seq: int, payload: bytes) -> bytes:
        reassembler = self.directions.setdefault(direction_key, DirectionalReassembler())
        return reassembler.add(seq, payload)
