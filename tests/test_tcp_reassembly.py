from rtsp_extractor.core.tcp_reassembly import DirectionalReassembler


def test_in_order_delivery():
    r = DirectionalReassembler()
    assert r.add(100, b"AAAA") == b"AAAA"
    assert r.add(104, b"BBBB") == b"BBBB"


def test_out_of_order_buffered_then_delivered():
    r = DirectionalReassembler()
    assert r.add(100, b"AAAA") == b"AAAA"
    assert r.add(108, b"CCCC") == b""       # arrives early, buffered
    assert r.add(104, b"BBBB") == b"BBBBCCCC"  # fills the gap, flushes both


def test_retransmission_is_dropped():
    r = DirectionalReassembler()
    assert r.add(100, b"AAAA") == b"AAAA"
    assert r.add(100, b"AAAA") == b""  # exact retransmit, already seen
    assert r.add(104, b"BBBB") == b"BBBB"


def test_partial_overlap_trimmed():
    r = DirectionalReassembler()
    assert r.add(100, b"AAAA") == b"AAAA"
    # Starts 2 bytes before the new frontier and extends past it.
    assert r.add(102, b"AABBBB") == b"BBBB"


def test_sequence_wraparound():
    r = DirectionalReassembler()
    near_wrap = (1 << 32) - 4
    assert r.add(near_wrap, b"AAAA") == b"AAAA"
    assert r.add(0, b"BBBB") == b"BBBB"
