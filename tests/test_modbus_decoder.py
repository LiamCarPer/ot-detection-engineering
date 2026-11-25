"""Guard the committed Modbus/TCP example frames.

The Rust tests already decode these frames; this check keeps the committed
fixture honest from the Python side as well, so a hand-edit that breaks the
MBAP length or drops a required function code fails the normal test run.
"""

from __future__ import annotations

from pathlib import Path

FRAMES = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "modbus-dpi"
    / "examples"
    / "frames.hex"
)

REQUIRED_FUNCTIONS = {1, 2, 3, 4, 5, 6, 15, 16, 22, 23, 43}


def _frames() -> list[bytes]:
    frames = []
    for line in FRAMES.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        frames.append(bytes.fromhex(line))
    return frames


def test_frames_have_a_consistent_mbap_length() -> None:
    frames = _frames()
    assert frames
    for frame in frames:
        assert len(frame) >= 8
        assert frame[2:4] == b"\x00\x00", "protocol id must be zero"
        declared = int.from_bytes(frame[4:6], "big")
        assert declared >= 2
        assert declared == len(frame) - 6, "MBAP length must cover unit id and PDU"


def test_examples_cover_the_required_function_codes() -> None:
    observed = {frame[7] & 0x7F for frame in _frames()}
    assert REQUIRED_FUNCTIONS <= observed, sorted(REQUIRED_FUNCTIONS - observed)


def test_examples_include_an_exception_and_a_coil_write() -> None:
    frames = _frames()
    assert any(frame[7] & 0x80 for frame in frames), "no exception response"

    coil_writes = [frame for frame in frames if frame[7] == 5]
    assert coil_writes, "no Write Single Coil frame"
    frame = coil_writes[0]
    assert int.from_bytes(frame[8:10], "big") == 172
    assert int.from_bytes(frame[10:12], "big") == 0xFF00


def test_examples_include_the_block_write_range_boundary() -> None:
    writes = [
        frame
        for frame in _frames()
        if frame[7] == 16 and int.from_bytes(frame[8:10], "big") == 3999
    ]
    assert writes, "no FC16 write starting at register 3999"
    frame = writes[0]
    assert int.from_bytes(frame[10:12], "big") == 10
    assert frame[12] == 20, "ten registers are twenty payload octets"
