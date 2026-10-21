#!/usr/bin/env python3
"""
linear_stream_parser.py

Memory-bounded, fault-tolerant sequential binary stream parser.
Implements stream-locked synchronization, forward verification,
and error-tolerant frame extraction for linear binary architectures.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import BinaryIO, Generator, Optional, Tuple

# Configuration Constants
SYNC_MARKER: bytes = b"\x53\x59\x4E\x43"  # "SYNC"
SYNC_LEN: int = len(SYNC_MARKER)
STATIC_HEADER_FORMAT: str = "<IIHQ"  # Sync(4), SeqID(4), Len(2), Timestamp(8)
STATIC_HEADER_SIZE: int = struct.calcsize(STATIC_HEADER_FORMAT)
MAX_PAYLOAD_SIZE: int = 65535

def compute_crc16_ccitt(data: bytes, initial: int = 0xFFFF) -> int:
    """Computes CRC-16-CCITT (poly 0x1021) across input bytes."""
    crc = initial
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

@dataclass(frozen=True)
class StreamFrame:
    """Represents a validated, deserialized linear record."""
    offset: int
    sequence_id: int
    timestamp_us: int
    payload: bytes
    crc_valid: bool

class CorruptFrameException(Exception):
    """Raised when record fails validation checks."""
    pass

class LinearStreamParser:
    """
    Parser implementing single-pass linear de-framing with
    active resynchronization for noisy or corrupted byte streams.
    """

    def __init__(self, stream: BinaryIO, strict: bool = False):
        self.stream = stream
        self.strict = strict
        self.bytes_scanned: int = 0

    def parse_records(self) -> Generator[StreamFrame, None, None]:
        """
        Stream generator yielding valid parsed records.
        Maintains minimal memory footprint using internal streaming buffers.
        """
        while True:
            current_offset = self.stream.tell()
            marker = self.stream.read(SYNC_LEN)

            if len(marker) < SYNC_LEN:
                # Normal EOF reached
                break

            if marker == SYNC_MARKER:
                frame = self._attempt_read_frame(current_offset)
                if frame is not None:
                    yield frame
                    continue

            # Out of sync or malformed record encountered
            if self.strict:
                raise CorruptFrameException(
                    f"Structural lock lost at absolute offset 0x{current_offset:08X}"
                )

            # Enter Hunt Mode: roll back SYNC_LEN - 1 bytes and step forward by 1 byte
            self.stream.seek(current_offset + 1, io.SEEK_SET)

    def _attempt_read_frame(self, frame_offset: int) -> Optional[StreamFrame]:
        """
        Speculatively parses a frame from the current header location.
        Returns the parsed frame if structural invariants hold; otherwise None.
        """
        # Read the rest of the fixed frame header (excluding the sync marker)
        remaining_header_len = STATIC_HEADER_SIZE - SYNC_LEN
        header_data = self.stream.read(remaining_header_len)

        if len(header_data) < remaining_header_len:
            return None

        # Reconstruct complete static header block for unpacking
        full_header = SYNC_MARKER + header_data
        _, seq_id, payload_len, timestamp = struct.unpack(
            STATIC_HEADER_FORMAT, full_header
        )

        if payload_len > MAX_PAYLOAD_SIZE:
            return None

        # Read variable payload plus trailing 2-byte CRC
        body_len = payload_len + 2
        body_data = self.stream.read(body_len)

        if len(body_data) < body_len:
            return None

        payload = body_data[:payload_len]
        (expected_crc,) = struct.unpack("<H", body_data[payload_len:])

        # Integrity verification
        calc_crc = compute_crc16_ccitt(full_header + payload)
        is_valid = calc_crc == expected_crc

        if not is_valid and self.strict:
            return None

        return StreamFrame(
            offset=frame_offset,
            sequence_id=seq_id,
            timestamp_us=timestamp,
            payload=payload,
            crc_valid=is_valid,
        )

def analyze_stream_cadence(file_path: str) -> None:
    """Triage utility to inspect and print metrics of a linear binary stream."""
    import sys

    print(f"[*] Triaging linear binary architecture: {file_path}")
    try:
        with open(file_path, "rb") as f:
            parser = LinearStreamParser(f, strict=False)
            count = 0
            last_seq: Optional[int] = None
            last_time: Optional[int] = None
            crc_failures = 0

            for frame in parser.parse_records():
                count += 1
                seq_delta = (
                    (frame.sequence_id - last_seq)
                    if last_seq is not None
                    else 0
                )
                time_delta = (
                    (frame.timestamp_us - last_time)
                    if last_time is not None
                    else 0
                )

                if not frame.crc_valid:
                    crc_failures += 1

                if count <= 5 or count % 1000 == 0:
                    status = "OK" if frame.crc_valid else "CRC_ERR"
                    print(
                        f"Frame {count:06d} | Offset: 0x{frame.offset:08X} | "
                        f"Seq: {frame.sequence_id} (Δ{seq_delta:+d}) | "
                        f"Time: {frame.timestamp_us} us (Δ{time_delta} us) | "
                        f"Bytes: {len(frame.payload)} | Status: {status}"
                    )

                last_seq = frame.sequence_id
                last_time = frame.timestamp_us

            print("=" * 68)
            print(f"[+] Total Valid Frames Decoded: {count}")
            print(f"[!] Total Checksum Anomalies:  {crc_failures}")

    except FileNotFoundError:
        print(f"[-] Target file not found: {file_path}", file=sys.stderr)
    except Exception as e:
        print(f"[-] Execution halted: {e}", file=sys.stderr)

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python linear_stream_parser.py <path_to_binary_file>")
        sys.exit(1)

    analyze_stream_cadence(sys.argv[1])
