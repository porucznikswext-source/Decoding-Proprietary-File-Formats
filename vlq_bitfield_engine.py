#!/usr/bin/env python3
"""
vlq_bitfield_engine.py

Comprehensive decoding toolkit for variable-length integers (LEB128,
ZigZag, MIDI VLQ, EBML VINT) and unaligned bitfield extraction.
"""

import io
import struct
from typing import BinaryIO, List, Literal, Optional, Tuple

class VLQDecodeError(ValueError):
    """Raised when an invalid or truncated variable-length sequence is encountered."""
    pass

class BitStreamError(EOFError):
    """Raised when an arbitrary bitfield read exceeds available stream capacity."""
    pass

# =====================================================================
# Variable-Length Quantity (VLQ) Decoders
# =====================================================================

def decode_uleb128(stream: BinaryIO) -> Tuple[int, int]:
    """
    Decodes an Unsigned Little-Endian Base 128 (ULEB128) integer.
    Returns: (decoded_value, bytes_consumed)
    """
    result = 0
    shift = 0
    bytes_read = 0

    while True:
        raw_byte = stream.read(1)
        if not raw_byte:
            raise VLQDecodeError("Unexpected EOF while parsing ULEB128.")
        
        byte_val = raw_byte[0]
        bytes_read += 1
        
        # 64-bit integer safeguard against malicious malformed inputs
        if shift > 63:
            raise VLQDecodeError("ULEB128 sequence exceeds 64-bit structural limit.")

        payload = byte_val & 0x7F
        result |= (payload << shift)
        shift += 7

        if (byte_val & 0x80) == 0:
            break

    return result, bytes_read

def decode_sleb128(stream: BinaryIO) -> Tuple[int, int]:
    """
    Decodes a Signed Little-Endian Base 128 (SLEB128) integer.
    Performs sign extension based on the final payload's MSB.
    Returns: (decoded_value, bytes_consumed)
    """
    result = 0
    shift = 0
    bytes_read = 0

    while True:
        raw_byte = stream.read(1)
        if not raw_byte:
            raise VLQDecodeError("Unexpected EOF while parsing SLEB128.")

        byte_val = raw_byte[0]
        bytes_read += 1

        if shift > 63:
            raise VLQDecodeError("SLEB128 sequence exceeds 64-bit structural limit.")

        payload = byte_val & 0x7F
        result |= (payload << shift)
        shift += 7

        # Sign bit of the current 7-bit payload is bit 6 (0x40)
        if (byte_val & 0x80) == 0:
            if (byte_val & 0x40) != 0:
                # Sign extend negative numbers into upper Python integer bits
                result |= -(1 << shift)
            break

    return result, bytes_read

def decode_zigzag(value: int) -> int:
    """Decodes a ZigZag-encoded unsigned integer into its signed representation."""
    return (value >> 1) ^ (-(value & 1))

def decode_midi_vlq(stream: BinaryIO) -> Tuple[int, int]:
    """
    Decodes a standard Big-Endian Variable-Length Quantity (MIDI / PDF style).
    Returns: (decoded_value, bytes_consumed)
    """
    result = 0
    bytes_read = 0

    while True:
        raw_byte = stream.read(1)
        if not raw_byte:
            raise VLQDecodeError("Unexpected EOF while parsing MIDI VLQ.")

        byte_val = raw_byte[0]
        bytes_read += 1

        if bytes_read > 8:
            raise VLQDecodeError("MIDI VLQ sequence exceeds maximum byte envelope.")

        result = (result << 7) | (byte_val & 0x7F)

        if (byte_val & 0x80) == 0:
            break

    return result, bytes_read

def decode_ebml_vint(stream: BinaryIO) -> Tuple[int, int]:
    """
    Decodes an EBML (Matroska/WebM) Variable-Size Integer (VINT).
    Length is determined by the position of the first set bit (MSB-first).
    Returns: (decoded_value, bytes_consumed)
    """
    first_byte_raw = stream.read(1)
    if not first_byte_raw:
        raise VLQDecodeError("Unexpected EOF while parsing EBML VINT.")

    first_byte = first_byte_raw[0]
    if first_byte == 0:
        raise VLQDecodeError("Invalid EBML VINT: Leading byte cannot be zero.")

    # Determine width from leading zero count
    mask = 0x80
    length = 1
    while (first_byte & mask) == 0:
        mask >>= 1
        length += 1

    # Extract initial payload bits with the length marker cleared
    result = first_byte & (~mask)

    if length > 1:
        additional_bytes = stream.read(length - 1)
        if len(additional_bytes) != (length - 1):
            raise VLQDecodeError("Truncated EBML VINT payload stream.")
        
        for b in additional_bytes:
            result = (result << 8) | b

    return result, length

# =====================================================================
# Arbitrary Bitfield Extraction Engine
# =====================================================================

class BitReader:
    """
    Stream reader supporting arbitrary bit-width scalar extractions
    across byte boundaries, configurable for MSB-first or LSB-first ordering.
    """

    def __init__(
        self,
        data: bytes,
        bit_order: Literal["msb_first", "lsb_first"] = "msb_first"
    ):
        self._data = data
        self._bit_order = bit_order
        self._byte_offset = 0
        self._bit_offset = 0  # Index into current byte (0..7)

    @property
    def bits_remaining(self) -> int:
        total_bits = len(self._data) * 8
        consumed_bits = (self._byte_offset * 8) + self._bit_offset
        return max(0, total_bits - consumed_bits)

    def read_bit(self) -> int:
        """Reads a single bit from the stream."""
        if self._byte_offset >= len(self._data):
            raise BitStreamError("Attempted to read past the end of bitstream.")

        current_byte = self._data[self._byte_offset]

        if self._bit_order == "msb_first":
            # Bit 7 down to Bit 0
            bit = (current_byte >> (7 - self._bit_offset)) & 1
        else:
            # Bit 0 up to Bit 7
            bit = (current_byte >> self._bit_offset) & 1

        self._bit_offset += 1
        if self._bit_offset == 8:
            self._bit_offset = 0
            self._byte_offset += 1

        return bit

    def read_bits(self, count: int) -> int:
        """
        Reads 'count' bits and packs them into an integer.
        MSB-first extracts high-order bits first.
        LSB-first accumulates low-order bits first.
        """
        if count <= 0:
            return 0
        if count > self.bits_remaining:
            raise BitStreamError(
                f"Requested {count} bits, but only {self.bits_remaining} remain."
            )

        value = 0
        if self._bit_order == "msb_first":
            for _ in range(count):
                value = (value << 1) | self.read_bit()
        else:
            for i in range(count):
                value |= (self.read_bit() << i)

        return value

    def align_to_byte(self) -> None:
        """Discards unaligned bits, synchronizing to the next byte boundary."""
        if self._bit_offset != 0:
            self._bit_offset = 0
            self._byte_offset += 1

# =====================================================================
# Verification and Demonstration Harness
# =====================================================================

def run_demonstration() -> None:
    print("=" * 65)
    print("VARIABLE-LENGTH QUANTITIES & BITFIELD DECODING DEMONSTRATION")
    print("=" * 65)

    # 1. LEB128 Test Cases (Unsigned and Signed)
    raw_uleb = bytes([0xE5, 0x8E, 0x26])  # 624485
    stream_uleb = io.BytesIO(raw_uleb)
    val_uleb, len_uleb = decode_uleb128(stream_uleb)
    print(f"[*] ULEB128:  Hex '{raw_uleb.hex()}' -> Value: {val_uleb} (Bytes: {len_uleb})")

    raw_sleb = bytes([0xC0, 0xBB, 0x78])  # -123456
    stream_sleb = io.BytesIO(raw_sleb)
    val_sleb, len_sleb = decode_sleb128(stream_sleb)
    print(f"[*] SLEB128:  Hex '{raw_sleb.hex()}' -> Value: {val_sleb} (Bytes: {len_sleb})")

    # 2. ZigZag Decoding
    zigzag_cases = [(0, 0), (1, -1), (2, 1), (3, -2), (4, 2), (4294967295, -2147483648)]
    print("\n[*] ZigZag Transformations:")
    for enc, expected in zigzag_cases:
        actual = decode_zigzag(enc)
        print(f"    Encoded: {enc:10d} -> Decoded Signed: {actual:11d}")

    # 3. MIDI Big-Endian VLQ
    raw_midi = bytes([0xBD, 0x84, 0x40])  # (0x3D << 14) | (0x04 << 7) | 0x40 = 1000000
    stream_midi = io.BytesIO(raw_midi)
    val_midi, len_midi = decode_midi_vlq(stream_midi)
    print(f"\n[*] MIDI VLQ: Hex '{raw_midi.hex()}' -> Value: {val_midi} (Bytes: {len_midi})")

    # 4. EBML VINT (Matroska)
    raw_ebml = bytes([0x41, 0x23])  # Leading '01' indicates 2-byte width; payload 0x0123 -> 291
    stream_ebml = io.BytesIO(raw_ebml)
    val_ebml, len_ebml = decode_ebml_vint(stream_ebml)
    print(f"[*] EBML VINT: Hex '{raw_ebml.hex()}' -> Value: {val_ebml} (Bytes: {len_ebml})")

    # 5. Arbitrary Bitfield Parsing (Non-byte aligned)
    # Simulated 30-bit telemetry packed into 4 bytes:
    # [Sign: 1b][Degrees: 7b][Minutes: 6b][Centisec: 14b][Quality: 2b][Pad: 2b]
    # Sign=1, Degrees=45 (0x2D), Minutes=30 (0x1E), Centisec=5000 (0x1388), Quality=2
    # Bits (MSB-first): 1 | 0101101 | 011110 | 01001110001000 | 10 | 00
    # Grouped into bytes:
    # B0: 10101101 (0xAD)
    # B1: 01111001 (0x79)
    # B2: 00111000 (0x38)
    # B3: 10001000 (0x88)
    packed_payload = bytes([0xAD, 0x79, 0x38, 0x88])
    reader = BitReader(packed_payload, bit_order="msb_first")

    print("\n[*] Deconstructing Custom 30-bit Packed Frame (MSB-First):")
    print(f"    Raw Hex Envelope: {packed_payload.hex()}")
    lat_sign = reader.read_bits(1)
    degrees = reader.read_bits(7)
    minutes = reader.read_bits(6)
    centisec = reader.read_bits(14)
    quality = reader.read_bits(2)

    print(f"    - Latitude Sign Bit : {lat_sign} ({'-' if lat_sign else '+'})")
    print(f"    - Latitude Degrees  : {degrees}°")
    print(f"    - Latitude Minutes  : {minutes}'")
    print(f"    - Centisecond Frame : {centisec}")
    print(f"    - GPS Quality Flag  : {quality}")
    print(f"    - Unaligned Padding : {reader.bits_remaining} bits remaining")
    print("=" * 65)

if __name__ == "__main__":
    run_demonstration()
