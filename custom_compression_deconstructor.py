#!/usr/bin/env python3
"""
custom_compression_deconstructor.py

Production-ready analytical deconstructors and parsers for proprietary
Run-Length Encoding (RLE) and sliding-window dictionary (LZSS) payloads.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from enum import Enum, auto
from typing import BinaryIO, Optional, Tuple, Union

class BitOrder(Enum):
    """Bit-reading order for compression flag words."""
    LSB_FIRST = auto()
    MSB_FIRST = auto()

class RleMode(Enum):
    """Opcode conventions for custom RLE engines."""
    PACKBITS_SIGNED = auto()
    SENTINEL_ESCAPED = auto()

class CompressionError(Exception):
    """Base exception for decompression and deconstruction failures."""
    pass

class CorruptedStreamError(CompressionError):
    """Raised when parsing encounters invalid offsets or broken streams."""
    pass

class ProprietaryRleDecoder:
    """
    Deconstructs and decodes custom Run-Length Encoded streams.
    Supports signed counter conventions and sentinel byte modes.
    """

    @staticmethod
    def decode_packbits(
        data: bytes, 
        max_output_size: Optional[int] = None
    ) -> bytes:
        """
        Decompresses signed-byte (PackBits style) RLE streams.
        - Counter N in [0..127]: Literal run of (N + 1) bytes.
        - Counter N in [129..255]: Repeat run of (256 - N + 1) bytes.
        - Counter 128 (0x80): No-op or stream terminator.
        """
        src = io.BytesIO(data)
        out = bytearray()

        while True:
            flag_byte = src.read(1)
            if not flag_byte:
                break  # Clean End-Of-Stream

            n = struct.unpack("b", flag_byte)[0]

            if n == -128:
                # 0x80 is commonly ignored or used as an explicit stop marker
                continue

            if n >= 0:
                # Literal run: copy n + 1 bytes directly
                count = n + 1
                literal_block = src.read(count)
                if len(literal_block) < count:
                    raise CorruptedStreamError(
                        f"Premature stream truncation during literal run. "
                        f"Expected {count} bytes, got {len(literal_block)}."
                    )
                out.extend(literal_block)
            else:
                # Repeat run: replicate next byte (|n| + 1) times
                count = (-n) + 1
                val_byte = src.read(1)
                if not val_byte:
                    raise CorruptedStreamError(
                        "Premature truncation while reading repeat value byte."
                    )
                out.extend(val_byte * count)

            if max_output_size and len(out) >= max_output_size:
                return bytes(out[:max_output_size])

        return bytes(out)

    @staticmethod
    def decode_sentinel(
        data: bytes, 
        sentinel: int = 0xE7, 
        max_output_size: Optional[int] = None
    ) -> bytes:
        """
        Decompresses sentinel-based RLE.
        Format: [Literal...] [Sentinel] [Count] [Value]
        Special case: [Sentinel] [0x00] emits a literal instance of Sentinel.
        """
        src = io.BytesIO(data)
        out = bytearray()

        while True:
            byte = src.read(1)
            if not byte:
                break

            val = byte[0]
            if val == sentinel:
                count_byte = src.read(1)
                if not count_byte:
                    raise CorruptedStreamError(
                        "Truncated stream reading sentinel run count."
                    )
                count = count_byte[0]

                if count == 0:
                    # Escaped sentinel literal
                    out.append(sentinel)
                else:
                    target_byte = src.read(1)
                    if not target_byte:
                        raise CorruptedStreamError(
                            "Truncated stream reading sentinel target value."
                        )
                    out.extend(target_byte * count)
            else:
                out.append(val)

            if max_output_size and len(out) >= max_output_size:
                return bytes(out[:max_output_size])

        return bytes(out)

@dataclass(frozen=True)
class LzssConfiguration:
    """Configuration mapping the geometry of a custom LZSS engine."""
    window_bits: int = 12          # 4096-byte sliding window
    length_bits: int = 4           # 16-length variations
    min_match_length: int = 3      # Standard bias: lengths encode 3..18
    bit_order: BitOrder = BitOrder.LSB_FIRST
    literal_marker_bit: int = 1    # 1 = Literal, 0 = Match reference
    ring_buffer_init: int = 0x20   # Standard historical default (space character)
    is_relative_offset: bool = False  # True: Head - Offset; False: Absolute ring

class ProprietaryLzssDecoder:
    """
    Highly configurable sliding-window decompressor designed to execute
    and validate reverse engineered proprietary LZSS variations.
    """

    def __init__(self, config: LzssConfiguration) -> None:
        self.config = config
        self.window_size = 1 << config.window_bits
        self.max_match_length = (1 << config.length_bits) - 1 + config.min_match_length

        if config.window_bits + config.length_bits != 16:
            raise ValueError("Token must cleanly pack into a 16-bit word.")

    def decode(
        self, 
        compressed_data: bytes, 
        expected_size: Optional[int] = None
    ) -> bytes:
        """
        Decompresses payload according to the defined structural profile.
        """
        src = io.BytesIO(compressed_data)
        out = bytearray()
        
        # Initialize cyclical ring buffer
        ring_buffer = bytearray([self.config.ring_buffer_init] * self.window_size)
        ring_head = self.window_size - self.max_match_length

        flag_register = 0
        bits_remaining = 0

        while True:
            # Check termination bounds
            if expected_size and len(out) >= expected_size:
                break

            # Read next flag word if bit register is depleted
            if bits_remaining == 0:
                flag_byte = src.read(1)
                if not flag_byte:
                    break  # Normal termination
                flag_register = flag_byte[0]
                bits_remaining = 8

            # Extract active operational bit
            if self.config.bit_order == BitOrder.LSB_FIRST:
                current_flag = flag_register & 1
                flag_register >>= 1
            else:
                current_flag = (flag_register >> 7) & 1
                flag_register = (flag_register << 1) & 0xFF
            
            bits_remaining -= 1

            if current_flag == self.config.literal_marker_bit:
                # -----------------------------------------------------------
                # Branch A: Uncompressed Literal Operation
                # -----------------------------------------------------------
                literal_byte = src.read(1)
                if not literal_byte:
                    break  # Stream terminated on boundary
                val = literal_byte[0]
                out.append(val)

                # Commit to sliding ring buffer
                ring_buffer[ring_head] = val
                ring_head = (ring_head + 1) % self.window_size

            else:
                # -----------------------------------------------------------
                # Branch B: Dictionary Match Reference Operation
                # -----------------------------------------------------------
                token_bytes = src.read(2)
                if len(token_bytes) < 2:
                    break  # Truncated control reference

                # Read 16-bit token (little-endian byte order standard)
                raw_token = struct.unpack("<H", token_bytes)[0]

                # Deconstruct bitfields
                # Layout: [Offset: WindowBits] [Length: LengthBits]
                offset_mask = self.window_size - 1
                length_mask = (1 << self.config.length_bits) - 1

                offset = raw_token & offset_mask
                raw_length = (raw_token >> self.config.window_bits) & length_mask
                match_length = raw_length + self.config.min_match_length

                # Execute dynamic back-reference copying
                for i in range(match_length):
                    if self.config.is_relative_offset:
                        # Relative backwards indexing from output buffer
                        source_pos = len(out) - offset
                        if source_pos < 0 or source_pos >= len(out):
                            raise CorruptedStreamError(
                                f"Invalid relative offset {offset} "
                                f"at output index {len(out)}."
                            )
                        byte_to_copy = out[source_pos]
                    else:
                        # Absolute ring buffer indexing
                        source_idx = (offset + i) % self.window_size
                        byte_to_copy = ring_buffer[source_idx]

                    # Append to output and push forward in history buffer
                    out.append(byte_to_copy)
                    ring_buffer[ring_head] = byte_to_copy
                    ring_head = (ring_head + 1) % self.window_size

                    if expected_size and len(out) >= expected_size:
                        return bytes(out[:expected_size])

        return bytes(out)

def synthesize_lzss_stream(plaintext: bytes) -> bytes:
    """
    Helper generator: Compresses small plaintexts using an unoptimized
    canonical LZSS pipeline to produce known-good test streams.
    """
    out = bytearray()
    src = memoryview(plaintext)
    pos = 0
    window_size = 4096
    max_match = 18
    min_match = 3

    ring_buffer = bytearray([0x20] * window_size)
    ring_head = window_size - max_match

    while pos < len(src):
        # Accumulate an 8-operation chunk
        chunk_ops = []
        
        while len(chunk_ops) < 8 and pos < len(src):
            # Scan for longest dictionary match within existing ring buffer
            best_offset = 0
            best_len = 0
            
            max_search = min(max_match, len(src) - pos)
            candidate_match = src[pos:pos + max_search]
            
            # Simple substring search in history
            for match_len in range(max_search, min_match - 1, -1):
                sub = candidate_match[:match_len]
                idx = ring_buffer.find(sub)
                if idx != -1:
                    best_offset = idx
                    best_len = match_len
                    break

            if best_len >= min_match:
                chunk_ops.append(("match", best_offset, best_len))
                for i in range(best_len):
                    ring_buffer[ring_head] = src[pos + i]
                    ring_head = (ring_head + 1) % window_size
                pos += best_len
            else:
                chunk_ops.append(("literal", src[pos]))
                ring_buffer[ring_head] = src[pos]
                ring_head = (ring_head + 1) % window_size
                pos += 1

        # Write Flag Byte followed by queued operations
        flag = 0
        payload = bytearray()
        for idx, op in enumerate(chunk_ops):
            if op[0] == "literal":
                flag |= (1 << idx)  # Bit = 1 denotes literal
                payload.append(op[1])
            else:
                # Bit = 0 denotes match
                offset = op[1]
                length_code = op[2] - min_match
                token = (offset & 0x0FFF) | ((length_code & 0x0F) << 12)
                payload.extend(struct.pack("<H", token))

        out.append(flag)
        out.extend(payload)

    return bytes(out)

def demonstrate_custom_decoding() -> None:
    """Runs functional round-trip decoding validations."""
    print("=" * 64)
    print("DEMONSTRATION: Proprietary RLE & LZSS Deconstructors")
    print("=" * 64)

    # 1. Evaluate PackBits Signed-Counter Variant
    # Stream: [Literal 3 bytes: 'ABC'] + [Repeat 'Z' 5 times (0xFC = -4)]
    raw_packbits = b"\x02ABC\xFCZ\x00!"
    decoded_rle = ProprietaryRleDecoder.decode_packbits(raw_packbits)
    print(f"\n[+] Executing PackBits Decoding:")
    print(f"    Raw Stream      : {raw_packbits.hex()}")
    print(f"    Decoded Plaintext: {decoded_rle.decode('ascii')}")

    # 2. Evaluate Sentinel RLE Variant
    # Stream: 'DATA' + [Sentinel 0xE7, Count 4, 'X'] + 'END'
    raw_sentinel = b"DATA\xE7\x04XEND"
    decoded_sentinel = ProprietaryRleDecoder.decode_sentinel(
        raw_sentinel, sentinel=0xE7
    )
    print(f"\n[+] Executing Sentinel RLE Decoding:")
    print(f"    Raw Stream      : {raw_sentinel.hex()}")
    print(f"    Decoded Plaintext: {decoded_sentinel.decode('ascii')}")

    # 3. Evaluate Configured Proprietary LZSS
    base_text = b"REVERSE_ENGINEERING_STRUCTURED_STREAM_REVERSE_ENGINEERING"
    synthetic_lzss = synthesize_lzss_stream(base_text)

    lzss_cfg = LzssConfiguration(
        window_bits=12,
        length_bits=4,
        min_match_length=3,
        bit_order=BitOrder.LSB_FIRST,
        literal_marker_bit=1,
        ring_buffer_init=0x20,
        is_relative_offset=False,
    )

    decoder = ProprietaryLzssDecoder(lzss_cfg)
    decompressed_lzss = decoder.decode(synthetic_lzss, expected_size=len(base_text))

    print(f"\n[+] Executing Proprietary LZSS Decoding:")
    print(f"    Compressed Size : {len(synthetic_lzss)} bytes")
    print(f"    Decompressed Size: {len(decompressed_lzss)} bytes")
    print(f"    Match Success   : {decompressed_lzss == base_text}")
    print(f"    Extracted Output: {decompressed_lzss.decode('ascii')}")
    print("=" * 64)

if __name__ == "__main__":
    demonstrate_custom_decoding()
