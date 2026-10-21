#!/usr/bin/env python3
"""
compression_signature_scanner.py

Production-grade analyzer for detecting, validating, and probing standard
compression algorithm signatures and stream envelopes within binary data.
"""

from __future__ import annotations

import bz2
import io
import lzma
import struct
import zlib
from dataclasses import dataclass
from enum import Enum, auto
from typing import BinaryIO, Dict, List, Optional, Tuple

class CompressionType(Enum):
    """Supported compression algorithm signatures."""
    UNKNOWN = auto()
    ZLIB = auto()
    GZIP = auto()
    RAW_DEFLATE = auto()
    BZIP2 = auto()
    XZ = auto()
    LZMA_ALONE = auto()
    ZSTANDARD = auto()
    LZ4_FRAME = auto()
    SNAPPY_FRAMED = auto()
    LZO_FRAMED = auto()

@dataclass(frozen=True)
class DetectionResult:
    """Encapsulates the identification metrics for a compressed stream."""
    compression_type: CompressionType
    confidence: float
    offset: int
    header_length: int
    description: str
    properties: Dict[str, object]

class CompressionSignatureScanner:
    """
    Scans binary buffers to detect and verify standard compression headers
    and validates raw bitstreams via mathematical checks and safe probes.
    """

    # Magic byte constants
    GZIP_MAGIC = b"\x1f\x8b\x08"
    XZ_MAGIC = b"\xfd7zXZ\x00"
    BZIP2_MAGIC = b"BZh"
    ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
    LZ4_MAGIC = b"\x04\x22\x4d\x18"
    LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
    SNAPPY_MAGIC = b"\xff\x06\x00\x00sNaPpY"
    LZO_MAGIC = b"\x89LZO\x00\x0d\x0a\x1a\x0a"

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Target payload must be bytes or bytearray.")
        self.data = bytes(data)
        self.size = len(self.data)

    def scan_at_offset(self, offset: int = 0) -> Optional[DetectionResult]:
        """
        Evaluates binary data at a specified offset to identify standard
        compression formats, ordered from high-specificity signatures
        to probabilistic raw stream checks.
        """
        if offset < 0 or offset >= self.size:
            return None

        slice_view = self.data[offset:]
        slice_len = len(slice_view)

        # 1. Fully-Framed Container Signatures (Deterministic)
        if slice_len >= 10 and slice_view.startswith(self.SNAPPY_MAGIC):
            return DetectionResult(
                compression_type=CompressionType.SNAPPY_FRAMED,
                confidence=1.0,
                offset=offset,
                header_length=10,
                description="Snappy framed stream identifier verified.",
                properties={"framing": "snappy_chunked"},
            )

        if slice_len >= 9 and slice_view.startswith(self.LZO_MAGIC):
            return DetectionResult(
                compression_type=CompressionType.LZO_FRAMED,
                confidence=1.0,
                offset=offset,
                header_length=9,
                description="LZOP standard container header verified.",
                properties={"framing": "lzop"},
            )

        if slice_len >= 6 and slice_view.startswith(self.XZ_MAGIC):
            return DetectionResult(
                compression_type=CompressionType.XZ,
                confidence=1.0,
                offset=offset,
                header_length=6,
                description="XZ multi-stream container verified.",
                properties={"container": "xz"},
            )

        if slice_len >= 4 and slice_view.startswith(self.ZSTD_MAGIC):
            return DetectionResult(
                compression_type=CompressionType.ZSTANDARD,
                confidence=1.0,
                offset=offset,
                header_length=4,
                description="Zstandard standard frame magic verified.",
                properties={"magic": "0xFD2FB528"},
            )

        if slice_len >= 4 and (
            slice_view.startswith(self.LZ4_MAGIC) or
            slice_view.startswith(self.LZ4_LEGACY_MAGIC)
        ):
            is_legacy = slice_view.startswith(self.LZ4_LEGACY_MAGIC)
            return DetectionResult(
                compression_type=CompressionType.LZ4_FRAME,
                confidence=1.0,
                offset=offset,
                header_length=4,
                description=f"LZ4 {'Legacy' if is_legacy else 'Standard'} frame magic verified.",
                properties={"legacy": is_legacy},
            )

        # 2. Gzip Inspection
        if slice_len >= 10 and slice_view.startswith(self.GZIP_MAGIC):
            flg = slice_view[3]
            mtime = struct.unpack("<I", slice_view[4:8])[0]
            return DetectionResult(
                compression_type=CompressionType.GZIP,
                confidence=1.0,
                offset=offset,
                header_length=10,
                description="Gzip RFC 1952 stream header verified.",
                properties={"flags": flg, "mtime": mtime},
            )

        # 3. Bzip2 Inspection
        if slice_len >= 10 and slice_view.startswith(self.BZIP2_MAGIC):
            block_char = chr(slice_view[3])
            if block_char in "123456789":
                pi_marker = slice_view[4:10]
                has_pi = pi_marker == b"\x31\x41\x59\x26\x53\x59"
                confidence = 1.0 if has_pi else 0.85
                return DetectionResult(
                    compression_type=CompressionType.BZIP2,
                    confidence=confidence,
                    offset=offset,
                    header_length=4 if not has_pi else 10,
                    description=f"Bzip2 block stream (block size: {block_char}00k).",
                    properties={
                        "block_level": int(block_char),
                        "pi_marker_verified": has_pi,
                    },
                )

        # 4. Zlib Stream Envelope (CMF/FLG Modulo-31 Invariant)
        if slice_len >= 2:
            cmf = slice_view[0]
            flg = slice_view[1]
            header_val = (cmf * 256) + flg
            
            # Mathematical invariant test
            if (header_val % 31 == 0) and ((cmf & 0x0F) == 8):
                window_size = 1 << ((cmf >> 4) + 8)
                fdict = bool(flg & 0x20)
                flevel = (flg >> 6) & 0x03
                
                # Verify sanity with small decompress probe
                probe_success = False
                try:
                    decompressor = zlib.decompressobj()
                    decompressor.decompress(slice_view[:256])
                    probe_success = True
                except zlib.error:
                    pass

                confidence = 0.99 if probe_success else 0.75
                return DetectionResult(
                    compression_type=CompressionType.ZLIB,
                    confidence=confidence,
                    offset=offset,
                    header_length=2 if not fdict else 6,
                    description="Zlib RFC 1950 header verified via modulo-31 check.",
                    properties={
                        "window_size": window_size,
                        "flevel": flevel,
                        "fdict": fdict,
                        "probe_succeeded": probe_success,
                    },
                )

        # 5. Classic LZMA Envelope (Props Byte Calculation)
        if slice_len >= 13:
            props = slice_view[0]
            if props < (9 * 5 * 5):  # Must satisfy (pb*5 + lp)*9 + lc
                lc = props % 9
                remainder = props // 9
                lp = remainder % 5
                pb = remainder // 5
                
                dict_size = struct.unpack("<I", slice_view[1:5])[0]
                uncomp_size = struct.unpack("<Q", slice_view[5:13])[0]
                
                # Dictionary size sanity: Must be a non-zero reasonable value
                if 0 < dict_size <= (1 << 30):
                    confidence = 0.90 if props == 0x5D else 0.60
                    return DetectionResult(
                        compression_type=CompressionType.LZMA_ALONE,
                        confidence=confidence,
                        offset=offset,
                        header_length=13,
                        description="Classic 13-byte LZMA stream header verified.",
                        properties={
                            "lc": lc,
                            "lp": lp,
                            "pb": pb,
                            "dict_size": dict_size,
                            "uncompressed_size": (
                                uncomp_size if uncomp_size != 0xFFFFFFFFFFFFFFFF else None
                            ),
                        },
                    )

        # 6. Raw DEFLATE Bitstream Probe (Negative Window Bits)
        if slice_len >= 8:
            # Check for probable dynamic Huffman block marker: bit pattern 100b
            if (slice_view[0] & 0x07) == 0x04:
                try:
                    # -15 specifies raw DEFLATE without Zlib/Gzip wrappers
                    decompressor = zlib.decompressobj(-15)
                    decompressed_chunk = decompressor.decompress(slice_view[:512])
                    if len(decompressed_chunk) > 0:
                        return DetectionResult(
                            compression_type=CompressionType.RAW_DEFLATE,
                            confidence=0.80,
                            offset=offset,
                            header_length=0,
                            description="Probable Raw DEFLATE bitstream (validated via probe).",
                            properties={
                                "first_byte_bits": f"0b{slice_view[0]:08b}",
                                "decompressed_sample_bytes": len(decompressed_chunk),
                            },
                        )
                except zlib.error:
                    pass

        return None

    def scan_all(self, stride: int = 1) -> List[DetectionResult]:
        """
        Sweeps the buffer linearly to locate embedded signatures across
        arbitrary byte boundaries.
        """
        results: List[DetectionResult] = []
        pos = 0

        while pos < self.size:
            match = self.scan_at_offset(pos)
            if match and match.confidence >= 0.70:
                results.append(match)
                # Skip forward past identified header to minimize redundant hits
                pos += max(match.header_length, 1)
            else:
                pos += stride

        return results

def demonstrate_signature_detection() -> None:
    """Executes a diagnostic run identifying varied compression envelopes."""
    print("=" * 66)
    print("COMPRESSION SIGNATURE & STREAM IDENTIFICATION ANALYSIS")
    print("=" * 66)

    # Synthesize test payload
    sample_text = (
        b"Binary parsing and reverse engineering require understanding "
        b"the balance between spatial overhead and decompression speed. "
    ) * 40

    # 1. Synthesize Gzip stream
    gzip_buffer = io.BytesIO()
    import gzip
    with gzip.GzipFile(fileobj=gzip_buffer, mode="wb") as f:
        f.write(sample_text)
    gzip_bytes = gzip_buffer.getvalue()

    # 2. Synthesize Zlib stream
    zlib_bytes = zlib.compress(sample_text, level=9)

    # 3. Synthesize Raw DEFLATE stream (no header/trailer)
    raw_deflate_obj = zlib.compressobj(level=6, method=zlib.DEFLATED, wbits=-15)
    raw_deflate_bytes = raw_deflate_obj.compress(sample_text) + raw_deflate_obj.flush()

    # 4. Synthesize Bzip2 stream
    bz2_bytes = bz2.compress(sample_text, compresslevel=9)

    # 5. Synthesize Classic LZMA stream
    lzma_bytes = lzma.compress(sample_text, format=lzma.FORMAT_ALONE)

    test_vectors = [
        ("Gzip Frame", gzip_bytes),
        ("Zlib Enveloped Stream", zlib_bytes),
        ("Raw DEFLATE Bitstream", raw_deflate_bytes),
        ("Bzip2 Block Stream", bz2_bytes),
        ("Classic LZMA Stream", lzma_bytes),
    ]

    for label, payload in test_vectors:
        print(f"\nEvaluating Vector: {label} (Size: {len(payload)} bytes)")
        scanner = CompressionSignatureScanner(payload)
        result = scanner.scan_at_offset(0)

        if result:
            print(f"  [+] Identified Algorithm : {result.compression_type.name}")
            print(f"  [+] Confidence Score     : {result.confidence * 100:.1f}%")
            print(f"  [+] Header Boundary      : {result.header_length} bytes")
            print(f"  [+] Details              : {result.description}")
            for k, v in result.properties.items():
                print(f"      - {k:<20}: {v}")
        else:
            print("  [-] No standard signature verified.")

    print("\n" + "=" * 66)

if __name__ == "__main__":
    demonstrate_signature_detection()
