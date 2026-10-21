#!/usr/bin/env python3
"""
signature_classifier.py

Industrial-strength binary signature classification and corpus-invariant
discovery engine for reverse engineering undocumented file formats.
"""

import argparse
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Dict, Generator, List, Optional, Tuple

@dataclass(frozen=True)
class SignatureDefinition:
    name: str
    category: str
    pattern: bytes
    mask: Optional[bytes] = None
    fixed_offset: Optional[int] = None
    endianness: str = "none"

@dataclass(frozen=True)
class SignatureMatch:
    offset: int
    name: str
    category: str
    matched_bytes: bytes
    confidence: float

class KnownSignatureDatabase:
    """Maintains definitions of common container, compression, and media magic."""

    @staticmethod
    def get_standard_signatures() -> List[SignatureDefinition]:
        return [
            SignatureDefinition(
                name="PNG Image Container",
                category="Graphics",
                pattern=b"\x89PNG\r\n\x1a\n",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="JPEG Image Stream",
                category="Graphics",
                pattern=b"\xFF\xD8\xFF",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="GIF Image 89a",
                category="Graphics",
                pattern=b"GIF89a",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="TIFF Little-Endian (Intel)",
                category="Graphics",
                pattern=b"II\x2A\x00",
                fixed_offset=0,
                endianness="little",
            ),
            SignatureDefinition(
                name="TIFF Big-Endian (Motorola)",
                category="Graphics",
                pattern=b"MM\x00\x2A",
                fixed_offset=0,
                endianness="big",
            ),
            SignatureDefinition(
                name="Zip Archive / Office Container",
                category="Archive",
                pattern=b"PK\x03\x04",
            ),
            SignatureDefinition(
                name="Zip Central Directory (EOCD)",
                category="Archive",
                pattern=b"PK\x05\x06",
            ),
            SignatureDefinition(
                name="7-Zip Archive",
                category="Archive",
                pattern=b"\x37\x7A\xBC\xAF\x27\x1C",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="Gzip Container",
                category="Compression",
                pattern=b"\x1F\x8B\x08",
            ),
            SignatureDefinition(
                name="Zstandard Frame",
                category="Compression",
                pattern=b"\x28\xB5\x2F\xFD",
            ),
            SignatureDefinition(
                name="XZ Container",
                category="Compression",
                pattern=b"\xFD7zXZ\x00",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="Bzip2 Stream",
                category="Compression",
                pattern=b"BZh",
            ),
            SignatureDefinition(
                name="zlib Window Default (32KB)",
                category="Compression",
                pattern=b"\x78\x9C",
            ),
            SignatureDefinition(
                name="zlib Window Best (32KB)",
                category="Compression",
                pattern=b"\x78\xDA",
            ),
            SignatureDefinition(
                name="SQLite 3 Database Engine",
                category="Database",
                pattern=b"SQLite format 3\x00",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="RIFF Multimedia Envelope",
                category="Media Container",
                pattern=b"RIFF",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="Ogg Media Container",
                category="Media Container",
                pattern=b"OggS",
            ),
            SignatureDefinition(
                name="Executable and Linkable Format (ELF)",
                category="Executable",
                pattern=b"\x7FELF",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="DOS MZ Executable / PE Stub",
                category="Executable",
                pattern=b"MZ",
                fixed_offset=0,
            ),
            SignatureDefinition(
                name="WebP / RIFF Sub-Type",
                category="Graphics",
                pattern=b"WEBP",
                fixed_offset=8,
            ),
        ]

class CorpusInvariantHunter:
    """Analyzes a set of binary files to extract candidate invariant magic bytes."""

    def __init__(self, sample_paths: List[Path], max_search_depth: int = 64):
        self.sample_paths = [p for p in sample_paths if p.is_file()]
        self.max_search_depth = max_search_depth

        if len(self.sample_paths) < 2:
            raise ValueError(
                "Corpus analysis requires at least two distinct binary samples."
            )

    def discover_prefix_invariants(self) -> List[Tuple[int, bytes]]:
        """
        Extracts contiguous static byte sequences present across all
        corpus samples starting from offset 0 up to max_search_depth.
        """
        # Read the search window from each sample
        buffers: List[bytes] = []
        for path in self.sample_paths:
            with open(path, "rb") as f:
                buffers.append(f.read(self.max_search_depth))

        min_len = min(len(b) for b in buffers)
        limit = min(min_len, self.max_search_depth)

        invariants: List[Tuple[int, bytes]] = []
        current_seq = bytearray()
        seq_start = 0

        for i in range(limit):
            current_byte = buffers[0][i]
            # Check if this exact byte is preserved at index i in all samples
            if all(buf[i] == current_byte for buf in buffers):
                if not current_seq:
                    seq_start = i
                current_seq.append(current_byte)
            else:
                if len(current_seq) >= 2:
                    invariants.append((seq_start, bytes(current_seq)))
                current_seq.clear()

        # Capture trailing invariant if active
        if len(current_seq) >= 2:
            invariants.append((seq_start, bytes(current_seq)))

        return invariants

class BinarySignatureScanner:
    """Scans binary streams against a library of signature definitions."""

    def __init__(
        self,
        signatures: Optional[List[SignatureDefinition]] = None,
        chunk_size: int = 65536,
    ):
        self.signatures = (
            signatures
            if signatures is not None
            else KnownSignatureDatabase.get_standard_signatures()
        )
        self.chunk_size = chunk_size
        self.max_pattern_len = (
            max(len(s.pattern) for s in self.signatures)
            if self.signatures
            else 0
        )

    def scan_file(
        self, file_path: Path
    ) -> Generator[SignatureMatch, None, None]:
        """Scans a file, checking fixed-offset and floating signatures."""
        file_size = file_path.stat().st_size
        if file_size == 0:
            return

        with open(file_path, "rb") as f:
            # 1. Evaluate fixed-offset signatures
            for sig in self.signatures:
                if sig.fixed_offset is not None:
                    if sig.fixed_offset + len(sig.pattern) <= file_size:
                        f.seek(sig.fixed_offset)
                        candidate = f.read(len(sig.pattern))
                        if candidate == sig.pattern:
                            yield SignatureMatch(
                                offset=sig.fixed_offset,
                                name=sig.name,
                                category=sig.category,
                                matched_bytes=candidate,
                                confidence=1.0,
                            )

            # 2. Evaluate floating signatures via sliding-window chunk reading
            floating_sigs = [
                s for s in self.signatures if s.fixed_offset is None
            ]
            if not floating_sigs:
                return

            offset = 0
            carryover = b""

            while offset < file_size:
                f.seek(offset)
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break

                buffer = carryover + chunk
                buf_len = len(buffer)
                base_offset = offset - len(carryover)

                for sig in floating_sigs:
                    pat = sig.pattern
                    pat_len = len(pat)
                    pos = 0

                    while True:
                        pos = buffer.find(pat, pos)
                        if pos == -1:
                            break

                        match_abs_offset = base_offset + pos

                        # Calculate confidence based on pattern size
                        confidence = 0.50 if pat_len < 3 else (
                            0.80 if pat_len == 3 else 0.95
                        )

                        yield SignatureMatch(
                            offset=match_abs_offset,
                            name=sig.name,
                            category=sig.category,
                            matched_bytes=pat,
                            confidence=confidence,
                        )
                        pos += 1

                # Keep overlap to ensure patterns crossing chunk boundaries are found
                carryover_len = self.max_pattern_len - 1
                if len(chunk) >= carryover_len:
                    carryover = chunk[-carryover_len:]
                else:
                    carryover = b""

                offset += len(chunk)

def format_hex_dump(data: bytes) -> str:
    """Formats bytes as spaced hex literals and printable ASCII equivalents."""
    hex_str = " ".join(f"{b:02X}" for b in data)
    ascii_str = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in data
    )
    return f"{hex_str} ['{ascii_str}']"

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Binary signature classification and corpus-invariant identification tool."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sub-command: scan
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a binary target for known standard file signatures."
    )
    scan_parser.add_argument("file", type=Path, help="Target binary file to scan.")

    # Sub-command: hunt
    hunt_parser = subparsers.add_parser(
        "hunt",
        help="Analyze a multi-file corpus to discover unknown invariant magic bytes.",
    )
    hunt_parser.add_argument(
        "corpus",
        type=Path,
        nargs="+",
        help="Two or more sample files from the same target architecture.",
    )
    hunt_parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=64,
        help="Maximum header byte depth to analyze (default: 64).",
    )

    args = parser.parse_args()

    if args.command == "scan":
        if not args.file.is_file():
            print(f"[-] Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        scanner = BinarySignatureScanner()
        matches = list(scanner.scan_file(args.file))

        # Sort matches by byte offset
        matches.sort(key=lambda m: m.offset)

        print("=" * 76)
        print(f"SIGNATURE CLASSIFICATION REPORT: {args.file.name}")
        print(f"File Size: {args.file.stat().st_size:,} bytes")
        print("=" * 76)

        if not matches:
            print("[*] No recognized signatures identified.")
            return

        fmt = "{:<10} {:<6} {:<24} {:<16} {}"
        print(fmt.format("Offset", "Conf", "Signature Name", "Category", "Hex"))
        print("-" * 76)

        for m in matches:
            hex_repr = " ".join(f"{b:02X}" for b in m.matched_bytes)
            print(
                fmt.format(
                    f"0x{m.offset:08X}",
                    f"{m.confidence:.2f}",
                    m.name[:23],
                    m.category[:15],
                    hex_repr,
                )
            )
        print("-" * 76)

    elif args.command == "hunt":
        try:
            hunter = CorpusInvariantHunter(
                args.corpus, max_search_depth=args.depth
            )
            invariants = hunter.discover_prefix_invariants()
        except ValueError as err:
            print(f"[-] Error: {err}", file=sys.stderr)
            sys.exit(1)

        print("=" * 76)
        print("CORPUS INVARIANT DISCOVERY REPORT")
        print(f"Analyzed Samples: {len(args.corpus)} files")
        print(f"Scan Depth      : {args.depth} bytes")
        print("=" * 76)

        if not invariants:
            print("[-] No consistent invariant byte sequences discovered.")
            print("[*] The corpus may contain compressed, encrypted, or highly variable headers.")
            return

        fmt = "{:<12} {:<8} {:<40}"
        print(fmt.format("Start Offset", "Length", "Candidate Invariant Bytes"))
        print("-" * 76)

        for offset, seq in invariants:
            dump = format_hex_dump(seq)
            if len(dump) > 50:
                dump = dump[:47] + "..."
            print(fmt.format(f"0x{offset:08X}", f"{len(seq)}B", dump))

        print("-" * 76)
        print("[*] Operational Guidance:")
        print("    1. Candidates at offset 0x00000000 are primary format identifiers.")
        print("    2. Candidates composed purely of 0x00 or 0xFF indicate data alignment.")
        print("    3. Multi-byte sequences preceding variable gaps often represent struct tags.")

if __name__ == "__main__":
    main()
