#!/usr/bin/env python3
"""
string_analyzer.py

Industrial-grade extraction and encoding classification engine for
reconstructing string storage patterns in unknown binary file formats.
"""

import argparse
import enum
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Generator, List, Optional, Tuple

class StoragePattern(enum.Enum):
    NULL_TERMINATED = "Null-Terminated"
    PASCAL_U8 = "Pascal (u8 length)"
    PASCAL_U16 = "Pascal (u16 length)"
    PASCAL_U32 = "Pascal (u32 length)"
    FIXED_WIDTH = "Fixed-Width Padded"

@dataclass(frozen=True)
class ExtractedString:
    offset: int
    pattern: StoragePattern
    encoding: str
    raw_length: int
    value: str
    printable_ratio: float

class EncodingClassifier:
    """Classifies encoding based on structural byte properties."""

    @staticmethod
    def is_alternating_zero_utf16(data: bytes) -> Optional[str]:
        if len(data) < 4 or len(data) % 2 != 0:
            return None

        # Check for UTF-16LE: nulls at odd indices
        odd_nulls = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
        even_chars = sum(
            1 for i in range(0, len(data), 2)
            if 0x20 <= data[i] <= 0x7E or data[i] in (0x09, 0x0A, 0x0D)
        )
        total_units = len(data) // 2

        if (odd_nulls / total_units) > 0.70 and (even_chars / total_units) > 0.70:
            return "utf-16-le"

        # Check for UTF-16BE: nulls at even indices
        even_nulls = sum(1 for i in range(0, len(data), 2) if data[i] == 0)
        odd_chars = sum(
            1 for i in range(1, len(data), 2)
            if 0x20 <= data[i] <= 0x7E or data[i] in (0x09, 0x0A, 0x0D)
        )

        if (even_nulls / total_units) > 0.70 and (odd_chars / total_units) > 0.70:
            return "utf-16-be"

        return None

    @staticmethod
    def test_utf8(data: bytes) -> bool:
        try:
            data.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    @staticmethod
    def test_ebcdic(data: bytes) -> float:
        # Check IBM Code Page 500 (EBCDIC) plausibility
        space_count = data.count(0x40)
        valid_ebcdic_alpha = sum(
            1 for b in data
            if (0x81 <= b <= 0x89) or (0x91 <= b <= 0x99) or
               (0xA2 <= b <= 0xA9) or (0xC1 <= b <= 0xC9) or
               (0xD1 <= b <= 0xD9) or (0xE2 <= b <= 0xE9) or
               (0xF0 <= b <= 0xF9) or b == 0x40
        )
        if len(data) == 0:
            return 0.0
        return valid_ebcdic_alpha / len(data)

    @classmethod
    def identify_encoding(cls, data: bytes) -> Tuple[str, str]:
        """
        Infers optimal character encoding.
        Returns: (encoding_name, decoded_string)
        """
        # 1. Evaluate UTF-16
        utf16_type = cls.is_alternating_zero_utf16(data)
        if utf16_type:
            try:
                decoded = data.decode(utf16_type)
                return utf16_type, decoded
            except UnicodeDecodeError:
                pass

        # 2. Evaluate UTF-8
        if cls.test_utf8(data):
            if all(b < 0x80 for b in data):
                return "ascii", data.decode("ascii")
            return "utf-8", data.decode("utf-8")

        # 3. Evaluate EBCDIC (CP500)
        ebcdic_score = cls.test_ebcdic(data)
        if ebcdic_score > 0.85:
            try:
                decoded = data.decode("cp500")
                return "cp500", decoded
            except UnicodeDecodeError:
                pass

        # 4. Fallback to Windows-1252 or CP437
        try:
            return "windows-1252", data.decode("windows-1252")
        except UnicodeDecodeError:
            return "cp437", data.decode("cp437", errors="replace")

class StringExtractionEngine:
    """Extracts strings across multiple boundary patterns."""

    def __init__(self, min_len: int = 4, max_len: int = 1024):
        self.min_len = min_len
        self.max_len = max_len

    @staticmethod
    def _calculate_printability(s: str) -> float:
        if not s:
            return 0.0
        printable_chars = sum(
            1 for c in s if c.isprintable() or c in "\t\r\n"
        )
        return printable_chars / len(s)

    def scan_null_terminated(
        self, stream: BinaryIO, start_offset: int, size: int
    ) -> Generator[ExtractedString, None, None]:
        """Scans for 1-byte and 2-byte null-terminated strings."""
        stream.seek(start_offset)
        buffer = stream.read(size)
        buf_len = len(buffer)
        i = 0

        while i < buf_len:
            # Check 1-byte null-terminated
            null_pos = buffer.find(b"\x00", i)
            if null_pos == -1:
                null_pos = buf_len

            raw_slice = buffer[i:null_pos]
            slice_len = len(raw_slice)

            if self.min_len <= slice_len <= self.max_len:
                enc, decoded = EncodingClassifier.identify_encoding(raw_slice)
                ratio = self._calculate_printability(decoded)
                if ratio >= 0.80:
                    yield ExtractedString(
                        offset=start_offset + i,
                        pattern=StoragePattern.NULL_TERMINATED,
                        encoding=enc,
                        raw_length=slice_len + 1,
                        value=decoded,
                        printable_ratio=ratio,
                    )

            # Advance past the null byte
            i = null_pos + 1

    def scan_length_prefixed(
        self,
        stream: BinaryIO,
        start_offset: int,
        size: int,
        prefix_type: str = "u8",
        endianness: str = "<"
    ) -> Generator[ExtractedString, None, None]:
        """Scans for length-prefixed strings using explicit integer counters."""
        prefix_formats = {
            "u8": (1, "B", StoragePattern.PASCAL_U8),
            "u16": (2, f"{endianness}H", StoragePattern.PASCAL_U16),
            "u32": (4, f"{endianness}I", StoragePattern.PASCAL_U32),
        }

        prefix_len, fmt_str, pattern_type = prefix_formats[prefix_type]
        stream.seek(start_offset)
        buffer = stream.read(size)
        buf_len = len(buffer)
        i = 0

        while i <= buf_len - prefix_len:
            length = struct.unpack_from(fmt_str, buffer, i)[0]

            if self.min_len <= length <= self.max_len:
                data_start = i + prefix_len
                data_end = data_start + length

                if data_end <= buf_len:
                    payload = buffer[data_start:data_end]
                    enc, decoded = EncodingClassifier.identify_encoding(payload)
                    ratio = self._calculate_printability(decoded)

                    if ratio >= 0.85:
                        yield ExtractedString(
                            offset=start_offset + i,
                            pattern=pattern_type,
                            encoding=enc,
                            raw_length=prefix_len + length,
                            value=decoded,
                            printable_ratio=ratio,
                        )
                        # Advance cleanly past this record
                        i = data_end
                        continue

            i += 1

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive string extraction and encoding engine."
    )
    parser.add_argument("file", type=Path, help="Target binary file.")
    parser.add_argument(
        "--offset", "-o", type=lambda x: int(x, 0), default=0,
        help="Scan start offset (default: 0)."
    )
    parser.add_argument(
        "--length", "-l", type=lambda x: int(x, 0), default=None,
        help="Maximum byte envelope to analyze."
    )
    parser.add_argument(
        "--min-len", "-m", type=int, default=4,
        help="Minimum extracted character length (default: 4)."
    )
    parser.add_argument(
        "--pattern", "-p",
        choices=["all", "null", "pascal8", "pascal16", "pascal32"],
        default="all",
        help="String storage boundary paradigm to evaluate."
    )

    args = parser.parse_args()

    if not args.file.is_file():
        print(f"[-] Error: Target file '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)

    file_size = args.file.stat().st_size
    read_size = args.length if args.length else (file_size - args.offset)

    if args.offset + read_size > file_size:
        read_size = file_size - args.offset

    engine = StringExtractionEngine(min_len=args.min_len)
    extracted: List[ExtractedString] = []

    with open(args.file, "rb") as f:
        if args.pattern in ("all", "null"):
            extracted.extend(
                engine.scan_null_terminated(f, args.offset, read_size)
            )
        if args.pattern in ("all", "pascal8"):
            extracted.extend(
                engine.scan_length_prefixed(f, args.offset, read_size, "u8")
            )
        if args.pattern in ("all", "pascal16"):
            extracted.extend(
                engine.scan_length_prefixed(f, args.offset, read_size, "u16")
            )
        if args.pattern in ("all", "pascal32"):
            extracted.extend(
                engine.scan_length_prefixed(f, args.offset, read_size, "u32")
            )

    extracted.sort(key=lambda s: s.offset)

    # Output formatting
    print(f"[*] Scanned {read_size} bytes starting at offset 0x{args.offset:X}")
    print(f"[*] Extracted {len(extracted)} valid structural strings:")
    print("-" * 78)
    line_format = "{:<10} {:<20} {:<12} {:<6} {}"
    print(line_format.format("Offset", "Storage Type", "Encoding", "Score", "String Content"))
    print("-" * 78)

    for item in extracted:
        sanitized = item.value.replace("\r", "").replace("\n", " ").strip()
        if len(sanitized) > 36:
            sanitized = sanitized[:33] + "..."
        print(
            line_format.format(
                f"0x{item.offset:08X}",
                item.pattern.value[:19],
                item.encoding,
                f"{item.printable_ratio:.2f}",
                sanitized,
            )
        )
    print("-" * 78)

if __name__ == "__main__":
    main()
