#!/usr/bin/env python3
"""
indirection_engine.py

Production-grade analyzer and extraction engine for resolving binary indirection,
including offset tables, string pools, pointer validation, and relocation fixups.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import BinaryIO, Dict, Generator, List, Optional, Set, Tuple

class PointerType(Enum):
    """Classification of pointer resolution arithmetic."""
    ABSOLUTE = auto()
    ANCHOR_RELATIVE = auto()
    SELF_RELATIVE = auto()

class StringEncoding(Enum):
    """String pool encoding styles."""
    NULL_TERMINATED_ASCII = auto()
    NULL_TERMINATED_UTF8 = auto()
    PASCAL_16 = auto()

@dataclass(frozen=True)
class ResolvedPointer:
    """Represents a validated, resolved pointer mapping."""
    index: int
    table_file_offset: int
    raw_value: int
    resolved_file_offset: int
    span_length: Optional[int]

class IndirectionError(Exception):
    """Base exception for indirection resolution errors."""
    pass

class PointerOutOfBoundsError(IndirectionError):
    """Raised when an offset points outside valid stream boundaries."""
    pass

class PointerCycleError(IndirectionError):
    """Raised when circular pointer references are detected."""
    pass

class IndirectionResolver:
    """
    Core engine for identifying, validating, and resolving offset tables
    and indirect data structures within binary streams.
    """

    def __init__(
        self,
        stream: BinaryIO,
        endianness: str = "<",
        pointer_width: int = 4
    ) -> None:
        self.stream = stream
        self.endianness = endianness
        self.pointer_width = pointer_width

        if self.endianness not in ("<", ">"):
            raise ValueError("Endianness must be '<' (little) or '>' (big).")
        if self.pointer_width not in (2, 4, 8):
            raise ValueError("Pointer width must be 2, 4, or 8 bytes.")

        self._type_char = {2: "H", 4: "I", 8: "Q"}[self.pointer_width]
        self._unpack_fmt = f"{self.endianness}{self._type_char}"

        # Cache file boundary
        self.stream.seek(0, io.SEEK_END)
        self.file_size = self.stream.tell()
        self.stream.seek(0, io.SEEK_SET)

    def read_raw_pointer(self, offset: int) -> int:
        """Reads and unpacks a single raw pointer scalar from the stream."""
        if offset + self.pointer_width > self.file_size:
            raise PointerOutOfBoundsError(
                f"Cannot read pointer at 0x{offset:08X}: beyond EOF"
            )
        self.stream.seek(offset, io.SEEK_SET)
        raw_bytes = self.stream.read(self.pointer_width)
        (value,) = struct.unpack(self._unpack_fmt, raw_bytes)
        return value

    def parse_offset_table(
        self,
        table_offset: int,
        entry_count: int,
        pointer_type: PointerType = PointerType.ABSOLUTE,
        anchor_offset: int = 0
    ) -> List[ResolvedPointer]:
        """
        Parses and validates an array of contiguous offsets.
        Calculates span lengths between entries where applicable.
        """
        table_byte_len = entry_count * self.pointer_width
        if table_offset + table_byte_len > self.file_size:
            raise PointerOutOfBoundsError(
                f"Offset table at 0x{table_offset:08X} (len {table_byte_len}) "
                f"exceeds file size 0x{self.file_size:08X}"
            )

        resolved_pointers: List[ResolvedPointer] = []

        for i in range(entry_count):
            curr_entry_offset = table_offset + (i * self.pointer_width)
            raw_ptr = self.read_raw_pointer(curr_entry_offset)

            # Arithmetic resolution
            if pointer_type == PointerType.ABSOLUTE:
                target_offset = raw_ptr
            elif pointer_type == PointerType.ANCHOR_RELATIVE:
                target_offset = anchor_offset + raw_ptr
            elif pointer_type == PointerType.SELF_RELATIVE:
                target_offset = curr_entry_offset + raw_ptr
            else:
                raise NotImplementedError("Unsupported pointer type.")

            # Validate target boundary
            if not (0 <= target_offset < self.file_size):
                raise PointerOutOfBoundsError(
                    f"Pointer index {i} (0x{raw_ptr:08X}) resolved to "
                    f"0x{target_offset:08X}, outside file limits [0, 0x{self.file_size:08X})"
                )

            resolved_pointers.append(
                ResolvedPointer(
                    index=i,
                    table_file_offset=curr_entry_offset,
                    raw_value=raw_ptr,
                    resolved_file_offset=target_offset,
                    span_length=None,
                )
            )

        # Compute payload spans based on delta to next entry if monotonic
        final_list: List[ResolvedPointer] = []
        for i in range(entry_count):
            curr = resolved_pointers[i]
            span: Optional[int] = None

            if i + 1 < entry_count:
                next_ptr = resolved_pointers[i + 1]
                if next_ptr.resolved_file_offset >= curr.resolved_file_offset:
                    span = (
                        next_ptr.resolved_file_offset
                        - curr.resolved_file_offset
                    )
            
            final_list.append(
                ResolvedPointer(
                    index=curr.index,
                    table_file_offset=curr.table_file_offset,
                    raw_value=curr.raw_value,
                    resolved_file_offset=curr.resolved_file_offset,
                    span_length=span,
                )
            )

        return final_list

    def extract_string_pool(
        self,
        pointers: List[ResolvedPointer],
        encoding: StringEncoding = StringEncoding.NULL_TERMINATED_UTF8
    ) -> Dict[int, str]:
        """
        Extracts and decodes strings referenced by an array of resolved pointers.
        """
        extracted_strings: Dict[int, str] = {}

        for ptr in pointers:
            self.stream.seek(ptr.resolved_file_offset, io.SEEK_SET)

            if encoding in (
                StringEncoding.NULL_TERMINATED_ASCII,
                StringEncoding.NULL_TERMINATED_UTF8
            ):
                string_bytes = bytearray()
                while True:
                    b = self.stream.read(1)
                    if not b or b == b"\x00":
                        break
                    string_bytes.extend(b)
                    # Defense against missing null terminator runaways
                    if len(string_bytes) > 4096:
                        raise IndirectionError(
                            f"Runaway string at 0x{ptr.resolved_file_offset:08X}: "
                            "exceeded 4096 bytes without null termination"
                        )

                codec = "ascii" if encoding == StringEncoding.NULL_TERMINATED_ASCII else "utf-8"
                extracted_strings[ptr.index] = string_bytes.decode(codec, errors="replace")

            elif encoding == StringEncoding.PASCAL_16:
                len_bytes = self.stream.read(2)
                if len(len_bytes) < 2:
                    raise PointerOutOfBoundsError(
                        f"Unexpected EOF reading Pascal length at 0x{ptr.resolved_file_offset:08X}"
                    )
                (str_len,) = struct.unpack(f"{self.endianness}H", len_bytes)
                if self.stream.tell() + str_len > self.file_size:
                    raise PointerOutOfBoundsError(
                        f"Pascal string exceeds EOF at 0x{self.stream.tell():08X}"
                    )
                payload = self.stream.read(str_len)
                extracted_strings[ptr.index] = payload.decode("utf-8", errors="replace")

        return extracted_strings

    def apply_relocations(
        self,
        base_delta: int,
        relocation_offsets: List[int]
    ) -> bytes:
        """
        Simulates loader fixup by applying a base address delta to pointers
        at specified relocation offsets, returning the patched binary buffer.
        """
        self.stream.seek(0, io.SEEK_SET)
        buffer = bytearray(self.stream.read())

        for rel_offset in relocation_offsets:
            if rel_offset + self.pointer_width > len(buffer):
                raise PointerOutOfBoundsError(
                    f"Relocation target 0x{rel_offset:08X} falls outside stream"
                )

            ptr_bytes = buffer[rel_offset : rel_offset + self.pointer_width]
            (original_val,) = struct.unpack(self._unpack_fmt, ptr_bytes)
            
            rebased_val = (original_val + base_delta) & ((1 << (self.pointer_width * 8)) - 1)
            patched_bytes = struct.pack(self._unpack_fmt, rebased_val)
            
            buffer[rel_offset : rel_offset + self.pointer_width] = patched_bytes

        return bytes(buffer)

    def scan_for_monotonic_pointer_candidates(
        self,
        min_entries: int = 4
    ) -> List[Tuple[int, int]]:
        """
        Heuristic scanner that identifies potential contiguous pointer tables
        exhibiting strict monotonicity within the bounds of the file.
        Returns a list of tuples: (table_start_offset, entry_count).
        """
        candidates: List[Tuple[int, int]] = []
        stride = self.pointer_width
        limit = self.file_size - (min_entries * stride)

        offset = 0
        while offset < limit:
            run_length = 0
            last_value = -1
            current_scan = offset

            while current_scan + stride <= self.file_size:
                self.stream.seek(current_scan, io.SEEK_SET)
                (val,) = struct.unpack(self._unpack_fmt, self.stream.read(stride))

                # Check if value represents a realistic absolute pointer
                if val <= last_value or val >= self.file_size or val < offset:
                    break

                last_value = val
                run_length += 1
                current_scan += stride

            if run_length >= min_entries:
                candidates.append((offset, run_length))
                offset += run_length * stride
            else:
                offset += stride

        return candidates

def demonstrate_indirection_analysis() -> None:
    """Demonstrates parsing, heuristic identification, and string extraction."""
    print("=" * 72)
    print("DEMONSTRATION: Indirection, String Table, and Relocation Engine")
    print("=" * 72)

    # Synthesize an in-memory test container
    # Header: Magic(4B), Count(4B), TableOffset(4B), DataPoolOffset(4B)
    # Followed by Offset Table, String Data, and Relocation Target
    mock_data = bytearray()
    
    # Header at 0x00
    mock_data.extend(b"PTRX")                       # Magic
    mock_data.extend(struct.pack("<I", 3))           # 3 records
    mock_data.extend(struct.pack("<I", 16))          # Table at 0x10
    mock_data.extend(struct.pack("<I", 32))          # Pool at 0x20
    
    # Offset Table at 0x10 (Anchor-relative to Pool Offset: 0x20)
    # Target 0: +0x00 (0x20), Target 1: +0x08 (0x28), Target 2: +0x14 (0x34)
    mock_data.extend(struct.pack("<I", 0x00))
    mock_data.extend(struct.pack("<I", 0x08))
    mock_data.extend(struct.pack("<I", 0x14))
    mock_data.extend(b"\x00\x00\x00\x00")           # Padding

    # Data Pool at 0x20
    mock_data.extend(b"PayloadA\x00")               # 0x20 - 0x28 (len 9)
    mock_data.extend(b"LongerPayloadB\x00")         # 0x28 - 0x37 (len 15)
    mock_data.extend(b"FinalDataBlock\x00")         # 0x37 - 0x46 (len 15)

    stream = io.BytesIO(mock_data)
    resolver = IndirectionResolver(stream, endianness="<", pointer_width=4)

    print(f"[*] Total Container Size: {resolver.file_size} bytes")

    # 1. Heuristic Scan
    print("[*] Running Heuristic Pointer Scanner...")
    runs = resolver.scan_for_monotonic_pointer_candidates(min_entries=3)
    for start, count in runs:
        print(f"    [+] Monotonic Run Found: Offset 0x{start:04X}, Count: {count}")

    # 2. Parse Known Anchor-Relative Table
    print("\n[*] Resolving Anchor-Relative Offset Table...")
    pointers = resolver.parse_offset_table(
        table_offset=0x10,
        entry_count=3,
        pointer_type=PointerType.ANCHOR_RELATIVE,
        anchor_offset=0x20
    )

    for ptr in pointers:
        span_str = f"{ptr.span_length} bytes" if ptr.span_length else "Unknown"
        print(
            f"    Index {ptr.index}: Raw=0x{ptr.raw_value:04X} -> "
            f"FileOffset=0x{ptr.resolved_file_offset:04X} | Span: {span_str}"
        )

    # 3. Extract Strings
    print("\n[*] Extracting String Pool Payload...")
    strings = resolver.extract_string_pool(pointers, StringEncoding.NULL_TERMINATED_ASCII)
    for idx, text in strings.items():
        print(f"    Record [{idx}]: \"{text}\"")

    # 4. Relocation Fixup Simulation
    print("\n[*] Simulating Base Relocation Fixup...")
    # Add +0x00010000 base delta to the pointers at 0x10, 0x14, 0x18
    rebased = resolver.apply_relocations(
        base_delta=0x00010000,
        relocation_offsets=[0x10, 0x14, 0x18]
    )
    (new_p0,) = struct.unpack("<I", rebased[0x10:0x14])
    print(f"    Original P0: 0x00000000 -> Rebased P0: 0x{new_p0:08X}")
    print("=" * 72)

if __name__ == "__main__":
    demonstrate_indirection_analysis()
