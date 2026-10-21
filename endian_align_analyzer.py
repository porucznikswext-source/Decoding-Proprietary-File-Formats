#!/usr/bin/env python3
"""
endian_align_analyzer.py

Heuristic analysis utility for detecting byte endianness, alignment boundaries,
and compiler padding runs in unknown binary format structures.
"""

import argparse
import math
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

@dataclass(frozen=True)
class EndiannessReport:
    sample_size: int
    little_endian_score: float
    big_endian_score: float
    detected_endianness: str
    confidence: float
    valid_pointers_le: int
    valid_pointers_be: int

@dataclass(frozen=True)
class AlignmentReport:
    total_bytes: int
    padding_runs_detected: int
    alignment_multiples: Dict[int, float]
    probable_alignment: int

class EndiannessHeuristicEngine:
    """Analyzes byte-level patterns to determine binary numeric orientation."""

    def __init__(self, data: bytes, total_file_size: Optional[int] = None):
        self.data = data
        self.total_file_size = total_file_size or len(data)

    def analyze(self) -> EndiannessReport:
        data_len = len(self.data)
        if data_len < 4:
            raise ValueError("Data stream too short for endianness analysis (min 4 bytes).")

        le_zero_score = 0
        be_zero_score = 0
        le_pointers = 0
        be_pointers = 0

        # Truncate to a multiple of 4 for 32-bit word inspection
        scan_length = data_len - (data_len % 4)

        for i in range(0, scan_length, 4):
            chunk = self.data[i:i + 4]
            val_le = struct.unpack("<I", chunk)[0]
            val_be = struct.unpack(">I", chunk)[0]

            # Small integer heuristic:
            # Low values leave upper bytes as zero.
            # LE format: [val, val, 00, 00] -> chunk[2] and chunk[3] are 0x00. # BE format: [00, 00, val, val] -> chunk[0] and chunk[1] are 0x00. if chunk[2] == 0 and chunk[3] == 0 and (chunk[0] != 0 or chunk[1] != 0):
                le_zero_score += 1
            if chunk[0] == 0 and chunk[1] == 0 and (chunk[2] != 0 or chunk[3] != 0):
                be_zero_score += 1

            # In-bounds pointer heuristic:
            # Check if values fall cleanly within the bounds of the container
            if 0 < val_le <= self.total_file_size:
                le_pointers += 1
            if 0 < val_be <= self.total_file_size:
                be_pointers += 1

        total_words = scan_length // 4
        le_combined = (le_zero_score * 1.5) + le_pointers
        be_combined = (be_zero_score * 1.5) + be_pointers

        total_score = le_combined + be_combined
        if total_score == 0:
            confidence = 0.0
            verdict = "INDETERMINATE"
        else:
            le_ratio = le_combined / total_score
            be_ratio = be_combined / total_score

            if le_ratio > be_ratio:
                verdict = "LITTLE_ENDIAN"
                confidence = round((le_ratio - be_ratio) * 100, 2)
            elif be_ratio > le_ratio:
                verdict = "BIG_ENDIAN"
                confidence = round((be_ratio - le_ratio) * 100, 2)
            else:
                verdict = "INDETERMINATE"
                confidence = 0.0

        return EndiannessReport(
            sample_size=scan_length,
            little_endian_score=round(le_combined, 2),
            big_endian_score=round(be_combined, 2),
            detected_endianness=verdict,
            confidence=confidence,
            valid_pointers_le=le_pointers,
            valid_pointers_be=be_pointers,
        )

class AlignmentHeuristicEngine:
    """Analyzes zero runs and structural offsets to detect natural alignment patterns."""

    def __init__(self, data: bytes):
        self.data = data

    def analyze(self) -> AlignmentReport:
        data_len = len(self.data)
        padding_runs = 0
        run_lengths: List[Tuple[int, int]] = []  # (offset, length)

        in_run = False
        start_offset = 0

        # Scan for potential padding byte patterns (zeros or debug patterns)
        for idx, byte in enumerate(self.data):
            if byte in (0x00, 0xCC, 0xCD):
                if not in_run:
                    in_run = True
                    start_offset = idx
            else:
                if in_run:
                    in_run = False
                    run_len = idx - start_offset
                    if 1 <= run_len <= 7:  # Typical compiler padding is < 8 bytes
                        padding_runs += 1
                        run_lengths.append((start_offset, run_len))

        if in_run:
            run_len = data_len - start_offset
            if 1 <= run_len <= 7:
                padding_runs += 1
                run_lengths.append((start_offset, run_len))

        # Check alignment boundaries of field transitions
        # A transition occurs where a padding run ends and actual data begins.
        alignment_targets = [2, 4, 8, 16]
        alignment_hits = {target: 0 for target in alignment_targets}

        for start_offset, length in run_lengths:
            resume_offset = start_offset + length
            for target in alignment_targets:
                if resume_offset % target == 0:
                    alignment_hits[target] += 1

        total_runs = max(len(run_lengths), 1)
        ratios = {
            target: round(hits / total_runs, 3)
            for target, hits in alignment_hits.items()
        }

        # Determine most probable natural alignment
        probable = 1
        for target in reversed(alignment_targets):
            if ratios[target] >= 0.70:
                probable = target
                break

        return AlignmentReport(
            total_bytes=data_len,
            padding_runs_detected=padding_runs,
            alignment_multiples=ratios,
            probable_alignment=probable,
        )

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect binary payloads for endianness, alignment boundaries, and padding."
    )
    parser.add_argument("file", type=Path, help="Target binary file to analyze.")
    parser.add_argument(
        "--offset", "-o", type=int, default=0, help="Offset to begin analysis (default: 0)."
    )
    parser.add_argument(
        "--length", "-l", type=int, default=1024, help="Byte count to evaluate (default: 1024)."
    )

    args = parser.parse_args()

    if not args.file.is_file():
        print(f"[-] Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    file_size = args.file.stat().st_size
    with open(args.file, "rb") as f:
        f.seek(args.offset)
        payload = f.read(args.length)

    if not payload:
        print("[-] Error: Read 0 bytes from specified offset.", file=sys.stderr)
        sys.exit(1)

    endian_engine = EndiannessHeuristicEngine(payload, total_file_size=file_size)
    endian_result = endian_engine.analyze()

    align_engine = AlignmentHeuristicEngine(payload)
    align_result = align_engine.analyze()

    print("==================================================")
    print("      BINARY STRUCTURAL PROFILE REPORT            ")
    print("==================================================")
    print(f"Target File:        {args.file.name}")
    print(f"Total File Size:    {file_size} bytes")
    print(f"Inspected Window:   Offset 0x{args.offset:X} to 0x{args.offset + len(payload):X} ({len(payload)} bytes)")
    print("--------------------------------------------------")
    print("ENDIANNESS HEURISTICS:")
    print(f"  Detected Order:   {endian_result.detected_endianness}")
    print(f"  Confidence:       {endian_result.confidence}%")
    print(f"  Scores:           LE: {endian_result.little_endian_score} | BE: {endian_result.big_endian_score}")
    print(f"  In-Bounds Ptrs:   LE: {endian_result.valid_pointers_le} | BE: {endian_result.valid_pointers_be}")
    print("--------------------------------------------------")
    print("ALIGNMENT & PADDING HEURISTICS:")
    print(f"  Probable Align:   {align_result.probable_alignment}-byte boundary")
    print(f"  Padding Runs:     {align_result.padding_runs_detected} suspicious inter-field runs")
    print("  Alignment Correlation Ratios:")
    for boundary, ratio in align_result.alignment_multiples.items():
        print(f"    - {boundary:2d}-byte boundary: {ratio * 100:.1f}%")
    print("==================================================")

if __name__ == "__main__":
    main()
