#!/usr/bin/env python3
"""
binary_diff_tracker.py

Production-grade differential analysis and mutation-based byte tracking engine.
Features alignment-aware binary diffing, arithmetic/bitwise delta triage,
and an active mutation harness for empirical reverse engineering.
"""

import argparse
import difflib
import os
import subprocess
import struct
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import List, Optional, Tuple

class DeltaType(Enum):
    SUBSTITUTION = auto()
    INSERTION = auto()
    DELETION = auto()

@dataclass
class MutationDelta:
    delta_type: DeltaType
    offset_a: int
    offset_b: int
    bytes_a: bytes
    bytes_b: bytes
    description: str

class BinaryDifferentialEngine:
    """Computes alignment-aware differences and classifies mathematical deltas."""

    def __init__(self, block_size: int = 16):
        self.block_size = block_size

    def compare_files(
        self, path_a: Path, path_b: Path
    ) -> List[MutationDelta]:
        """Aligns two binaries and extracts structured mutations."""
        if not path_a.is_file() or not path_b.is_file():
            raise FileNotFoundError("One or both target files do not exist.")

        data_a = path_a.read_bytes()
        data_b = path_b.read_bytes()

        return self.align_and_diff(data_a, data_b)

    def align_and_diff(
        self, data_a: bytes, data_b: bytes
    ) -> List[MutationDelta]:
        """
        Uses sequence matching to align byte streams and isolate mutations,
        preventing cascading false-positives caused by phase shifts.
        """
        matcher = difflib.SequenceMatcher(None, data_a, data_b, autojunk=False)
        opcodes = matcher.get_opcodes()
        deltas: List[MutationDelta] = []

        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "equal":
                continue

            sub_a = data_a[i1:i2]
            sub_b = data_b[j1:j2]

            if tag == "replace":
                desc = self._analyze_substitution(sub_a, sub_b)
                deltas.append(
                    MutationDelta(
                        delta_type=DeltaType.SUBSTITUTION,
                        offset_a=i1,
                        offset_b=j1,
                        bytes_a=sub_a,
                        bytes_b=sub_b,
                        description=desc,
                    )
                )
            elif tag == "insert":
                deltas.append(
                    MutationDelta(
                        delta_type=DeltaType.INSERTION,
                        offset_a=i1,
                        offset_b=j1,
                        bytes_a=b"",
                        bytes_b=sub_b,
                        description=f"Inserted {len(sub_b)} byte(s)",
                    )
                )
            elif tag == "delete":
                deltas.append(
                    MutationDelta(
                        delta_type=DeltaType.DELETION,
                        offset_a=i1,
                        offset_b=j1,
                        bytes_a=sub_a,
                        bytes_b=b"",
                        description=f"Deleted {len(sub_a)} byte(s)",
                    )
                )

        return deltas

    def _analyze_substitution(self, a: bytes, b: bytes) -> str:
        """Classifies substitution into bitwise, scalar, or complex transforms."""
        if len(a) != len(b):
            return f"Length mismatch substitution ({len(a)}B -> {len(b)}B)"

        length = len(a)
        
        # Single-byte analysis
        if length == 1:
            val_a = a[0]
            val_b = b[0]
            xor_mask = val_a ^ val_b
            arith_diff = val_b - val_a
            
            # Check for isolated single-bit toggle
            if xor_mask != 0 and (xor_mask & (xor_mask - 1)) == 0:
                bit_pos = (xor_mask).bit_length() - 1
                return f"Bitflag flip (Bit {bit_pos}, Mask: 0x{xor_mask:02X})"
            
            return (
                f"Scalar byte delta: {arith_diff:+d} "
                f"(0x{val_a:02X} -> 0x{val_b:02X}, XOR: 0x{xor_mask:02X})"
            )

        # Multi-byte integer analysis (16-bit and 32-bit LE/BE)
        if length in (2, 4):
            fmt = "<H" if length == 2 else "<I"
            fmt_be = ">H" if length == 2 else ">I"
            try:
                uint_a_le = struct.unpack(fmt, a)[0]
                uint_b_le = struct.unpack(fmt, b)[0]
                diff_le = uint_b_le - uint_a_le

                uint_a_be = struct.unpack(fmt_be, a)[0]
                uint_b_be = struct.unpack(fmt_be, b)[0]
                diff_be = uint_b_be - uint_a_be

                return (
                    f"Word{length*8} change | "
                    f"LE Delta: {diff_le:+d} | "
                    f"BE Delta: {diff_be:+d}"
                )
            except struct.error:
                pass

        # String detection fallback
        if all(0x20 <= c <= 0x7E for c in a) and all(0x20 <= c <= 0x7E for c in b):
            str_a = a.decode("ascii", errors="replace")
            str_b = b.decode("ascii", errors="replace")
            return f'ASCII change: "{str_a}" -> "{str_b}"'

        return f"Block mutation across {length} contiguous bytes"

class ActiveMutationHarness:
    """Mutates specific byte offsets and evaluates external software behavior."""

    def __init__(self, baseline_path: Path, oracle_cmd: List[str]):
        self.baseline_path = baseline_path
        self.oracle_cmd = oracle_cmd

    def execute_oracle(self, target_file: Path) -> Tuple[int, str]:
        """Runs the validation oracle command against a file."""
        cmd = [part.replace("{FILE}", str(target_file)) for part in self.oracle_cmd]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode, res.stdout.strip()
        except subprocess.TimeoutExpired:
            return -1, "ORACLE_TIMEOUT"
        except Exception as e:
            return -2, f"EXECUTION_FAILED: {str(e)}"

    def sweep_byte_bitflips(
        self, offset: int, scratch_path: Path
    ) -> List[Tuple[int, int, str]]:
        """
        Flips each bit of the byte at the specified offset individually
        and evaluates oracle responses.
        """
        original_data = bytearray(self.baseline_path.read_bytes())
        if offset >= len(original_data):
            raise IndexError(f"Target offset 0x{offset:X} exceeds file bounds.")

        results: List[Tuple[int, int, str]] = []
        original_byte = original_data[offset]

        for bit in range(8):
            mask = 1 << bit
            mutated = bytearray(original_data)
            mutated[offset] = original_byte ^ mask

            scratch_path.write_bytes(mutated)
            code, output = self.execute_oracle(scratch_path)
            results.append((bit, code, output))

        if scratch_path.exists():
            scratch_path.unlink()

        return results

def format_hex_dump(data: bytes, max_len: int = 16) -> str:
    """Formats bytes into a clean, compact hex sequence."""
    if len(data) <= max_len:
        return data.hex(" ").upper()
    truncated = data[:max_len].hex(" ").upper()
    return f"{truncated} ... [{len(data)}B total]"

def print_diff_report(deltas: List[MutationDelta]) -> None:
    """Renders tabular differential analysis results."""
    print("=" * 78)
    print(f"{'TYPE':<12} | {'OFF(A)':<8} | {'OFF(B)':<8} | {'DETAILS'}")
    print("-" * 78)

    for d in deltas:
        type_str = d.delta_type.name
        off_a = f"0x{d.offset_a:06X}" if d.bytes_a else "------"
        off_b = f"0x{d.offset_b:06X}" if d.bytes_b else "------"

        print(f"{type_str:<12} | {off_a:<8} | {off_b:<8} | {d.description}")

        if d.delta_type == DeltaType.SUBSTITUTION:
            print(f"  [-] A: {format_hex_dump(d.bytes_a)}")
            print(f"  [+] B: {format_hex_dump(d.bytes_b)}")
        elif d.delta_type == DeltaType.INSERTION:
            print(f"  [+] Injected: {format_hex_dump(d.bytes_b)}")
        elif d.delta_type == DeltaType.DELETION:
            print(f"  [-] Removed:  {format_hex_dump(d.bytes_a)}")

    print("=" * 78)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Binary Differential Analysis and Mutation Tracking Toolkit."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sub-command: diff
    diff_parser = subparsers.add_parser(
        "diff", help="Perform alignment-aware differential analysis."
    )
    diff_parser.add_argument("file_a", type=Path, help="Baseline file.")
    diff_parser.add_argument("file_b", type=Path, help="Mutated file.")

    # Sub-command: probe
    probe_parser = subparsers.add_parser(
        "probe", help="Perform active mutation bit-flipping at an offset."
    )
    probe_parser.add_argument("baseline", type=Path, help="Known-valid baseline file.")
    probe_parser.add_argument(
        "offset",
        type=lambda x: int(x, 0),
        help="Target byte offset (e.g. 0x4A or 74).",
    )
    probe_parser.add_argument(
        "--oracle",
        nargs="+",
        required=True,
        help="Command to run application oracle. Use {FILE} as placeholder.",
    )
    probe_parser.add_argument(
        "--scratch",
        type=Path,
        default=Path("scratch_mutated.tmp"),
        help="Path for temporary mutated file generation.",
    )

    args = parser.parse_args()

    if args.command == "diff":
        engine = BinaryDifferentialEngine()
        try:
            deltas = engine.compare_files(args.file_a, args.file_b)
            if not deltas:
                print("[+] Files are binary identical.")
                sys.exit(0)
            print_diff_report(deltas)
        except Exception as e:
            print(f"[-] Diff error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "probe":
        harness = ActiveMutationHarness(args.baseline, args.oracle)
        print(f"[*] Commencing bit-sweep mutation at offset 0x{args.offset:06X}...")
        try:
            results = harness.sweep_byte_bitflips(args.offset, args.scratch)
            print("-" * 60)
            print(f"{'BIT':<4} | {'MASK':<6} | {'EXIT CODE':<10} | {'ORACLE OUTPUT'}")
            print("-" * 60)
            for bit, code, out in results:
                mask_str = f"0x{(1 << bit):02X}"
                out_summary = (out[:36] + "..") if len(out) > 36 else out
                print(f"{bit:<4} | {mask_str:<6} | {code:<10} | {out_summary}")
            print("-" * 60)
            print("[+] Mutation sweep completed.")
        except Exception as e:
            print(f"[-] Probing error: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
