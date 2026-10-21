#!/usr/bin/env python3
"""
primitive_profiler.py

Automated structural profiler and scoring engine for identifying primitive
integer, fixed-point, IEEE 754, and legacy floating-point variants
in undocumented binary streams.
"""

import argparse
import math
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

@dataclass(frozen=True)
class PrimitiveHypothesis:
    type_name: str
    raw_hex: str
    interpreted_value: Any
    plausibility_score: float
    notes: str

class LegacyFloatDecoder:
    """Decodes non-standard and legacy floating-point architectures."""

    @staticmethod
    def decode_mbf32(raw_bytes: bytes) -> Optional[float]:
        """
        Decodes a 32-bit Microsoft Binary Format (MBF) float.
        Layout: [frac0] [frac1] [sign:1 + frac2:7] [exponent]
        """
        if len(raw_bytes) != 4:
            return None

        b0, b1, b2, b3 = raw_bytes
        if b3 == 0:
            return 0.0

        exponent = b3
        sign = -1.0 if (b2 & 0x80) else 1.0
        fraction_bits = ((b2 & 0x7F) << 16) | (b1 << 8) | b0

        # Normalization has implicit bit at 0.5 (2^-1)
        # Fraction occupies 23 explicit bits scaled below 0.5
        mantissa = 0.5 + (fraction_bits / (2.0 ** 24))
        val = sign * mantissa * math.pow(2.0, exponent - 128)
        return val

class PrimitiveProfilerEngine:
    """Evaluates raw byte slices across multiple numerical interpretations."""

    def __init__(self, endianness: str = "little"):
        self.endianness = endianness
        self.prefix = "<" if endianness == "little" else ">"

    def profile_16bit(self, chunk: bytes) -> List[PrimitiveHypothesis]:
        results: List[PrimitiveHypothesis] = []
        if len(chunk) < 2:
            return results

        raw_slice = chunk[:2]
        hex_repr = raw_slice.hex().upper()

        u16 = struct.unpack(f"{self.prefix}H", raw_slice)[0]
        s16 = struct.unpack(f"{self.prefix}h", raw_slice)[0]
        results.append(PrimitiveHypothesis("uint16", hex_repr, u16, 0.8, "Standard unsigned"))
        results.append(PrimitiveHypothesis("int16", hex_repr, s16, 0.8, "Two's complement signed"))

        # Fixed-point Q8.8 interpretation
        q8_8 = s16 / 256.0
        results.append(PrimitiveHypothesis("fixed_Q8.8", hex_repr, round(q8_8, 4), 0.6, "Fractional fixed-point"))

        # IEEE 754 Half-Precision Float (binary16)
        try:
            f16 = struct.unpack(f"{self.prefix}e", raw_slice)[0]
            plausibility = 0.5
            notes = "Half float"
            if not math.isnan(f16) and not math.isinf(f16):
                if 1e-4 <= abs(f16) <= 1e4:
                    plausibility = 0.85
                    notes = "Plausible normalized half float"
                elif f16 == 0.0:
                    plausibility = 0.7
            else:
                plausibility = 0.1
                notes = "NaN or Infinity representation"
            results.append(PrimitiveHypothesis("float16", hex_repr, f16, plausibility, notes))
        except (ValueError, struct.error):
            pass

        return results

    def profile_32bit(self, chunk: bytes) -> List[PrimitiveHypothesis]:
        results: List[PrimitiveHypothesis] = []
        if len(chunk) < 4:
            return results

        raw_slice = chunk[:4]
        hex_repr = raw_slice.hex().upper()

        u32 = struct.unpack(f"{self.prefix}I", raw_slice)[0]
        s32 = struct.unpack(f"{self.prefix}i", raw_slice)[0]
        results.append(PrimitiveHypothesis("uint32", hex_repr, u32, 0.8, "Standard unsigned"))
        results.append(PrimitiveHypothesis("int32", hex_repr, s32, 0.8, "Two's complement signed"))

        # Fixed-point Q16.16 interpretation
        q16_16 = s32 / 65536.0
        results.append(PrimitiveHypothesis("fixed_Q16.16", hex_repr, round(q16_16, 5), 0.65, "Fractional fixed-point"))

        # IEEE 754 Single-Precision Float (binary32)
        try:
            f32 = struct.unpack(f"{self.prefix}f", raw_slice)[0]
            plausibility = 0.5
            notes = "Standard single float"
            if not math.isnan(f32) and not math.isinf(f32):
                abs_val = abs(f32)
                if 1e-5 <= abs_val <= 1e6:
                    plausibility = 0.95
                    notes = "Highly plausible normalized real-world float"
                elif abs_val == 0.0:
                    plausibility = 0.75
                elif abs_val < 1e-30:
                    plausibility = 0.1
                    notes = "Suspicious subnormal/underflow float"
            else:
                plausibility = 0.05
                notes = "NaN or Infinity representation"
            results.append(PrimitiveHypothesis("float32_ieee", hex_repr, f32, plausibility, notes))
        except (ValueError, struct.error):
            pass

        # Legacy Microsoft Binary Format (MBF)
        # Note: MBF is traditionally evaluated under little-endian byte distribution
        mbf_bytes = raw_slice if self.endianness == "little" else raw_slice[::-1]
        mbf_val = LegacyFloatDecoder.decode_mbf32(mbf_bytes)
        if mbf_val is not None:
            mbf_plausibility = 0.4
            notes = "Legacy MBF single"
            if not math.isnan(mbf_val) and 1e-4 <= abs(mbf_val) <= 1e6:
                mbf_plausibility = 0.80
                notes = "Plausible legacy MBF single"
            results.append(PrimitiveHypothesis("float32_mbf", hex_repr, mbf_val, mbf_plausibility, notes))

        return results

    def profile_64bit(self, chunk: bytes) -> List[PrimitiveHypothesis]:
        results: List[PrimitiveHypothesis] = []
        if len(chunk) < 8:
            return results

        raw_slice = chunk[:8]
        hex_repr = raw_slice.hex().upper()

        u64 = struct.unpack(f"{self.prefix}Q", raw_slice)[0]
        s64 = struct.unpack(f"{self.prefix}q", raw_slice)[0]
        results.append(PrimitiveHypothesis("uint64", hex_repr, u64, 0.75, "Standard unsigned 64-bit"))
        results.append(PrimitiveHypothesis("int64", hex_repr, s64, 0.75, "Two's complement signed 64-bit"))

        # IEEE 754 Double-Precision Float (binary64)
        try:
            f64 = struct.unpack(f"{self.prefix}d", raw_slice)[0]
            plausibility = 0.5
            notes = "Standard double float"
            if not math.isnan(f64) and not math.isinf(f64):
                abs_val = abs(f64)
                if 1e-6 <= abs_val <= 1e8:
                    plausibility = 0.95
                    notes = "Highly plausible double precision float"
                elif abs_val == 0.0:
                    plausibility = 0.7
                elif abs_val < 1e-200:
                    plausibility = 0.1
                    notes = "Suspicious subnormal double float"
            else:
                plausibility = 0.05
                notes = "NaN or Infinity representation"
            results.append(PrimitiveHypothesis("float64_ieee", hex_repr, f64, plausibility, notes))
        except (ValueError, struct.error):
            pass

        return results

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deconstruct arbitrary binary slices into competing numeric interpretations."
    )
    parser.add_argument("file", type=Path, help="Target binary file to analyze.")
    parser.add_argument(
        "--offset", "-o", type=lambda x: int(x, 0), default=0,
        help="Byte offset to evaluate (accepts decimal or hex: e.g. 0x10)."
    )
    parser.add_argument(
        "--width", "-w", type=int, choices=[16, 32, 64], default=32,
        help="Evaluation bit-width (16, 32, or 64 bits)."
    )
    parser.add_argument(
        "--endian", "-e", choices=["little", "big"], default="little",
        help="Byte ordering context (default: little)."
    )

    args = parser.parse_args()

    if not args.file.is_file():
        print(f"[-] Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    read_bytes = args.width // 8
    with open(args.file, "rb") as f:
        f.seek(args.offset)
        chunk = f.read(read_bytes)

    if len(chunk) < read_bytes:
        print(
            f"[-] Error: Requested {read_bytes} bytes at offset 0x{args.offset:X}, "
            f"but only found {len(chunk)} bytes.",
            file=sys.stderr,
        )
        sys.exit(1)

    profiler = PrimitiveProfilerEngine(endianness=args.endian)

    if args.width == 16:
        hypotheses = profiler.profile_16bit(chunk)
    elif args.width == 32:
        hypotheses = profiler.profile_32bit(chunk)
    else:
        hypotheses = profiler.profile_64bit(chunk)

    hypotheses.sort(key=lambda h: h.plausibility_score, reverse=True)

    print("=================================================================")
    print(f"  PRIMITIVE PROFILER REPORT: Offset 0x{args.offset:X} ({args.endian.upper()}-ENDIAN)")
    print(f"  Raw Hex: {chunk.hex().upper()}")
    print("=================================================================")
    print(f"{'Type':<14} {'Interpreted Value':<24} {'Score':<6} {'Notes'}")
    print("-" * 65)

    for h in hypotheses:
        val_str = (
            f"{h.interpreted_value:.6g}"
            if isinstance(h.interpreted_value, float)
            else str(h.interpreted_value)
        )
        print(f"{h.type_name:<14} {val_str:<24} {h.plausibility_score:<6.2f} {h.notes}")
    print("=================================================================")

if __name__ == "__main__":
    main()
