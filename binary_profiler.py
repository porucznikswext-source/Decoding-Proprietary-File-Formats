#!/usr/bin/env python3
"""
binary_profiler.py

Industrial-grade statistical triage utility for reverse engineering
undocumented binary file formats. Computes Shannon entropy, Chi-square
distribution tests, serial correlation, and sliding-window topographic maps.
"""

import argparse
import math
import os
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Generator, List, Optional, Tuple

@dataclass(frozen=True)
class WindowMetric:
    offset: int
    size: int
    entropy: float
    chi2: float
    null_ratio: float

@dataclass(frozen=True)
class StructuralZone:
    start_offset: int
    end_offset: int
    length: int
    mean_entropy: float
    zone_type: str

class StatisticalAnalysisEngine:
    """Core engine for mathematical and statistical profiling of byte buffers."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
        if not data:
            return 0.0

        length = len(data)
        counts = Counter(data)
        entropy = 0.0

        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def calculate_chi_square(data: bytes) -> float:
        """
        Calculates Pearson Chi-Square goodness-of-fit against
        a uniform byte distribution.
        """
        if not data:
            return 0.0

        length = len(data)
        expected = length / 256.0
        counts = Counter(data)
        chi2 = 0.0

        for byte_val in range(256):
            observed = counts.get(byte_val, 0)
            chi2 += ((observed - expected) ** 2) / expected

        return chi2

    @staticmethod
    def calculate_serial_correlation(data: bytes) -> float:
        """
        Calculates the Serial Correlation Coefficient measuring the
        dependency between adjacent bytes.
        """
        n = len(data)
        if n < 2:
            return 0.0

        mean = sum(data) / n
        numerator = 0.0
        denominator = 0.0

        for i in range(n - 1):
            dev_current = data[i] - mean
            dev_next = data[i + 1] - mean
            numerator += dev_current * dev_next
            denominator += dev_current ** 2

        # Include boundary wrapping pair
        dev_last = data[n - 1] - mean
        dev_first = data[0] - mean
        numerator += dev_last * dev_first
        denominator += dev_last ** 2

        if denominator == 0.0:
            return 0.0

        return numerator / denominator

    @staticmethod
    def estimate_monte_carlo_pi(data: bytes) -> float:
        """Estimates Pi using successive byte pairs as normalized coordinates."""
        if len(data) < 2:
            return 0.0

        total_points = len(data) // 2
        inside_circle = 0

        for i in range(0, total_points * 2, 2):
            x = data[i] / 255.0
            y = data[i + 1] / 255.0
            if (x * x + y * y) <= 1.0:
                inside_circle += 1

        return 4.0 * (inside_circle / total_points)

class SlidingWindowProfiler:
    """Processes large binary files through a sliding inspection envelope."""

    def __init__(self, window_size: int = 1024, step_size: int = 256):
        if step_size <= 0 or window_size <= 0:
            raise ValueError("Window and step dimensions must be positive integers.")
        if step_size > window_size:
            raise ValueError("Step size cannot exceed window size.")

        self.window_size = window_size
        self.step_size = step_size
        self.engine = StatisticalAnalysisEngine()

    def profile_stream(
        self, stream, total_size: int
    ) -> Generator[WindowMetric, None, None]:
        """Yields statistical metrics for each sequential sliding window."""
        offset = 0

        while offset < total_size:
            stream.seek(offset)
            chunk = stream.read(self.window_size)
            if not chunk:
                break

            actual_len = len(chunk)
            entropy = self.engine.calculate_entropy(chunk)
            chi2 = self.engine.calculate_chi_square(chunk)
            null_count = chunk.count(0x00)
            null_ratio = null_count / actual_len

            yield WindowMetric(
                offset=offset,
                size=actual_len,
                entropy=entropy,
                chi2=chi2,
                null_ratio=null_ratio,
            )

            offset += self.step_size

class StructuralZoneClassifier:
    """Aggregates contiguous sliding metrics into semantic structural zones."""

    @staticmethod
    def _classify_entropy_type(entropy: float, null_ratio: float) -> str:
        if null_ratio > 0.85:
            return "Null / Alignment Padding"
        if entropy < 1.5:
            return "Sparse Arrays / Redundant Tables"
        if entropy < 3.5:
            return "Structured Numeric Pointers / Records"
        if entropy < 5.5:
            return "ASCII / Code Page Strings / Bytecode"
        if entropy < 7.2:
            return "Packed Bitfields / Uncompressed Audio-Video"
        return "High Entropy (Compressed / Ciphertext)"

    @classmethod
    def segment_zones(
        cls, metrics: List[WindowMetric]
    ) -> List[StructuralZone]:
        """Merges contiguous windows exhibiting similar characteristics."""
        if not metrics:
            return []

        zones: List[StructuralZone] = []
        current_type = cls._classify_entropy_type(
            metrics[0].entropy, metrics[0].null_ratio
        )
        zone_start = metrics[0].offset
        zone_entropies = [metrics[0].entropy]

        for m in metrics[1:]:
            m_type = cls._classify_entropy_type(m.entropy, m.null_ratio)

            if m_type == current_type:
                zone_entropies.append(m.entropy)
            else:
                zone_end = m.offset
                mean_ent = sum(zone_entropies) / len(zone_entropies)
                zones.append(
                    StructuralZone(
                        start_offset=zone_start,
                        end_offset=zone_end,
                        length=zone_end - zone_start,
                        mean_entropy=mean_ent,
                        zone_type=current_type,
                    )
                )
                current_type = m_type
                zone_start = m.offset
                zone_entropies = [m.entropy]

        # Finalize trailing zone
        last_metric = metrics[-1]
        zone_end = last_metric.offset + last_metric.size
        mean_ent = sum(zone_entropies) / len(zone_entropies)
        zones.append(
            StructuralZone(
                start_offset=zone_start,
                end_offset=zone_end,
                length=zone_end - zone_start,
                mean_entropy=mean_ent,
                zone_type=current_type,
            )
        )

        return zones

def render_ascii_sparkline(val: float, min_val: float = 0.0, max_val: float = 8.0) -> str:
    """Renders a simple, fixed-width ASCII sparkline bar for terminal display."""
    bars = [".", ":", "-", "=", "+", "*", "#", "%", "@"]
    clamped = max(min_val, min(max_val, val))
    normalized = (clamped - min_val) / (max_val - min_val)
    idx = int(normalized * (len(bars) - 1))
    return bars[idx]

def execute_binary_triage(
    file_path: str, window_size: int, step_size: int
) -> None:
    """Coordinates the end-to-end triage inspection and renders findings."""
    if not os.path.isfile(file_path):
        print(f"[-] Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        print("[-] Target file is empty.", file=sys.stderr)
        return

    print("=" * 72)
    print("INITIAL BINARY TRIAGE & STATISTICAL PROFILE")
    print(f"Target: {os.path.abspath(file_path)}")
    print(f"Size  : {file_size:,} bytes (0x{file_size:X})")
    print("=" * 72)

    engine = StatisticalAnalysisEngine()

    # Phase 1: Macro-level analysis (Up to 16MB sample for global metrics)
    sample_limit = min(file_size, 16 * 1024 * 1024)
    with open(file_path, "rb") as f:
        sample_buffer = f.read(sample_limit)

    global_entropy = engine.calculate_entropy(sample_buffer)
    global_chi2 = engine.calculate_chi_square(sample_buffer)
    global_scc = engine.calculate_serial_correlation(sample_buffer)
    global_pi = engine.estimate_monte_carlo_pi(sample_buffer)

    print("\n[+] Global Statistical Indicators:")
    print(f"    - Shannon Entropy   : {global_entropy:.4f} / 8.0000 bits/byte")
    print(f"    - Chi-Square (X^2)  : {global_chi2:,.2f} (Uniform = 256.00)")
    print(f"    - Serial Correlation: {global_scc:.6f} (-1.0 to +1.0)")
    print(f"    - Monte Carlo Pi    : {global_pi:.6f} (Delta: {abs(math.pi - global_pi):.6f})")

    # Phase 2: Sliding Window Topography
    print(f"\n[+] Sliding Window Scan (Window: {window_size}B, Step: {step_size}B)")
    profiler = SlidingWindowProfiler(window_size=window_size, step_size=step_size)

    with open(file_path, "rb") as f:
        metrics = list(profiler.profile_stream(f, file_size))

    if not metrics:
        print("[-] No metrics generated.")
        return

    # Visual sparkline representation (Sampled to fit terminal width)
    print("\n[+] Topographic Entropy Curve:")
    sparkline_chars = 60
    stride = max(1, len(metrics) // sparkline_chars)
    sampled_sparkline = [
        render_ascii_sparkline(metrics[i].entropy)
        for i in range(0, len(metrics), stride)
    ][:sparkline_chars]
    print(f"    [Start] {''.join(sampled_sparkline)} [End]")
    print("    Legend: Low [ . : - = + * # % @ ] High (8.0)")

    # Phase 3: Structural Zone Segmentation
    zones = StructuralZoneClassifier.segment_zones(metrics)
    print(f"\n[+] Detected Structural Zones ({len(zones)} discrete regions):")
    print("-" * 72)
    fmt_header = "{:<12} {:<12} {:<10} {:<6}  {}"
    fmt_row = "{:<12} {:<12} {:<10} {:<6.2f}  {}"
    print(fmt_header.format("Start Offset", "End Offset", "Length", "H_mean", "Probable Composition"))
    print("-" * 72)

    for zone in zones:
        print(
            fmt_row.format(
                f"0x{zone.start_offset:08X}",
                f"0x{zone.end_offset:08X}",
                f"{zone.length:,}B",
                zone.mean_entropy,
                zone.zone_type,
            )
        )
    print("-" * 72)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract statistical metrics and structural zones from binary files."
    )
    parser.add_argument("file", help="Path to the binary file to profile.")
    parser.add_argument(
        "--window", "-w", type=int, default=1024,
        help="Sliding window size in bytes (default: 1024)."
    )
    parser.add_argument(
        "--step", "-s", type=int, default=256,
        help="Sliding window step advance in bytes (default: 256)."
    )

    args = parser.parse_args()
    execute_binary_triage(args.file, args.window, args.step)

if __name__ == "__main__":
    main()
