#!/usr/bin/env python3
"""
entropy_profiler.py

A modular utility for calculating sliding-window Shannon entropy
across unknown binary files to identify structural archetypes.
"""

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, List

@dataclass(frozen=True)
class EntropyBlock:
    offset: int
    size: int
    entropy: float
    classification: str

class BinaryProfiler:
    def __init__(self, window_size: int = 1024, step_size: int = 512):
        if window_size <= 0 or step_size <= 0:
            raise ValueError("Window and step sizes must be positive integers.")
        self.window_size = window_size
        self.step_size = step_size

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Computes the Shannon entropy of a given byte sequence (0.0 to 8.0)."""
        if not data:
            return 0.0

        length = len(data)
        counts = Counter(data)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def classify_entropy(entropy: float) -> str:
        """Classifies the structural nature of data based on its entropy value."""
        if entropy < 1.0:
            return "PAD/NULL (Structural Boundary)"
        elif entropy < 5.0:
            return "METADATA (Structured Headers / Tables)"
        elif entropy < 7.2:
            return "RAW_DATA (Audio, Text, Vector Payloads)"
        else:
            return "HIGH_ENTROPY (Compressed / Encrypted)"

    def profile_stream(self, data: bytes) -> Generator[EntropyBlock, None, None]:
        """Slides a window across binary data and yields analytical blocks."""
        data_len = len(data)
        
        for offset in range(0, data_len, self.step_size):
            chunk = data[offset : offset + self.window_size]
            if not chunk:
                break

            entropy = self.calculate_shannon_entropy(chunk)
            classification = self.classify_entropy(entropy)
            yield EntropyBlock(
                offset=offset,
                size=len(chunk),
                entropy=round(entropy, 4),
                classification=classification,
            )

    def profile_file(self, file_path: Path) -> List[EntropyBlock]:
        """Reads a target file and executes the complete profiling pipeline."""
        if not file_path.is_file():
            raise FileNotFoundError(f"Target binary not found: {file_path}")

        raw_bytes = file_path.read_bytes()
        return list(self.profile_stream(raw_bytes))

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Profile binary files to locate structural boundaries via Shannon Entropy."
    )
    parser.add_argument("file", type=Path, help="Path to the target unknown binary file.")
    parser.add_argument(
        "-w", "--window", type=int, default=1024, help="Window size in bytes (default: 1024)."
    )
    parser.add_argument(
        "-s", "--step", type=int, default=512, help="Step size in bytes (default: 512)."
    )

    args = parser.parse_args()

    profiler = BinaryProfiler(window_size=args.window, step_size=args.step)
    
    try:
        results = profiler.profile_file(args.file)
        print(f"Offset (Hex)    Entropy   Classification")
        print("-----------------------------------------------------------------")
        for block in results:
            print(
                f"0x{block.offset:08X}      {block.entropy:.2f}     {block.classification}"
            )
    except Exception as exc:
        print(f"Error profiling binary: {exc}")

if __name__ == "__main__":
    main()
