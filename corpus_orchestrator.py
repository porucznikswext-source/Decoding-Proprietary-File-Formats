#!/usr/bin/env python3
"""
corpus_orchestrator.py

Production-grade binary corpus cataloging and verification engine.
Manages file lineages, computes cryptographic invariants, detects volatile
non-deterministic byte offsets, and exports analytical corpus manifests.
"""

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class SampleRecord:
    filename: str
    file_size: int
    sha256: str
    generation_tier: str
    description: str
    parameters: Dict[str, str]
    volatile_offsets: List[int]

class VolatilityAnalyzer:
    """Analyzes differences between twin-save files to isolate volatile bytes."""

    @staticmethod
    def identify_volatile_offsets(file_paths: List[Path]) -> List[int]:
        """
        Compares multiple files that are expected to be identical.
        Returns a sorted list of byte offsets where values diverge.
        """
        if len(file_paths) < 2:
            return []

        # Read all files into memory
        buffers: List[bytes] = []
        for path in file_paths:
            with open(path, "rb") as f:
                buffers.append(f.read())

        # Determine reference length based on shortest file
        min_length = min(len(buf) for buf in buffers)
        max_length = max(len(buf) for buf in buffers)

        volatile_offsets: Set[int] = set()

        # Check byte divergence up to min_length
        for offset in range(min_length):
            base_byte = buffers[0][offset]
            for buf in buffers[1:]:
                if buf[offset] != base_byte:
                    volatile_offsets.add(offset)
                    break

        # If files differ in length, all overflowing bytes are marked volatile
        if min_length != max_length:
            for offset in range(min_length, max_length):
                volatile_offsets.add(offset)

        return sorted(list(volatile_offsets))

class CorpusCataloger:
    """Orchestrates corpus registration, hashing, and manifest generation."""

    def __init__(self, corpus_root: Path):
        self.corpus_root = corpus_root
        self.samples_dir = corpus_root / "raw_samples"
        self.manifest_path = corpus_root / "manifest.json"
        self.samples_dir.mkdir(parents=True, exist_ok=True)
        self.records: List[SampleRecord] = []

    def compute_sha256(self, file_path: Path) -> str:
        """Computes the SHA-256 cryptographic digest of a binary file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def register_sample(
        self,
        file_path: Path,
        tier: str,
        description: str,
        parameters: Dict[str, str],
        volatile_offsets: Optional[List[int]] = None,
    ) -> SampleRecord:
        """Calculates file metrics and appends sample record to the catalog."""
        if not file_path.is_file():
            raise FileNotFoundError(f"Sample not found: {file_path}")

        file_size = file_path.stat().st_size
        digest = self.compute_sha256(file_path)
        volatiles = volatile_offsets if volatile_offsets is not None else []

        record = SampleRecord(
            filename=file_path.name,
            file_size=file_size,
            sha256=digest,
            generation_tier=tier,
            description=description,
            parameters=parameters,
            volatile_offsets=volatiles,
        )
        self.records.append(record)
        return record

    def save_manifest(self) -> None:
        """Persists the registered records into an indented JSON manifest."""
        manifest_data = {
            "version": "1.0.0",
            "sample_count": len(self.records),
            "samples": [asdict(r) for r in self.records],
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        print(f"[+] Manifest saved successfully: {self.manifest_path}")

def execute_twin_test(files: List[Path]) -> None:
    """Executes non-deterministic noise triage across specified sample files."""
    print("=" * 72)
    print("TWIN-SAVE VOLATILITY VERIFICATION")
    print("=" * 72)

    for p in files:
        if not p.is_file():
            print(f"[-] Error: Target file does not exist: {p}", file=sys.stderr)
            sys.exit(1)

    offsets = VolatilityAnalyzer.identify_volatile_offsets(files)

    if not offsets:
        print("[+] Output is fully deterministic. No volatile bytes detected.")
        print("    Files are binary identical.")
        return

    print(f"[-] Detected {len(offsets)} volatile byte offset(s):")
    
    # Group contiguous offsets for concise terminal display
    ranges: List[Tuple[int, int]] = []
    for off in offsets:
        if not ranges or off > ranges[-1][1] + 1:
            ranges.append((off, off))
        else:
            ranges[-1] = (ranges[-1][0], off)

    for start, end in ranges:
        if start == end:
            print(f"    Offset 0x{start:08X} ({start})")
        else:
            length = end - start + 1
            print(f"    Range  0x{start:08X} - 0x{end:08X} ({length} bytes)")

    print("-" * 72)
    print("[*] Operational Guidance:")
    print("    1. Apply this offset mask to ignore noise during differential diffs.")
    print("    2. Offsets spanning 4 or 8 bytes often represent timestamps or pointers.")
    print("    3. Offsets spanning 16 bytes typically represent random UUIDs/GUIDs.")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Binary Corpus Cataloging and Non-Determinism Isolation Tool."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sub-command: twin-test
    twin_parser = subparsers.add_parser(
        "twin-test",
        help="Compare two or more identical-state saves to detect volatile noise.",
    )
    twin_parser.add_argument(
        "files",
        type=Path,
        nargs="+",
        help="List of files saved under identical application states.",
    )

    # Sub-command: init-manifest
    init_parser = subparsers.add_parser(
        "init-manifest",
        help="Scan a directory of corpus samples and construct an initial manifest.",
    )
    init_parser.add_argument(
        "directory",
        type=Path,
        help="Path to the corpus directory containing samples.",
    )
    init_parser.add_argument(
        "--tier",
        type=str,
        default="Tier 1: Minimalist",
        help="Default tier label to assign to unregistered samples.",
    )

    args = parser.parse_args()

    if args.command == "twin-test":
        execute_twin_test(args.files)

    elif args.command == "init-manifest":
        corpus_path = args.directory.resolve()
        if not corpus_path.is_dir():
            print(f"[-] Directory not found: {corpus_path}", file=sys.stderr)
            sys.exit(1)

        cataloger = CorpusCataloger(corpus_path)
        sample_files = sorted(
            [f for f in corpus_path.iterdir() if f.is_file() and f.name != "manifest.json"]
        )

        if not sample_files:
            print(f"[-] No sample files discovered in {corpus_path}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Registering {len(sample_files)} sample(s) into corpus catalog...")
        for file_p in sample_files:
            cataloger.register_sample(
                file_path=file_p,
                tier=args.tier,
                description="Auto-registered during catalog initialization.",
                parameters={"source": "bulk_import"},
            )

        cataloger.save_manifest()
        print(f"[+] Corpus directory successfully initialized at: {corpus_path}")

if __name__ == "__main__":
    main()
