#!/usr/bin/env python3
"""
workbench_triage.py

Automated workspace initialization, forensic triage, and artifact cataloging
for proprietary binary file format analysis.
"""

import argparse
import hashlib
import json
import math
import os
import shutil
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

@dataclass(frozen=True)
class FileArtifact:
    file_name: str
    relative_path: str
    size_bytes: int
    sha256: str
    magic_hex: str
    magic_ascii: str
    entropy: float
    is_probable_container: bool

@dataclass(frozen=True)
class WorkspaceManifest:
    project_name: str
    initialized_utc: str
    sample_count: int
    artifacts: List[FileArtifact]

class BinaryTriageTool:
    """Manages workspace scaffolding, file ingestion, and static triage metrics."""

    SUBDIRECTORIES = [
        "corpus/raw",
        "corpus/mutated",
        "schemas",
        "templates",
        "scripts",
        "reports",
    ]

    def __init__(self, workspace_root: Path, project_name: str):
        self.workspace_root = workspace_root.resolve()
        self.project_name = project_name

    def initialize_workspace(self) -> None:
        """Constructs an isolated, standardized directory structure."""
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        for sub_dir in self.SUBDIRECTORIES:
            (self.workspace_root / sub_dir).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon entropy across the provided byte payload."""
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return round(entropy, 4)

    @staticmethod
    def format_ascii(data: bytes) -> str:
        """Converts bytes to a sanitized, printable ASCII string representation."""
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

    def process_file(self, file_path: Path) -> FileArtifact:
        """Reads, hashes, and profiles a single target binary artifact."""
        raw_bytes = file_path.read_bytes()
        file_size = len(raw_bytes)
        sha256 = self.calculate_sha256(raw_bytes)

        # Extract leading 16-byte magic signature block
        magic_slice = raw_bytes[:16]
        magic_hex = magic_slice.hex().upper()
        magic_ascii = self.format_ascii(magic_slice)
        entropy = self.calculate_entropy(raw_bytes)

        # Flag artifacts exhibiting typical compressed or archive signatures
        is_probable_container = entropy >= 7.2000

        relative_path = str(file_path.relative_to(self.workspace_root))

        return FileArtifact(
            file_name=file_path.name,
            relative_path=relative_path,
            size_bytes=file_size,
            sha256=sha256,
            magic_hex=magic_hex,
            magic_ascii=magic_ascii,
            entropy=entropy,
            is_probable_container=is_probable_container,
        )

    def ingest_samples(self, source_files: List[Path]) -> WorkspaceManifest:
        """Copies target samples into the corpus directory and creates the baseline manifest."""
        raw_corpus_dir = self.workspace_root / "corpus" / "raw"
        artifacts: List[FileArtifact] = []

        for source in source_files:
            if not source.is_file():
                continue
            destination = raw_corpus_dir / source.name
            shutil.copy2(source, destination)
            artifact = self.process_file(destination)
            artifacts.append(artifact)

        manifest = WorkspaceManifest(
            project_name=self.project_name,
            initialized_utc=datetime.now(timezone.utc).isoformat(),
            sample_count=len(artifacts),
            artifacts=artifacts,
        )

        manifest_path = self.workspace_root / "reports" / "triage_manifest.json"
        manifest_path.write_text(
            json.dumps(asdict(manifest), indent=2), encoding="utf-8"
        )

        return manifest

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Initialize a binary analysis workbench and ingest target format samples."
    )
    parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        required=True,
        help="Root directory for the reverse engineering workbench.",
    )
    parser.add_argument(
        "--project",
        "-p",
        type=str,
        required=True,
        help="Name of the file format or research project.",
    )
    parser.add_argument(
        "--samples",
        "-s",
        type=Path,
        nargs="*",
        default=[],
        help="List of sample files to ingest immediately.",
    )

    args = parser.parse_args()

    tool = BinaryTriageTool(args.workspace, args.project)
    tool.initialize_workspace()

    if args.samples:
        manifest = tool.ingest_samples(args.samples)
        print(f"[*] Workspace initialized: {args.workspace}")
        print(f"[*] Ingested {manifest.sample_count} artifact(s).")
        print("\nArtifact Summary:")
        print(f"{'File Name':<24} {'Size (B)':<10} {'Entropy':<8} {'Magic (ASCII)':<16}")
        print("-" * 62)
        for art in manifest.artifacts:
            print(
                f"{art.file_name:<24} {art.size_bytes:<10} {art.entropy:<8.4f} {art.magic_ascii:<16}"
            )
        print(f"\n[+] Manifest written to: {args.workspace}/reports/triage_manifest.json")
    else:
        print(f"[*] Workspace structure established at: {args.workspace}")
        print("[*] No samples provided. Corpus directories ready for ingestion.")

if __name__ == "__main__":
    main()
