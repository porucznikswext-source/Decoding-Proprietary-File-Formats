#!/usr/bin/env python3
"""
chunk_tree_parser.py

Hierarchical Tag-Length-Value (TLV) and FourCC Chunk Parser.
Traverses recursive binary architectures, isolates container/leaf nodes,
and validates structural containment boundaries.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO, List, Optional, Set, Union

class LengthSemantics(Enum):
    """Defines how the length scalar is interpreted."""
    EXCLUSIVE = 1      # Length measures ONLY payload bytes (RIFF, PNG)
    INCLUSIVE = 2      # Length measures Header + Length + Payload (ISOBMFF)

@dataclass
class ChunkLayoutConfig:
    """Configuration governing framing and boundary alignment."""
    endianness: str = "<"                    # '<' for little, '>' for big
    length_semantics: LengthSemantics = LengthSemantics.EXCLUSIVE
    alignment_boundary: int = 1              # Byte alignment (1 = none, 2 = RIFF)
    container_tags: Set[bytes] = field(default_factory=set)
    has_type_subcode: bool = False           # Secondary 4B type for containers

@dataclass
class ChunkNode:
    """Represents a discrete structural node in the binary hierarchy."""
    offset: int
    header_size: int
    tag: bytes
    payload_length: int
    total_physical_size: int
    sub_type: Optional[bytes] = None
    is_container: bool = False
    children: List[ChunkNode] = field(default_factory=list)

    @property
    def tag_str(self) -> str:
        """Attempts to render the tag as clean ASCII; falls back to hex."""
        try:
            ascii_text = self.tag.decode("ascii")
            if ascii_text.isprintable():
                return f"'{ascii_text}'"
        except UnicodeDecodeError:
            pass
        return "0x" + self.tag.hex().upper()

    def print_tree(self, level: int = 0) -> None:
        """Recursively displays the structural topography of the chunk tree."""
        indent = "  " * level
        node_kind = "BRANCH" if self.is_container else "LEAF"
        sub_info = f" [{self.sub_type.decode('ascii', errors='replace')}]" \
                   if self.sub_type else ""
        print(
            f"{indent}[{node_kind}] Tag: {self.tag_str:<8}{sub_info} | "
            f"Offset: 0x{self.offset:08X} | "
            f"Payload: {self.payload_length:8d} B | "
            f"Total Span: {self.total_physical_size:8d} B"
        )
        for child in self.children:
            child.print_tree(level + 1)

class ChunkParsingError(Exception):
    """Base exception for chunk containment and structure violations."""
    pass

class HierarchicalChunkParser:
    """
    Modular engine for reading, decoding, and validating chunk-based
    hierarchical file architectures.
    """

    def __init__(self, stream: BinaryIO, config: ChunkLayoutConfig):
        self.stream = stream
        self.config = config
        self._max_depth = 32

        # Validate endianness configuration
        if self.config.endianness not in ("<", ">"):
            raise ValueError("Endianness must be '<' (little) or '>' (big)")

    def parse(self) -> List[ChunkNode]:
        """Parses the entire stream from the beginning to EOF."""
        self.stream.seek(0, io.SEEK_END)
        total_file_size = self.stream.tell()
        self.stream.seek(0, io.SEEK_SET)

        root_nodes: List[ChunkNode] = []

        while self.stream.tell() < total_file_size:
            start_off = self.stream.tell()
            node = self._read_next_node(total_file_size, depth=0)
            if node is None:
                break
            root_nodes.append(node)

            # Enforce forward progression
            if self.stream.tell() <= start_off:
                raise ChunkParsingError(
                    f"Infinite traversal detected at offset 0x{start_off:08X}"
                )

        return root_nodes

    def _read_next_node(
        self, boundary_offset: int, depth: int
    ) -> Optional[ChunkNode]:
        """
        Reads and constructs a single chunk node.
        Recursively processes child chunks if the node is a container.
        """
        current_offset = self.stream.tell()

        # Check if we have reached or exceeded the allocated bounding span
        if current_offset >= boundary_offset:
            return None

        # Verify minimal room for Tag (4B) and Length (4B)
        if current_offset + 8 > boundary_offset:
            # Trailing alignment or incomplete data
            return None

        tag_bytes = self.stream.read(4)
        (raw_length,) = struct.unpack(f"{self.config.endianness}I", 
                                      self.stream.read(4))

        header_bytes_consumed = 8
        sub_type: Optional[bytes] = None

        # Compute payload and span boundaries based on length semantics
        if self.config.length_semantics == LengthSemantics.EXCLUSIVE:
            payload_len = raw_length
            nominal_total = header_bytes_consumed + payload_len
        elif self.config.length_semantics == LengthSemantics.INCLUSIVE:
            if raw_length < header_bytes_consumed:
                raise ChunkParsingError(
                    f"Malformed inclusive length {raw_length} at 0x{current_offset:08X}"
                )
            payload_len = raw_length - header_bytes_consumed
            nominal_total = raw_length
        else:
            raise NotImplementedError("Unsupported length semantic")

        # Calculate alignment padding bytes
        pad_bytes = 0
        if self.config.alignment_boundary > 1:
            remainder = payload_len % self.config.alignment_boundary
            if remainder != 0:
                pad_bytes = self.config.alignment_boundary - remainder

        total_physical_span = nominal_total + pad_bytes
        chunk_end_offset = current_offset + total_physical_span

        # Boundary violation check against the parent envelope
        if chunk_end_offset > boundary_offset:
            raise ChunkParsingError(
                f"Chunk {tag_bytes!r} at 0x{current_offset:08X} exceeds parent "
                f"boundary (Span: 0x{chunk_end_offset:08X} > 0x{boundary_offset:08X})"
            )

        # Check for container qualification
        is_container = tag_bytes in self.config.container_tags

        if is_container and self.config.has_type_subcode:
            # Container chunks like RIFF/LIST consume the first 4 bytes of payload
            # to store a secondary format tag (e.g., 'WAVE', 'AVI ')
            if payload_len < 4:
                raise ChunkParsingError(
                    f"Container {tag_bytes!r} payload too small for subcode "
                    f"at 0x{current_offset:08X}"
                )
            sub_type = self.stream.read(4)
            child_payload_start = self.stream.tell()
        else:
            child_payload_start = self.stream.tell()

        node = ChunkNode(
            offset=current_offset,
            header_size=header_bytes_consumed,
            tag=tag_bytes,
            payload_length=payload_len,
            total_physical_size=total_physical_span,
            sub_type=sub_type,
            is_container=is_container,
        )

        # Process children if container
        if is_container:
            if depth >= self._max_depth:
                raise ChunkParsingError(
                    f"Max recursion depth exceeded at offset 0x{current_offset:08X}"
                )

            # Limit child scope strictly to chunk's inner payload limit
            inner_boundary = current_offset + nominal_total

            while self.stream.tell() < inner_boundary:
                child_start = self.stream.tell()
                child_node = self._read_next_node(inner_boundary, depth + 1)
                if child_node is None:
                    break
                node.children.append(child_node)

                if self.stream.tell() <= child_start:
                    raise ChunkParsingError(
                        f"Stagnant child parsing at offset 0x{child_start:08X}"
                    )

            # Seek directly to physical chunk boundary, absorbing inner padding
            self.stream.seek(chunk_end_offset, io.SEEK_SET)
        else:
            # For leaf chunks, seek past payload and physical padding
            self.stream.seek(chunk_end_offset, io.SEEK_SET)

        return node

    def extract_leaf_data(self, node: ChunkNode) -> bytes:
        """Reads and returns the raw payload bytes of a specified leaf node."""
        if node.is_container:
            raise ValueError("Cannot read container node as atomic raw data")

        current_loc = self.stream.tell()
        try:
            payload_offset = node.offset + node.header_size
            self.stream.seek(payload_offset, io.SEEK_SET)
            return self.stream.read(node.payload_length)
        finally:
            self.stream.seek(current_loc, io.SEEK_SET)

def analyze_binary_chunks(file_path: Path) -> None:
    """Triage tool demonstrating chunk parsing across real-world containers."""
    if not file_path.is_file():
        print(f"[-] File not found: {file_path}")
        return

    print("=" * 78)
    print(f"TRIAGING CHUNK HIERARCHY: {file_path.name}")
    print("=" * 78)

    # Standard configuration matching classic RIFF-style hierarchies
    riff_config = ChunkLayoutConfig(
        endianness="<",
        length_semantics=LengthSemantics.EXCLUSIVE,
        alignment_boundary=2,
        container_tags={b"RIFF", b"LIST", b"FORM", b"CAT "},
        has_type_subcode=True,
    )

    with open(file_path, "rb") as f:
        parser = HierarchicalChunkParser(f, riff_config)
        try:
            roots = parser.parse()
            for root in roots:
                root.print_tree()
            print("-" * 78)
            print(f"[+] Successfully mapped {len(roots)} root hierarchy elements.")
        except ChunkParsingError as err:
            print(f"[-] Structural parse failure: {err}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python chunk_tree_parser.py <path_to_binary_file>")
        sys.exit(1)

    analyze_binary_chunks(Path(sys.argv[1]))
