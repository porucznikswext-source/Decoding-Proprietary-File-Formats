#!/usr/bin/env python3
"""
archive_vfs_parser.py

Production-grade parser and extraction engine for proprietary hierarchical
archive filesystems and directory structures.
"""

from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass, field
from enum import IntFlag
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Dict, Iterator, List, Optional, Set, Tuple

class EntryFlags(IntFlag):
    """Structural attribute flags defining node behavior."""
    NONE = 0x00
    IS_DIRECTORY = 0x01
    IS_COMPRESSED = 0x02
    IS_ENCRYPTED = 0x04

@dataclass
class ArchiveEntry:
    """Represents an individual node in the archive filesystem."""
    entry_id: int
    parent_id: int
    flags: EntryFlags
    data_offset: int
    compressed_size: int
    uncompressed_size: int
    timestamp: int
    name: str

    @property
    def is_directory(self) -> bool:
        """Determines if the entry is a directory container."""
        return bool(self.flags & EntryFlags.IS_DIRECTORY)

    @property
    def is_compressed(self) -> bool:
        """Determines if the payload requires decompression."""
        return bool(self.flags & EntryFlags.IS_COMPRESSED)

class VFSError(Exception):
    """Base exception for all archive filesystem errors."""
    pass

class CyclicPathError(VFSError):
    """Raised when circular parent references are detected."""
    pass

class PathTraversalSecurityError(VFSError):
    """Raised when a path attempts to escape the root directory."""
    pass

class CorruptedArchiveError(VFSError):
    """Raised when structural boundaries or invariants are breached."""
    pass

class VirtualFileSystem:
    """
    Constructs, validates, and resolves an in-memory hierarchical directory
    tree from parsed archive records.
    """

    def __init__(self, entries: List[ArchiveEntry]) -> None:
        self._entries: Dict[int, ArchiveEntry] = {e.entry_id: e for e in entries}
        self._children: Dict[int, List[int]] = {}
        self._root_ids: List[int] = []
        self._resolved_paths: Dict[int, PurePosixPath] = {}

        self._build_relational_indices()
        self._validate_and_resolve_paths()

    def _build_relational_indices(self) -> None:
        """Constructs forward child-lookup tables from parent IDs."""
        for entry_id, entry in self._entries.items():
            # A parent_id of 0xFFFFFFFF or referencing itself signifies a root
            if entry.parent_id == 0xFFFFFFFF or entry.parent_id == entry_id:
                self._root_ids.append(entry_id)
            else:
                if entry.parent_id not in self._entries:
                    raise CorruptedArchiveError(
                        f"Entry {entry_id} ('{entry.name}') references "
                        f"non-existent parent ID {entry.parent_id}."
                    )
                self._children.setdefault(entry.parent_id, []).append(entry_id)

        if not self._root_ids and self._entries:
            raise CorruptedArchiveError("No root directory node detected.")

    def _validate_and_resolve_paths(self) -> None:
        """Resolves canonical paths for all nodes and validates against cycles."""
        for entry_id in self._entries:
            path_tokens: List[str] = []
            visited: Set[int] = set()
            curr_id = entry_id

            while True:
                if curr_id in visited:
                    raise CyclicPathError(
                        f"Cyclic reference detected at node ID {curr_id}."
                    )
                visited.add(curr_id)

                entry = self._entries[curr_id]
                if entry.name:
                    path_tokens.append(entry.name)

                # Check if root boundary reached
                if entry.parent_id == 0xFFFFFFFF or entry.parent_id == curr_id:
                    break

                curr_id = entry.parent_id

            # Path tokens were collected ascending up to root; reverse them
            path_tokens.reverse()
            resolved = PurePosixPath("/".join(path_tokens))
            self._resolved_paths[entry_id] = resolved

    def get_path(self, entry_id: int) -> PurePosixPath:
        """Retrieves the fully qualified virtual path for a given entry ID."""
        if entry_id not in self._resolved_paths:
            raise KeyError(f"Entry ID {entry_id} not present in VFS.")
        return self._resolved_paths[entry_id]

    def list_directory(self, entry_id: int) -> List[ArchiveEntry]:
        """Returns direct children of a given directory entry."""
        child_ids = self._children.get(entry_id, [])
        return [self._entries[cid] for cid in child_ids]

    def walk(self, start_id: Optional[int] = None) -> Iterator[Tuple[PurePosixPath, ArchiveEntry]]:
        """Traverses the virtual tree yielding paths and associated entry metadata."""
        roots_to_process = [start_id] if start_id is not None else self._root_ids
        for root_id in roots_to_process:
            stack = [root_id]
            while stack:
                curr_id = stack.pop()
                entry = self._entries[curr_id]
                yield self._resolved_paths[curr_id], entry
                
                # Push children to stack
                children = self._children.get(curr_id, [])
                for child_id in reversed(children):
                    stack.append(child_id)

class HierarchicalArchiveParser:
    """
    Parser for proprietary binary archives containing structured
    directory tables and embedded filesystems.
    """

    MAGIC = b"VFSA"  # Virtual File System Archive
    HEADER_STRUCT = struct.Struct("<4sHHQQ")  # Magic, Ver, Flags, DirOff, DirSize
    ENTRY_HEADER_STRUCT = struct.Struct("<IIHQQQI H") # Layout of entry record

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.stream.seek(0, io.SEEK_END)
        self.file_size = self.stream.tell()
        self.stream.seek(0, io.SEEK_SET)

    def parse_filesystem(self) -> VirtualFileSystem:
        """Parses the archive header and directory table, returning a live VFS."""
        if self.file_size < self.HEADER_STRUCT.size:
            raise CorruptedArchiveError("Stream is too small to contain a valid header.")

        self.stream.seek(0, io.SEEK_SET)
        header_bytes = self.stream.read(self.HEADER_STRUCT.size)
        magic, version, flags, dir_offset, dir_size = self.HEADER_STRUCT.unpack(header_bytes)

        if magic != self.MAGIC:
            raise CorruptedArchiveError(f"Invalid magic signature: {magic!r}")

        # Bounds check the directory table coordinates
        if dir_offset + dir_size > self.file_size:
            raise CorruptedArchiveError(
                f"Directory table (0x{dir_offset:08X}, len {dir_size}) "
                f"exceeds file boundary (0x{self.file_size:08X})."
            )

        entries = self._parse_directory_table(dir_offset, dir_size)
        return VirtualFileSystem(entries)

    def _parse_directory_table(self, offset: int, size: int) -> List[ArchiveEntry]:
        """Decodes raw contiguous directory records within the specified span."""
        self.stream.seek(offset, io.SEEK_SET)
        end_offset = offset + size
        entries: List[ArchiveEntry] = []

        # Sub-header format:
        # uint32 entry_id, uint32 parent_id, uint16 flags, uint64 data_offset,
        # uint64 comp_size, uint64 uncomp_size, uint32 timestamp, uint16 name_len
        dentry_fixed = struct.Struct("<IIHQQQIH")

        while self.stream.tell() < end_offset:
            current_pos = self.stream.tell()
            if current_pos + dentry_fixed.size > end_offset:
                raise CorruptedArchiveError(
                    f"Truncated directory entry header at offset 0x{current_pos:08X}."
                )

            record_bytes = self.stream.read(dentry_fixed.size)
            (
                entry_id,
                parent_id,
                raw_flags,
                data_off,
                comp_size,
                uncomp_size,
                timestamp,
                name_len,
            ) = dentry_fixed.unpack(record_bytes)

            if self.stream.tell() + name_len > end_offset:
                raise CorruptedArchiveError(
                    f"String length {name_len} exceeds table limits at 0x{current_pos:08X}."
                )

            name_bytes = self.stream.read(name_len)
            name_str = name_bytes.decode("utf-8", errors="replace").rstrip("\x00")

            flags = EntryFlags(raw_flags)

            # Defensive verification of payload spans for non-directory records
            if not (flags & EntryFlags.IS_DIRECTORY):
                if data_off + comp_size > self.file_size:
                    raise CorruptedArchiveError(
                        f"Entry '{name_str}' payload (0x{data_off:08X}, len {comp_size}) "
                        f"extends beyond archive EOF (0x{self.file_size:08X})."
                    )

            entries.append(
                ArchiveEntry(
                    entry_id=entry_id,
                    parent_id=parent_id,
                    flags=flags,
                    data_offset=data_off,
                    compressed_size=comp_size,
                    uncompressed_size=uncomp_size,
                    timestamp=timestamp,
                    name=name_str,
                )
            )

        return entries

    def extract_file(
        self,
        entry: ArchiveEntry,
        destination_root: Path,
        vfs: VirtualFileSystem
    ) -> Path:
        """
        Extracts an individual file to disk, enforcing directory traversal
        sanitization to prevent ZipSlip attacks.
        """
        if entry.is_directory:
            raise ValueError("Cannot extract directory entry directly as a file.")

        # Resolve path and neutralize traversal vectors
        virtual_path = vfs.get_path(entry.entry_id)
        
        # Strip root slashes to treat it purely as relative to destination
        clean_relative_str = str(virtual_path).lstrip("/\\")
        dest_root_absolute = destination_root.resolve()
        
        target_path = (dest_root_absolute / clean_relative_str).resolve()

        # Strict containment verification
        if not str(target_path).startswith(str(dest_root_absolute)):
            raise PathTraversalSecurityError(
                f"Path traversal detected: '{virtual_path}' resolves "
                f"outside destination root: '{target_path}'"
            )

        # Create parent directory structure
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Stream payload from disk
        self.stream.seek(entry.data_offset, io.SEEK_SET)
        payload = self.stream.read(entry.compressed_size)

        if len(payload) != entry.compressed_size:
            raise CorruptedArchiveError(
                f"Unexpected EOF reading payload for entry '{entry.name}'."
            )

        with open(target_path, "wb") as out_file:
            out_file.write(payload)

        return target_path

def synthesize_mock_archive() -> bytes:
    """
    Constructs an in-memory mock archive to demonstrate hierarchical
    directory structures and parsing logic.
    """
    buffer = io.BytesIO()
    
    # Placeholder for header
    buffer.write(b"\x00" * HierarchicalArchiveParser.HEADER_STRUCT.size)

    # Write file payloads
    file1_payload = b"print('Engine Initialized')\n"
    file1_offset = buffer.tell()
    buffer.write(file1_payload)

    file2_payload = b"[Audio]\nVolume=1.0\nChannels=2\n"
    file2_offset = buffer.tell()
    buffer.write(file2_payload)

    # Write directory records
    dir_offset = buffer.tell()
    dentry_struct = struct.Struct("<IIHQQQIH")

    # Entry 0: Root directory (ID: 0, Parent: 0xFFFFFFFF)
    name0 = b""
    buffer.write(dentry_struct.pack(
        0, 0xFFFFFFFF, EntryFlags.IS_DIRECTORY, 0, 0, 0, 1600000000, len(name0)
    ))
    buffer.write(name0)

    # Entry 1: "scripts" directory (ID: 1, Parent: 0)
    name1 = b"scripts"
    buffer.write(dentry_struct.pack(
        1, 0, EntryFlags.IS_DIRECTORY, 0, 0, 0, 1600000000, len(name1)
    ))
    buffer.write(name1)

    # Entry 2: "main.lua" inside "scripts" (ID: 2, Parent: 1)
    name2 = b"main.lua"
    buffer.write(dentry_struct.pack(
        2, 1, EntryFlags.NONE, file1_offset,
        len(file1_payload), len(file1_payload), 1600000000, len(name2)
    ))
    buffer.write(name2)

    # Entry 3: "config.ini" in Root (ID: 3, Parent: 0)
    name3 = b"config.ini"
    buffer.write(dentry_struct.pack(
        3, 0, EntryFlags.NONE, file2_offset,
        len(file2_payload), len(file2_payload), 1600000000, len(name3)
    ))
    buffer.write(name3)

    dir_size = buffer.tell() - dir_offset

    # Finalize header
    buffer.seek(0, io.SEEK_SET)
    header_data = HierarchicalArchiveParser.HEADER_STRUCT.pack(
        HierarchicalArchiveParser.MAGIC,
        1,              # Version
        0,              # Flags
        dir_offset,
        dir_size
    )
    buffer.write(header_data)

    return buffer.getvalue()

def demonstrate_archive_vfs() -> None:
    """Executes a diagnostic run displaying hierarchy resolution."""
    raw_archive_bytes = synthesize_mock_archive()
    stream = io.BytesIO(raw_archive_bytes)

    print("=" * 72)
    print("ARCHIVE FILESYSTEM & DIRECTORY RESOLUTION ANALYSIS")
    print("=" * 72)

    parser = HierarchicalArchiveParser(stream)
    vfs = parser.parse_filesystem()

    print(f"[*] Archive parsed successfully ({len(vfs._entries)} total entries).")
    print("\n[*] Reconstructed Virtual Filesystem Hierarchy:")
    
    for path, entry in vfs.walk():
        node_type = "DIR " if entry.is_directory else "FILE"
        display_path = str(path) if str(path) else "/"
        size_info = f"{entry.uncompressed_size:6d} B" if not entry.is_directory else "     -"
        print(f"  [{node_type}] ID: {entry.entry_id:<3} | {display_path:<25} | Size: {size_info}")

    print("=" * 72)

if __name__ == "__main__":
    demonstrate_archive_vfs()
