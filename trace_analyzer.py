#!/usr/bin/env python3
"""
trace_analyzer.py

Parses and visualizes execution traces emitted by syscall_io_logger.so.
Identifies backpatch operations, struct boundary transitions, and sequential
versus random-access layout architectures.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

@dataclass
class WriteSpan:
    operation: str
    offset: int
    length: int
    is_backpatch: bool
    hex_preview: str
    extra: str

class TraceSession:
    def __init__(self, filename: str):
        self.filename = filename
        self.spans: List[WriteSpan] = []
        self.highest_watermark = 0
        self.backpatch_count = 0

    def record_write(
        self, op: str, offset: int, length: int, preview: str, extra: str
    ) -> None:
        is_backpatch = False
        if offset < self.highest_watermark:
            is_backpatch = True
            self.backpatch_count += 1
        else:
            self.highest_watermark = max(self.highest_watermark, offset + length)

        self.spans.append(
            WriteSpan(
                operation=op,
                offset=offset,
                length=length,
                is_backpatch=is_backpatch,
                hex_preview=preview,
                extra=extra,
            )
        )

def process_trace(trace_file: Path) -> Dict[str, TraceSession]:
    sessions: Dict[str, TraceSession] = {}

    with open(trace_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            op = record.get("op")
            target = record.get("file", "unknown")
            offset = record.get("off", 0)
            length = record.get("len", 0)
            extra = record.get("extra", "")
            bytes_preview = record.get("bytes", "")

            if target not in sessions:
                sessions[target] = TraceSession(target)

            session = sessions[target]

            if op in ("WRITE", "PWRITE") and length > 0:
                session.record_write(
                    op=op,
                    offset=offset,
                    length=length,
                    preview=bytes_preview,
                    extra=extra,
                )
            elif op == "LSEEK" and extra == "BACKPATCH_SEEK":
                pass

    return sessions

def print_session_report(session: TraceSession) -> None:
    print("=" * 78)
    print(f"FILE TOPOGRAPHY REPORT: {session.filename}")
    print(f"Total Write Ops: {len(session.spans)} | Backpatch Events: {session.backpatch_count}")
    print(f"Max File Offset Reached: 0x{session.highest_watermark:08X} ({session.highest_watermark} bytes)")
    print("-" * 78)
    print(f"{'STATUS':<11} | {'OP':<6} | {'OFFSET':<10} | {'SIZE':<8} | {'PREVIEW'}")
    print("-" * 78)

    for span in session.spans:
        status = "[BACKPATCH]" if span.is_backpatch else "SEQUENTIAL"
        off_str = f"0x{span.offset:08X}"
        size_str = f"{span.length} B"
        preview = (span.hex_preview[:28] + "..") if len(span.hex_preview) > 28 else span.hex_preview

        print(f"{status:<11} | {span.operation:<6} | {off_str:<10} | {size_str:<8} | {preview}")

    print("=" * 78)

def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze dynamic write trace logs.")
    parser.add_argument("logfile", type=Path, help="Path to trace JSONL log.")
    args = parser.parse_args()

    if not args.logfile.is_file():
        print(f"[-] Log file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    sessions = process_trace(args.logfile)
    if not sessions:
        print("[-] No tracked operations found in log.", file=sys.stderr)
        sys.exit(1)

    for session in sessions.values():
        if session.spans:
            print_session_report(session)

if __name__ == "__main__":
    main()
