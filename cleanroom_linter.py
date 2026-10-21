#!/usr/bin/env python3
"""
cleanroom_linter.py

Automated sanitization and cryptographic verification for clean-room
specification documents passing between analysis and implementation teams.
"""

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Pattern

@dataclass(frozen=True)
class TaintViolation:
    line_number: int
    rule_name: str
    matched_text: str
    context: str

@dataclass(frozen=True)
class AuditCertificate:
    file_path: str
    sha256_hash: str
    timestamp_utc: str
    clean: bool
    violations: List[Dict[str, str]]

class SpecificationAuditor:
    """Scans clean-room specifications for leakage of disassembly/decompilation artifacts."""

    # Rules targeting disassembler labels, registers, and decompiler footprints
    RULES: Dict[str, Pattern[str]] = {
        "Disassembler Function Label": re.compile(
            r"\b(sub_[0-9a-fA-F]{6,}|loc_[0-9a-fA-F]{6,}|off_[0-9a-fA-F]{6,})\b"
        ),
        "Memory Address Pointer": re.compile(r"\b0x[0-9a-fA-F]{8,16}\b"),
        "x86/x64 Hardware Register": re.compile(
            r"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r[8-9][d-w]?|r1[0-5][d-w]?)\b",
            re.IGNORECASE,
        ),
        "ARM Architecture Register": re.compile(
            r"\b(r[0-9]|r1[0-5]|x[0-9]|x[1-2][0-9]|x3[0-1]|w[0-9]|w[1-2][0-9]|w3[0-1])\b",
            re.IGNORECASE,
        ),
        "Decompiler Variable Footprint": re.compile(
            r"\b(v[0-9]+|a[0-9]+|varg[0-9]+|arg_[0-9a-fA-F]+)\b"
        ),
        "C++ RTTI / Mangled Symbol Leak": re.compile(r"\b_Z[0-9A-Za-z_]+\b"),
    }

    def __init__(self, target_path: Path):
        self.target_path = target_path
        if not self.target_path.is_file():
            raise FileNotFoundError(f"Target specification not found: {target_path}")

    @staticmethod
    def _calculate_sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def audit(self) -> AuditCertificate:
        """Audits the specification file and generates an immutable audit record."""
        raw_bytes = self.target_path.read_bytes()
        file_hash = self._calculate_sha256(raw_bytes)
        
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Specification must be a UTF-8 text file.") from exc

        violations: List[TaintViolation] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # Exclude markdown code ticks or generic section labels if necessary,
            # but strictly scan structural field definitions
            for rule_name, pattern in self.RULES.items():
                for match in pattern.finditer(line):
                    matched_str = match.group(0)
                    start_pos = max(0, match.start() - 20)
                    end_pos = min(len(line), match.end() + 20)
                    context_snippet = line[start_pos:end_pos].strip()

                    violations.append(
                        TaintViolation(
                            line_number=line_idx,
                            rule_name=rule_name,
                            matched_text=matched_str,
                            context=context_snippet,
                        )
                    )

        certificate = AuditCertificate(
            file_path=str(self.target_path.resolve()),
            sha256_hash=file_hash,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            clean=len(violations) == 0,
            violations=[asdict(v) for v in violations],
        )

        return certificate

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify that an Interface Specification Document contains no leaked taint vectors."
    )
    parser.add_argument(
        "spec_file",
        type=Path,
        help="Path to the specification file (Markdown, text, or YAML).",
    )
    parser.add_argument(
        "-o",
        "--output-cert",
        type=Path,
        help="Optional path to write the JSON audit certificate.",
    )

    args = parser.parse_args()

    try:
        auditor = SpecificationAuditor(args.spec_file)
        certificate = auditor.audit()

        if certificate.clean:
            print("[✓] CLEAN SPECIFICATION: No taint vectors detected.")
            print(f"    File Hash (SHA-256): {certificate.sha256_hash}")
            status_code = 0
        else:
            print(
                f"[!] TAINT DETECTED: {len(certificate.violations)} issue(s) discovered.",
                file=sys.stderr,
            )
            for v in certificate.violations:
                print(
                    f"    Line {v['line_number']} [{v['rule_name']}]: '{v['matched_text']}' in: \"...{v['context']}...\"",
                    file=sys.stderr,
                )
            status_code = 1

        if args.output_cert:
            args.output_cert.write_text(
                json.dumps(asdict(certificate), indent=2), encoding="utf-8"
            )
            print(f"[i] Certificate written to: {args.output_cert}")

        sys.exit(status_code)

    except Exception as exc:
        print(f"Error during audit: {exc}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
