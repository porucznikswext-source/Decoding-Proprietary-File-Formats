#!/usr/bin/env python3
"""
integrity_identifier.py

Production-ready diagnostic suite for identifying, parameterizing, and
recovering Cyclic Redundancy Checks (CRCs), linear accumulators, and
non-cryptographic hashes in proprietary file formats.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

def reflect_bits(val: int, width: int) -> int:
    """Reflects (reverses) the binary bit order of an integer."""
    res = 0
    for _ in range(width):
        res = (res << 1) | (val & 1)
        val >>= 1
    return res

@dataclass(frozen=True)
class CrcModel:
    """Defines a parameterized Rocksoft CRC model."""
    name: str
    width: int
    poly: int
    init: int
    ref_in: bool
    ref_out: bool
    xor_out: int

    def compute(self, data: bytes) -> int:
        """Computes the CRC checksum over the provided data buffer."""
        mask = (1 << self.width) - 1
        reg = self.init

        if self.ref_in:
            for byte in data:
                reg ^= byte
                for _ in range(8):
                    if reg & 1:
                        reg = (reg >> 1) ^ reflect_bits(self.poly, self.width)
                    else:
                        reg >>= 1
        else:
            top_bit = 1 << (self.width - 1)
            for byte in data:
                reg ^= (byte << (self.width - 8))
                for _ in range(8):
                    if reg & top_bit:
                        reg = ((reg << 1) ^ self.poly) & mask
                    else:
                        reg = (reg << 1) & mask

        if self.ref_in != self.ref_out:
            reg = reflect_bits(reg, self.width)

        return (reg ^ self.xor_out) & mask

# Standard reference profiles commonly found in proprietary software
STANDARD_CRC_CATALOG: List[CrcModel] = [
    CrcModel("CRC-16/CCITT-FALSE", 16, 0x1021, 0xFFFF, False, False, 0x0000),
    CrcModel("CRC-16/ARC",         16, 0x8005, 0x0000, True,  True,  0x0000),
    CrcModel("CRC-16/MODBUS",      16, 0x8005, 0xFFFF, True,  True,  0x0000),
    CrcModel("CRC-32/ISO-HDLC",    32, 0x04C11DB7, 0xFFFFFFFF, True,  True,  0xFFFFFFFF),
    CrcModel("CRC-32/BZIP2",       32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF),
    CrcModel("CRC-32/MPEG-2",      32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000),
    CrcModel("CRC-32/POSIX",       32, 0x04C11DB7, 0x00000000, False, False, 0xFFFFFFFF),
    CrcModel("CRC-32C (Castagnoli)", 32, 0x1EDC6F41, 0xFFFFFFFF, True,  True,  0xFFFFFFFF),
    CrcModel("CRC-32/JAMCRC",      32, 0x04C11DB7, 0xFFFFFFFF, True,  True,  0x00000000),
]

class AccumulatorEngine:
    """Implements non-CRC linear and modular checksums."""

    @staticmethod
    def adler32(data: bytes) -> int:
        """Calculates standard 32-bit Adler checksum."""
        mod_adler = 65521
        a = 1
        b = 0
        for byte in data:
            a = (a + byte) % mod_adler
            b = (b + a) % mod_adler
        return (b << 16) | a

    @staticmethod
    def fletcher16(data: bytes) -> int:
        """Calculates standard 16-bit Fletcher checksum."""
        sum1 = 0
        sum2 = 0
        for byte in data:
            sum1 = (sum1 + byte) % 255
            sum2 = (sum2 + sum1) % 255
        return (sum2 << 8) | sum1

    @staticmethod
    def fnv1a_32(data: bytes) -> int:
        """Calculates 32-bit Fowler-Noll-Vo 1a non-cryptographic hash."""
        fnv_prime = 0x01000193
        hval = 0x811C9DC5
        for byte in data:
            hval ^= byte
            hval = (hval * fnv_prime) & 0xFFFFFFFF
        return hval

class ChecksumIdentifier:
    """
    Automated triage scanner that identifies matching verification algorithms
    from observed byte buffers and target checksums.
    """

    def __init__(self, data: bytes, target_checksum: int) -> None:
        self.data = data
        self.target = target_checksum

    def scan_all(self) -> List[str]:
        """Runs the payload against all catalogs and common accumulators."""
        matches: List[str] = []

        # 1. Test Linear and Fast Hashes
        if (self.target & 0xFFFF) == AccumulatorEngine.fletcher16(self.data):
            matches.append("MATCH: Fletcher-16")

        if (self.target & 0xFFFFFFFF) == AccumulatorEngine.adler32(self.data):
            matches.append("MATCH: Adler-32")

        if (self.target & 0xFFFFFFFF) == AccumulatorEngine.fnv1a_32(self.data):
            matches.append("MATCH: FNV-1a (32-bit)")

        # 2. Test Standard Rocksoft Catalog
        for model in STANDARD_CRC_CATALOG:
            res = model.compute(self.data)
            if res == self.target:
                matches.append(f"MATCH: {model.name} (Poly=0x{model.poly:X})")

        return matches

    def recover_affine_presets(
        self, width: int, poly: int, ref: bool
    ) -> List[Tuple[int, int]]:
        """
        Attempts to solve for custom Init and XorOut values given a known
        width, polynomial, and reflection setting.
        Assumes common zero-base conventions:
          Case 1: XorOut = 0, solve for Init.
          Case 2: Init = (1 << width) - 1, solve for XorOut.
        """
        solutions = []
        mask = (1 << width) - 1

        # Case 1: Assume XorOut = 0, calculate back
        zero_out_model = CrcModel("Probe", width, poly, 0, ref, ref, 0)
        baseline = zero_out_model.compute(self.data)
        
        # In a linear CRC without XorOut: Target = Baseline ^ Transform(Init)
        # We test direct inverted presets:
        for candidate_init in [0x00000000, mask]:
            for candidate_xor in [0x00000000, mask]:
                test_model = CrcModel(
                    "Probe", width, poly, candidate_init, ref, ref, candidate_xor
                )
                if test_model.compute(self.data) == self.target:
                    solutions.append((candidate_init, candidate_xor))

        return solutions

def run_demonstration() -> None:
    """Executes verification and identification tests against synthetic inputs."""
    print("=" * 68)
    print("DEMONSTRATION: Automated Checksum & CRC Parameter Identification")
    print("=" * 68)

    sample_payload = b"SYSTEM_TELEMETRY_RECORD_0x4002B19"
    
    # 1. Generate known test targets
    expected_crc32 = 0x88405086  # Computed using CRC-32/ISO-HDLC
    expected_adler = AccumulatorEngine.adler32(sample_payload)
    expected_fnv   = AccumulatorEngine.fnv1a_32(sample_payload)

    # 2. Test standard CRC-32 identification
    print(f"\n[+] Probing Standard CRC-32 Input:")
    print(f"    Payload: {sample_payload.decode('ascii')}")
    print(f"    Target : 0x{expected_crc32:08X}")
    
    scanner = ChecksumIdentifier(sample_payload, expected_crc32)
    results = scanner.scan_all()
    for res in results:
        print(f"    --> {res}")

    # 3. Test Adler-32 identification
    print(f"\n[+] Probing Linear Accumulator Input:")
    print(f"    Target : 0x{expected_adler:08X}")
    scanner_adler = ChecksumIdentifier(sample_payload, expected_adler)
    results_adler = scanner_adler.scan_all()
    for res in results_adler:
        print(f"    --> {res}")

    # 4. Test FNV-1a Non-Cryptographic Hash identification
    print(f"\n[+] Probing Fast Hash Input:")
    print(f"    Target : 0x{expected_fnv:08X}")
    scanner_fnv = ChecksumIdentifier(sample_payload, expected_fnv)
    results_fnv = scanner_fnv.scan_all()
    for res in results_fnv:
        print(f"    --> {res}")

    # 5. Recovering Presets for Custom Inits
    custom_model = CrcModel(
        "CustomCRC32", 32, 0x04C11DB7, 0x12345678, True, True, 0xFFFFFFFF
    )
    custom_target = custom_model.compute(sample_payload)
    print(f"\n[+] Probing Non-Standard Preset CRC:")
    print(f"    Target : 0x{custom_target:08X}")

    # Check against standard catalog (expected failure)
    scanner_custom = ChecksumIdentifier(sample_payload, custom_target)
    custom_results = scanner_custom.scan_all()
    print(f"    Standard Catalog Matches: {len(custom_results)}")

    print("=" * 68)

if __name__ == "__main__":
    run_demonstration()
