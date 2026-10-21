#!/usr/bin/env python3
"""
entropy_classifier.py

Production-grade statistical profiling and heuristic classification engine
to distinguish between compressed and encrypted binary payloads.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

class ClassificationResult(Enum):
    """Categorical classification of high-entropy data."""
    DEFINITE_PLAINTEXT_OR_STRUCTURED = auto()
    PROBABLE_COMPRESSION = auto()
    PROBABLE_ENCRYPTION = auto()
    AMBIGUOUS_HIGH_ENTROPY = auto()

@dataclass(frozen=True)
class AnalysisMetrics:
    """Statistical and structural metrics extracted from a byte stream."""
    size: int
    shannon_entropy: float
    chi_square: float
    chi_square_p_estimate: float
    arithmetic_mean: float
    serial_correlation: float
    monte_carlo_pi: float
    pi_error_percent: float
    is_aligned_16: bool
    is_aligned_8: bool
    pkcs7_candidate: bool

class PayloadEntropyAnalyzer:
    """
    Analyzes binary buffers using statistical tests and structural heuristics
    to differentiate compressed data from encrypted data.
    """

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be a bytes or bytearray instance.")
        self.data = bytes(data)
        self.size = len(self.data)

    def compute_shannon_entropy(self) -> float:
        """Calculates Shannon entropy in bits per byte [0.0 - 8.0]."""
        if self.size == 0:
            return 0.0

        frequencies = [0] * 256
        for b in self.data:
            frequencies[b] += 1

        entropy = 0.0
        for count in frequencies:
            if count > 0:
                p = count / self.size
                entropy -= p * math.log2(p)

        return float(entropy)

    def compute_chi_square(self) -> Tuple[float, float]:
        """
        Calculates Pearson's Chi-Square against uniform distribution.
        Returns (chi_square_value, rough_uniformity_score).
        """
        if self.size < 256:
            return 0.0, 0.0

        frequencies = [0] * 256
        for b in self.data:
            frequencies[b] += 1

        expected = self.size / 256.0
        chi_sq = sum(((f - expected) ** 2) / expected for f in frequencies)

        # degrees of freedom = 255. # Mean = 255, Variance = 2 * 255 = 510, StDev ~ 22.58
        # Z-score measures deviations from the expected chi-square mean of 255
        z = (chi_sq - 255.0) / math.sqrt(510.0)
        return float(chi_sq), float(z)

    def compute_mean_and_serial_correlation(self) -> Tuple[float, float]:
        """Calculates arithmetic mean and serial correlation at lag 1."""
        if self.size < 2:
            return (float(self.data[0]) if self.size == 1 else 0.0), 0.0

        total = sum(self.data)
        mean = total / self.size

        # Lag-1 Autocorrelation
        numerator = 0.0
        denominator = 0.0

        for i in range(self.size - 1):
            diff_curr = self.data[i] - mean
            diff_next = self.data[i + 1] - mean
            numerator += diff_curr * diff_next
            denominator += diff_curr * diff_curr

        # Include the final sample in denominator
        last_diff = self.data[-1] - mean
        denominator += last_diff * last_diff

        correlation = (numerator / denominator) if denominator != 0.0 else 0.0
        return float(mean), float(correlation)

    def compute_monte_carlo_pi(self) -> Tuple[float, float]:
        """
        Estimates Pi using successive byte pairs as 2D coordinates.
        Returns (estimated_pi, percentage_error).
        """
        points = self.size // 2
        if points < 128:
            return 0.0, 100.0

        inside_circle = 0
        radius_sq = 127.5 * 127.5

        for i in range(0, points * 2, 2):
            x = self.data[i] - 127.5
            y = self.data[i + 1] - 127.5
            if (x * x + y * y) <= radius_sq:
                inside_circle += 1

        estimated_pi = 4.0 * inside_circle / points
        error = abs((estimated_pi - math.pi) / math.pi) * 100.0
        return float(estimated_pi), float(error)

    def check_pkcs7_padding(self) -> bool:
        """Inspects trailer to detect standard PKCS#7 block cipher padding."""
        if self.size < 16 or (self.size % 16 != 0):
            return False

        pad_len = self.data[-1]
        if pad_len == 0 or pad_len > 16:
            return False

        padding_span = self.data[-pad_len:]
        return all(b == pad_len for b in padding_span)

    def analyze(self) -> Tuple[AnalysisMetrics, ClassificationResult, str]:
        """Runs the analysis pipeline and returns metrics with classification."""
        entropy = self.compute_shannon_entropy()
        chi_sq, chi_z = self.compute_chi_square()
        mean, correlation = self.compute_mean_and_serial_correlation()
        pi_val, pi_err = self.compute_monte_carlo_pi()

        is_16 = (self.size % 16 == 0) and (self.size > 0)
        is_8 = (self.size % 8 == 0) and (self.size > 0)
        pkcs7 = self.check_pkcs7_padding()

        metrics = AnalysisMetrics(
            size=self.size,
            shannon_entropy=entropy,
            chi_square=chi_sq,
            chi_square_p_estimate=chi_z,
            arithmetic_mean=mean,
            serial_correlation=correlation,
            monte_carlo_pi=pi_val,
            pi_error_percent=pi_err,
            is_aligned_16=is_16,
            is_aligned_8=is_8,
            pkcs7_candidate=pkcs7,
        )

        # Baseline threshold for high entropy
        if entropy < 7.50:
            return (
                metrics,
                ClassificationResult.DEFINITE_PLAINTEXT_OR_STRUCTURED,
                "Entropy is too low for strong compression or encryption.",
            )

        # Score-based decision logic
        encryption_score = 0
        compression_score = 0
        reasons: List[str] = []

        # 1. Entropy intensity
        if entropy >= 7.995:
            encryption_score += 2
            reasons.append("Extremely high Shannon entropy (>= 7.995)")
        elif entropy >= 7.85:
            compression_score += 1
            reasons.append("Moderate high-entropy (7.85 - 7.995)")

        # 2. Chi-square Z-score deviation
        # Ideal random Z is near 0. Highly compressed streams deviate heavily (Z > 4.0)
        if abs(chi_z) < 2.5:
            encryption_score += 3
            reasons.append("Chi-square conforms closely to uniform random noise")
        elif abs(chi_z) > 4.0:
            compression_score += 3
            reasons.append("Chi-square shows non-random byte distribution bias")

        # 3. Serial Correlation
        if abs(correlation) < 0.002:
            encryption_score += 2
            reasons.append("Negligible adjacent byte correlation (|r| < 0.002)")
        elif abs(correlation) > 0.005:
            compression_score += 2
            reasons.append("Detectable adjacent byte correlation (|r| > 0.005)")

        # 4. Monte Carlo Pi Convergence
        if pi_err < 0.8:
            encryption_score += 1
            reasons.append("Monte Carlo Pi error < 0.8%")
        elif pi_err > 2.0:
            compression_score += 1
            reasons.append("Monte Carlo Pi error > 2.0%")

        # 5. Structural Block Alignments
        if is_16:
            encryption_score += 1
            reasons.append("Size is exact multiple of 16 (AES block boundary)")
        else:
            compression_score += 1
            reasons.append("Size breaks 16-byte block boundary")

        if pkcs7:
            encryption_score += 2
            reasons.append("Valid trailing PKCS#7 padding detected")

        # Synthesize final classification
        if encryption_score >= compression_score + 3:
            classification = ClassificationResult.PROBABLE_ENCRYPTION
        elif compression_score >= encryption_score + 3:
            classification = ClassificationResult.PROBABLE_COMPRESSION
        else:
            classification = ClassificationResult.AMBIGUOUS_HIGH_ENTROPY

        summary = f"Classified as {classification.name}. Factors: " + "; ".join(reasons)
        return metrics, classification, summary

def demonstrate_classification() -> None:
    """Generates synthetic payloads and runs classification diagnostics."""
    import os
    import zlib

    print("=" * 68)
    print("DEMONSTRATION: Distinguishing Compression from Encryption")
    print("=" * 68)

    # 1. Synthesize compressed payload: Repetitive English text deflated
    base_text = (
        b"The quick brown fox jumps over the lazy dog. Proprietary binary "
        b"structures, indirection tables, and hierarchical nodes. "
    ) * 300
    compressed_sample = zlib.compress(base_text, level=9)

    # 2. Synthesize pseudo-encrypted payload: Uniform random bytes (aligned to 16)
    # Using OS cryptographically secure random source to simulate raw ciphertext
    raw_ciphertext = bytearray(os.urandom(len(compressed_sample)))
    # Align to 16 bytes and add PKCS#7 padding
    pad_needed = 16 - (len(raw_ciphertext) % 16)
    raw_ciphertext.extend(bytes([pad_needed] * pad_needed))
    encrypted_sample = bytes(raw_ciphertext)

    samples = [
        ("Deflated Structured Text (Zlib)", compressed_sample),
        ("Simulated Ciphertext (AES-CBC)", encrypted_sample),
    ]

    for label, payload in samples:
        print(f"\n--- Testing: {label} (Size: {len(payload)} bytes) ---")
        analyzer = PayloadEntropyAnalyzer(payload)
        metrics, classification, reason = analyzer.analyze()

        print(f"  Shannon Entropy   : {metrics.shannon_entropy:.6f} bits/byte")
        print(f"  Chi-Square (χ²)   : {metrics.chi_square:.2f} (Z: {metrics.chi_square_p_estimate:+.2f})")
        print(f"  Arithmetic Mean   : {metrics.arithmetic_mean:.2f} (Target: 127.50)")
        print(f"  Serial Correlation: {metrics.serial_correlation:+.6f}")
        print(f"  Monte Carlo Pi    : {metrics.monte_carlo_pi:.4f} (Error: {metrics.pi_error_percent:.2f}%)")
        print(f"  16-byte Aligned   : {metrics.is_aligned_16}")
        print(f"  PKCS#7 Signature  : {metrics.pkcs7_candidate}")
        print(f"  >> Verdict        : {classification.name}")
        print(f"  >> Breakdown      : {reason}")

    print("=" * 68)

if __name__ == "__main__":
    demonstrate_classification()
