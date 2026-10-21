#!/usr/bin/env python3
"""
hilbert_visualizer.py

Production-grade utility for rendering binary file topography using
locality-preserving Hilbert space-filling curves. Generates high-resolution
topographic maps using semantic byte-class coloring.
"""

import argparse
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, List, Tuple

@dataclass(frozen=True)
class RGBColor:
    r: int
    g: int
    b: int

    def to_bytes(self) -> bytes:
        return bytes((self.r, self.g, self.b))

class SemanticPalette:
    """Precomputed color palette mapping bytes to semantic architectural roles."""

    def __init__(self) -> None:
        self.table: List[RGBColor] = [RGBColor(0, 0, 0)] * 256
        self._initialize_palette()

    def _initialize_palette(self) -> None:
        for b in range(256):
            if b == 0x00:
                # Null padding / uninitialized memory
                self.table[b] = RGBColor(10, 10, 15)
            elif b == 0xFF:
                # Alignment fill / bitmask saturation
                self.table[b] = RGBColor(255, 255, 255)
            elif b in (0x09, 0x0A, 0x0D):
                # Text whitespace (tab, newline, carriage return)
                self.table[b] = RGBColor(46, 204, 113)
            elif 0x20 <= b <= 0x7E:
                # Printable ASCII characters
                self.table[b] = RGBColor(52, 152, 219)
            elif 0x01 <= b <= 0x1F:
                # Low control characters / small integers
                self.table[b] = RGBColor(142, 68, 173)
            elif 0x7F <= b <= 0x9F:
                # Extended control codes
                self.table[b] = RGBColor(230, 126, 34)
            else:
                # High-order values / binary data payloads
                self.table[b] = RGBColor(231, 76, 60)

    def get_color(self, byte_val: int) -> RGBColor:
        return self.table[byte_val & 0xFF]

class HilbertCurveMapper:
    """Calculates coordinates for Hilbert space-filling curve projections."""

    @staticmethod
    def calculate_order(data_size: int, max_order: int = 11) -> int:
        """Determines the minimal Hilbert order required to contain data size."""
        if data_size <= 0:
            return 1
        needed_pixels = data_size
        order = math.ceil(math.log2(math.sqrt(needed_pixels)))
        order = max(1, order)
        return min(order, max_order)

    @staticmethod
    def distance_to_xy(index: int, order: int) -> Tuple[int, int]:
        """
        Maps a 1D linear offset to a 2D (x, y) coordinate.
        Canvas dimension is 2^order.
        """
        total_dim = 1 << order
        x = 0
        y = 0
        t = index
        s = 1

        while s < total_dim:
            rx = 1 & (t // 2)
            ry = 1 & (t ^ rx)

            # Rotate quadrant
            if ry == 0:
                if rx == 1:
                    x = (s - 1) - x
                    y = (s - 1) - y
                x, y = y, x

            x += s * rx
            y += s * ry
            t //= 4
            s <<= 1

        return x, y

class PortablePixmapWriter:
    """Writes raw binary RGB data to netpbm PPM format (zero dependencies)."""

    @staticmethod
    def write_ppm(
        output_path: Path, width: int, height: int, pixel_buffer: bytearray
    ) -> None:
        """Serializes RGB pixel data to standard binary PPM (P6)."""
        header = f"P6\n{width} {height}\n255\n".encode("ascii")
        with open(output_path, "wb") as f:
            f.write(header)
            f.write(pixel_buffer)

class FileTopographyEngine:
    """Coordinates stream reading, projection, and rendering."""

    def __init__(self, palette: SemanticPalette):
        self.palette = palette

    def render(
        self,
        input_path: Path,
        output_path: Path,
        forced_order: int = 0,
        downsample: bool = False,
    ) -> None:
        """Renders binary file into a space-filling Hilbert visualization."""
        if not input_path.is_file():
            raise FileNotFoundError(f"Source file not found: {input_path}")

        file_size = input_path.stat().st_size
        if file_size == 0:
            raise ValueError("Target file contains zero bytes.")

        if forced_order > 0:
            order = forced_order
        else:
            order = HilbertCurveMapper.calculate_order(file_size)

        dimension = 1 << order
        total_pixels = dimension * dimension
        stride = 1

        if file_size > total_pixels and downsample:
            stride = math.ceil(file_size / total_pixels)
            effective_bytes = total_pixels
        else:
            effective_bytes = min(file_size, total_pixels)

        print(f"[*] Visualizing: {input_path.name}")
        print(f"    - File Size  : {file_size:,} bytes")
        print(f"    - Curve Order: {order} (Canvas: {dimension}x{dimension})")
        print(f"    - Resolution : {total_pixels:,} pixels")
        if stride > 1:
            print(f"    - Subsampling: 1 sample every {stride} bytes")

        # Initialize background canvas with dark neutral gray
        bg_color = RGBColor(20, 20, 20)
        pixel_data = bytearray(bg_color.to_bytes() * total_pixels)

        with open(input_path, "rb") as f:
            for i in range(effective_bytes):
                if stride > 1:
                    f.seek(i * stride)
                    chunk = f.read(1)
                else:
                    chunk = f.read(1)

                if not chunk:
                    break

                byte_val = chunk[0]
                color = self.palette.get_color(byte_val)
                x, y = HilbertCurveMapper.distance_to_xy(i, order)

                # Row-major pixel offset: (y * width + x) * 3
                pixel_index = (y * dimension + x) * 3
                pixel_data[pixel_index : pixel_index + 3] = color.to_bytes()

        PortablePixmapWriter.write_ppm(
            output_path, dimension, dimension, pixel_data
        )
        print(f"[+] Topographic rendering saved to: {output_path}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render binary topography maps using Hilbert space-filling curves."
    )
    parser.add_argument("file", type=Path, help="Input binary file.")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("topography.ppm"),
        help="Output PPM path (default: topography.ppm).",
    )
    parser.add_argument(
        "--order",
        "-r",
        type=int,
        default=0,
        help="Manually specify Hilbert order (1-12). Default calculates automatically.",
    )
    parser.add_argument(
        "--downsample",
        "-d",
        action="store_true",
        help="Subsample file if it exceeds canvas capacity instead of truncating.",
    )

    args = parser.parse_args()

    palette = SemanticPalette()
    engine = FileTopographyEngine(palette)

    try:
        engine.render(
            input_path=args.file,
            output_path=args.output,
            forced_order=args.order,
            downsample=args.downsample,
        )
    except Exception as err:
        print(f"[-] Execution failed: {err}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
