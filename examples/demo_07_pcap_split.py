#!/usr/bin/env python3
"""
Demo 07 — Split PCAP by 5-tuple (native C++).

Usage:
    python examples/demo_07_pcap_split.py test/single.pcap [output_dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wa1kpcap.extract import split_pcap


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.pcap> [output_dir]")
        sys.exit(1)

    pcap = Path(sys.argv[1])
    if not pcap.is_absolute():
        pcap = ROOT / pcap
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else pcap.parent / f"{pcap.stem}_flows"

    path, stats = split_pcap(pcap, out, return_stats=True)
    print(f"Split {stats.packets} packets into {stats.flows} flow pcaps")
    print(f"Output directory: {path}")


if __name__ == "__main__":
    main()
