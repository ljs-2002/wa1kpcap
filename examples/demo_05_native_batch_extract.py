#!/usr/bin/env python3
"""
Demo 05 — Native C++ batch feature extraction.

Requires: pip install -e .  (BUILD_NVERS=ON, libpcap + OpenSSL)

Usage:
    python examples/demo_05_native_batch_extract.py test/multi.pcap [output_dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wa1kpcap.extract import extract_all, list_features


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.pcap> [output_dir]")
        sys.exit(1)

    pcap = Path(sys.argv[1])
    if not pcap.is_absolute():
        pcap = ROOT / pcap
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else pcap.parent / f"{pcap.stem}_features"

    print("Available native extractors:")
    for spec in list_features():
        print(f"  {spec.name:12s} [{spec.output_format:8s}] {spec.description}")

    print(f"\nInput : {pcap}")
    print(f"Output: {out}\n")

    paths, stats = extract_all(
        pcap,
        out,
        features=["cic", "cicext", "seq", "payload", "tls", "dns"],
        n_packets=0,
        workers=4,
        return_stats=True,
    )

    for name, path in paths.items():
        print(f"  {name:10s} -> {path}")

    print(f"\nDone: {stats.flows} flows, {stats.packets} packets, {stats.elapsed_sec:.2f}s")


if __name__ == "__main__":
    main()
