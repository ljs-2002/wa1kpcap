#!/usr/bin/env python3
"""
Demo 08 — Unified sequence output (wa1kpcap + native seq in one JSONL).

Usage:
    python examples/demo_08_unified_sequences.py test/single.pcap [output.log]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wa1kpcap.extract import extract_unified_seq


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "test/single.pcap"
    if not pcap.is_absolute():
        pcap = ROOT / pcap
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    path, stats = extract_unified_seq(
        pcap, out, n_packets=0, return_stats=True,
    )
    print(f"Merged {stats.flows} flows -> {path} ({stats.elapsed_sec:.2f}s)")

    with path.open(encoding="utf-8") as f:
        first = json.loads(f.readline())
    seq = first.get("sequences", {})
    print("Sequence fields:", sorted(seq.keys()))


if __name__ == "__main__":
    main()
