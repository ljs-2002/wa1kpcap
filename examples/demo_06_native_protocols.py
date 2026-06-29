#!/usr/bin/env python3
"""
Demo 06 — Protocol-specific native extractors (TLS, DNS, …).

Usage:
    python examples/demo_06_native_protocols.py test/multi.pcap
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wa1kpcap.protocols import (
    tls_features,
    dns_features,
    seq_features,
    sequence_fields_union,
    wa1k_nvers_seq_mapping,
)


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "test/multi.pcap"
    if not pcap.is_absolute():
        pcap = ROOT / pcap

    print("Sequence field union (wa1kpcap ∪ native):")
    print(" ", ", ".join(sequence_fields_union()[:8]), "...")
    print("Mapping wa1kpcap → native:", wa1k_nvers_seq_mapping())
    print()

    with tempfile.TemporaryDirectory(prefix="wa1k_demo_") as tmp:
        out = Path(tmp)

        tls_path, tls_stats = tls_features(
            pcap, output_path=out / "tls.log", return_stats=True
        )
        print(f"TLS : {tls_stats.flows} flows -> {tls_path}")

        dns_path, dns_stats = dns_features(
            pcap, output_path=out / "dns.log", return_stats=True
        )
        print(f"DNS : {dns_stats.flows} flows -> {dns_path}")

        seq_rows, seq_stats = seq_features(
            pcap, output_path=out / "seq.log", n_packets=30, return_stats=True, load=True
        )
        print(f"SEQ : {seq_stats.packets} pkts, {len(seq_rows)} flow records")
        if seq_rows:
            keys = list(seq_rows[0].keys())[:6]
            print(f"      sample keys: {keys}")


if __name__ == "__main__":
    main()
