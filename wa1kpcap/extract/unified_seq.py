"""
Merge wa1kpcap built-in flow sequences with native (nvers) seq JSONL into one file.

Output: JSON Lines, one record per flow; all sequence arrays live in a flat
``sequences`` object (no nvers/wa1kpcap nesting):

    {
      "file": "traffic.pcap",
      "flow_id": "192.168.1.1:443->10.0.0.1:52431/TCP",
      "five_tuple": {...},
      "sequences": {
        "direction": [...], "pkt_len": [...], "tls_type": [...],
        "packet_lengths": [...], "iats": [...], "tcp_flags": [...], ...
      }
    }
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from wa1kpcap import Wa1kPcap
from wa1kpcap.extract import ExtractStats, _require_native, extract, read_jsonl


def canonical_key(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: int,
) -> tuple[str, int, str, int, int]:
    """Direction-independent 5-tuple key (matches nvers canonical ordering)."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, src_port, dst_ip, dst_port, proto)
    return (dst_ip, dst_port, src_ip, src_port, proto)


def _key_from_nvers(rec: dict[str, Any]) -> tuple[str, int, str, int, int]:
    ft = rec["five_tuple"]
    return canonical_key(
        ft["src_ip"], ft["dst_ip"],
        int(ft["src_port"]), int(ft["dst_port"]),
        int(ft["proto"]),
    )


def _key_from_flow(flow) -> tuple[str, int, str, int, int]:
    return canonical_key(
        flow.src_ip, flow.dst_ip,
        int(flow.sport), int(flow.dport),
        int(flow.protocol),
    )


def _wa1k_sequences(flow) -> dict[str, list]:
    """Extract wa1kpcap FlowFeatures sequence arrays as plain lists."""
    if not flow.features:
        return {}
    f = flow.features
    out: dict[str, list] = {}
    for name in (
        "packet_lengths", "ip_lengths", "trans_lengths", "app_lengths",
        "timestamps", "iats", "tcp_flags", "tcp_window_sizes",
    ):
        arr = getattr(f, name, None)
        if arr is not None and len(arr) > 0:
            out[name] = arr.tolist()
    return out


def _merge_sequences(
    nvers_rec: dict[str, Any] | None,
    wa1k_rec: dict[str, list] | None,
) -> dict[str, list]:
    """Flat union of sequence fields from both engines (nvers keys take precedence)."""
    merged: dict[str, list] = {}
    if nvers_rec:
        merged.update(nvers_rec.get("sequences") or {})
    if wa1k_rec:
        for name, arr in wa1k_rec.items():
            if name not in merged:
                merged[name] = arr
    return merged


def _merge_record(
    pcap_name: str,
    key: tuple[str, int, str, int, int],
    nvers_rec: dict[str, Any] | None,
    wa1k_rec: dict[str, list] | None,
) -> dict[str, Any]:
    sip, sp, dip, dp, proto = key
    flow_id = f"{sip}:{sp}->{dip}:{dp}/{proto}"

    rec: dict[str, Any] = {
        "file": pcap_name,
        "flow_id": flow_id,
        "five_tuple": {
            "src_ip": sip,
            "src_port": sp,
            "dst_ip": dip,
            "dst_port": dp,
            "proto": proto,
        },
        "sequences": _merge_sequences(nvers_rec, wa1k_rec),
    }

    if nvers_rec:
        rec["flow_id"] = nvers_rec.get("flow_id", flow_id)
        rec["first_ts"] = nvers_rec.get("first_ts")
        rec["last_ts"] = nvers_rec.get("last_ts")
        rec["n_pkts"] = nvers_rec.get("n_pkts")

    return rec


def extract_unified_seq(
    pcap_path: str | Path,
    output_path: str | Path | None = None,
    *,
    n_packets: int = 0,
    workers: int = 0,
    bpf_filter: str | None = None,
    return_stats: bool = False,
) -> Path | tuple[Path, ExtractStats]:
    """
    Merge wa1kpcap + native seq into a single JSONL file.

    Runs two passes (Wa1kPcap analyzer + native seq extractor), joins on
    canonical 5-tuple, and writes one flat ``sequences`` dict per flow.
    """
    _require_native()
    pcap = Path(pcap_path).resolve()
    if not pcap.is_file():
        raise FileNotFoundError(pcap)

    out = Path(output_path) if output_path else pcap.parent / f"{pcap.stem}_seq_unified.log"
    pcap_name = pcap.name

    import time
    t0 = time.perf_counter()

    # Pass 1: native seq (C++)
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        extract(
            pcap, "seq",
            output_path=tmp_path,
            n_packets=n_packets,
            workers=workers,
        )
        nvers_by_key = {_key_from_nvers(r): r for r in read_jsonl(tmp_path)}
    finally:
        tmp_path.unlink(missing_ok=True)

    # Pass 2: wa1kpcap sequences (YAML engine)
    analyzer = Wa1kPcap(
        verbose_mode=True,
        enable_reassembly=True,
        bpf_filter=bpf_filter,
    )
    flows = analyzer.analyze_file(str(pcap))
    wa1k_by_key = {_key_from_flow(f): _wa1k_sequences(f) for f in flows}

    all_keys = set(nvers_by_key) | set(wa1k_by_key)
    merged_count = 0
    with out.open("w", encoding="utf-8") as fout:
        for key in sorted(all_keys):
            nvers_rec = nvers_by_key.get(key)
            wa1k_seq = wa1k_by_key.get(key)
            if not nvers_rec and not wa1k_seq:
                continue
            line = _merge_record(pcap_name, key, nvers_rec, wa1k_seq)
            fout.write(json.dumps(line, ensure_ascii=False) + "\n")
            merged_count += 1

    elapsed = time.perf_counter() - t0
    stats = ExtractStats(
        exit_code=0,
        message="ok",
        flows=merged_count,
        packets=sum(r.get("n_pkts", 0) or 0 for r in nvers_by_key.values()),
        elapsed_sec=elapsed,
        output_path=out,
    )
    if return_stats:
        return out, stats
    return out


__all__ = [
    "canonical_key",
    "extract_unified_seq",
]
