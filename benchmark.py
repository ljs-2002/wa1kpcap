"""
Benchmark: wa1kpcap dpkt engine vs native C++ engine
- Consistency check on test/multi.pcap
- Speed test on datasets
- Generate markdown report
"""

import argparse
import gc
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np

# ============================================================
# Configuration
# ============================================================
CONSISTENCY_PCAP = Path("D:/MyProgram/wa1kpcap1/test/multi.pcap")

DATASETS = {
    "USTCTFC2016": Path("D:/Project/Dataset/USTCTFC2016/ustc-tfc2016"),
    # "TON-IoT": Path("D:/Project/Dataset/TON-IoT"),
}

REPORT_PATH = Path("D:/MyProgram/wa1kpcap1/benchmark_report.md")
BPF_FILTER = "tcp or udp"

LITE_PCAPS = [
    Path("D:/Project/Dataset/USTCTFC2016/ustc-tfc2016/Benign/Skype.pcap"),
    Path("D:/Project/Dataset/USTCTFC2016/ustc-tfc2016/Benign/FTP.pcap"),
]


def find_pcaps(directory: Path) -> list[Path]:
    """Recursively find all .pcap and .pcapng files."""
    pcaps = []
    for ext in ("*.pcap", "*.pcapng"):
        pcaps.extend(directory.rglob(ext))
    return sorted(pcaps)


def get_total_size_gb(paths: list[Path]) -> float:
    return sum(p.stat().st_size for p in paths) / (1024**3)


# ============================================================
# wa1kpcap helpers
# ============================================================
def wa1kpcap_extract_flows(
    pcap_path: str, engine: str = "dpkt", use_filter: bool = True
):
    """Extract flows with wa1kpcap, return (flows, elapsed_seconds)."""
    from wa1kpcap import Wa1kPcap

    kw = dict(
        filter_ack=False,
        verbose_mode=False,
        engine=engine,
        app_layer_parsing="port_only",
    )
    if use_filter:
        kw["bpf_filter"] = BPF_FILTER

    analyzer = Wa1kPcap(**kw)
    t0 = time.perf_counter()
    flows = analyzer.analyze_file(pcap_path)

    # Touch IAT sequences to ensure they are computed
    for f in flows:
        _ = f.iats

    elapsed = time.perf_counter() - t0
    return flows, elapsed


def wa1kpcap_flow_key(flow) -> tuple:
    """Normalised 5-tuple (sorted IPs so direction doesn't matter)."""
    k = flow.key
    a = (k.src_ip, k.src_port)
    b = (k.dst_ip, k.dst_port)
    if a > b:
        a, b = b, a
    return (a[0], b[0], a[1], b[1], k.protocol)


# ============================================================
# Consistency check
# ============================================================
def _build_flow_map(flows, key_fn) -> dict[tuple, list[float]]:
    """Build normalised_key -> timestamps mapping from a list of flows."""
    result: dict[tuple, list[float]] = {}
    for f in flows:
        k = key_fn(f)
        ts = f.timestamps
        if ts is not None:
            result[k] = ts.tolist() if hasattr(ts, "tolist") else list(ts)
    return result


def _pairwise_iat_compare(
    map_a: dict[tuple, list[float]],
    map_b: dict[tuple, list[float]],
    name_a: str,
    name_b: str,
) -> tuple[list[dict], list[dict], int, int, set, set, set]:
    """Compare two flow maps pairwise. Returns (common_details, mismatches, matched, mismatched, common, only_a, only_b)."""
    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())
    common = keys_a & keys_b
    only_a = keys_a - keys_b
    only_b = keys_b - keys_a

    def _compute_iat(ts_list):
        if len(ts_list) > 1:
            return np.diff(ts_list).tolist()
        return []

    matched = 0
    mismatches = []
    details = []
    for k in sorted(common):
        a_ts = map_a[k]
        b_ts = map_b[k]
        a_iat = _compute_iat(a_ts)
        b_iat = _compute_iat(b_ts)

        iat_len_match = len(a_iat) == len(b_iat)
        if iat_len_match and len(a_iat) > 0:
            max_diff = float(np.max(np.abs(np.array(a_iat) - np.array(b_iat))))
            iat_match = max_diff < 1e-4
        elif iat_len_match:
            iat_match = True
            max_diff = 0.0
        else:
            iat_match = False
            max_diff = float("nan")

        proto_name = {6: "TCP", 17: "UDP"}.get(k[4], str(k[4]))
        detail = {
            "key": f"{k[0]}:{k[2]} <-> {k[1]}:{k[3]} ({proto_name})",
            "a_pkts": len(a_ts),
            "b_pkts": len(b_ts),
            "a_iat_len": len(a_iat),
            "b_iat_len": len(b_iat),
            "iat_match": iat_match,
            "max_diff": max_diff,
            "a_iat_head": a_iat[:5],
            "b_iat_head": b_iat[:5],
        }
        details.append(detail)
        if iat_match:
            matched += 1
        else:
            mismatches.append(detail)

    return details, mismatches, matched, len(mismatches), common, only_a, only_b


def _render_pair_section(
    lines: list[str],
    name_a: str,
    name_b: str,
    map_a: dict,
    map_b: dict,
    section_prefix: str,
):
    """Render a pairwise comparison section into lines."""
    details, mismatches, matched, mismatched, common, only_a, only_b = (
        _pairwise_iat_compare(map_a, map_b, name_a, name_b)
    )

    lines.append(f"### {section_prefix}.1 Overview")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| {name_a} flows | {len(map_a)} |")
    lines.append(f"| {name_b} flows | {len(map_b)} |")
    lines.append(f"| Common 5-tuple keys | {len(common)} |")
    lines.append(f"| Only in {name_a} | {len(only_a)} |")
    lines.append(f"| Only in {name_b} | {len(only_b)} |")
    lines.append(f"| IAT matched | {matched}/{len(common)} |")
    lines.append(f"| IAT mismatched | {mismatched}/{len(common)} |")
    lines.append("")

    if only_a:
        lines.append(f"### {section_prefix}.2 Flows only in {name_a}")
        lines.append("")
        lines.append("| # | Flow | Packets |")
        lines.append("|---|------|---------|")
        for i, k in enumerate(sorted(only_a), 1):
            proto_name = {6: "TCP", 17: "UDP"}.get(k[4], str(k[4]))
            lines.append(
                f"| {i} | {k[0]}:{k[2]} <-> {k[1]}:{k[3]} ({proto_name}) | {len(map_a[k])} |"
            )
        lines.append("")

    if only_b:
        lines.append(f"### {section_prefix}.3 Flows only in {name_b}")
        lines.append("")
        lines.append("| # | Flow | Packets |")
        lines.append("|---|------|---------|")
        for i, k in enumerate(sorted(only_b), 1):
            proto_name = {6: "TCP", 17: "UDP"}.get(k[4], str(k[4]))
            lines.append(
                f"| {i} | {k[0]}:{k[2]} <-> {k[1]}:{k[3]} ({proto_name}) | {len(map_b[k])} |"
            )
        lines.append("")

    lines.append(f"### {section_prefix}.4 Common flows IAT comparison")
    lines.append("")
    lines.append(
        f"| Flow | {name_a} pkts | {name_b} pkts | IAT len | IAT match | max diff (s) |"
    )
    lines.append(
        "|------|" + "-------------|" * 2 + "---------|-----------|-------------|"
    )
    for d in details:
        diff_str = f"{d['max_diff']:.6f}" if not np.isnan(d["max_diff"]) else "N/A"
        lines.append(
            f"| {d['key']} | {d['a_pkts']} | {d['b_pkts']} "
            f"| {d['a_iat_len']}/{d['b_iat_len']} "
            f"| {'Y' if d['iat_match'] else '**N**'} "
            f"| {diff_str} |"
        )
    lines.append("")

    if mismatches:
        show = mismatches[:5]
        lines.append(
            f"### {section_prefix}.5 IAT mismatch examples "
            f"(showing {len(show)}/{mismatched})"
        )
        lines.append("")
        for i, d in enumerate(show, 1):
            lines.append(f"**Example {i}: {d['key']}**")
            lines.append("")
            lines.append(f"- {name_a}: {d['a_pkts']} pkts, {d['a_iat_len']} IATs")
            lines.append(f"- {name_b}: {d['b_pkts']} pkts, {d['b_iat_len']} IATs")
            if not np.isnan(d["max_diff"]):
                lines.append(f"- Max IAT diff: {d['max_diff']:.6f}s")
            else:
                lines.append("- IAT length mismatch")
            a_head = [f"{v:.6f}" for v in d["a_iat_head"]]
            b_head = [f"{v:.6f}" for v in d["b_iat_head"]]
            lines.append(f"- {name_a} IAT (first 5): `[{', '.join(a_head)}]`")
            lines.append(f"- {name_b} IAT (first 5): `[{', '.join(b_head)}]`")
            lines.append("")


def consistency_check() -> str:
    """Compare wa1kpcap[dpkt], wa1kpcap[native], and flowcontainer on test/multi.pcap.

    Returns markdown string with results.
    """
    print("=" * 60)
    print("Consistency check on", CONSISTENCY_PCAP)
    print("=" * 60)

    pcap = str(CONSISTENCY_PCAP)
    from wa1kpcap import Wa1kPcap

    common_kw = dict(
        filter_ack=False,
        filter_rst=False,
        filter_retrans=True,
        bpf_filter=BPF_FILTER,
        verbose_mode=False,
        udp_timeout=0,
    )

    # --- wa1kpcap dpkt ---
    print("  Running wa1kpcap[dpkt] ...")
    dpkt_flows = Wa1kPcap(engine="dpkt", **common_kw).analyze_file(pcap)
    dpkt_map = _build_flow_map(dpkt_flows, wa1kpcap_flow_key)
    print(f"    -> {len(dpkt_map)} flows")

    # --- wa1kpcap native ---
    print("  Running wa1kpcap[native] ...")
    native_flows = Wa1kPcap(engine="native", **common_kw).analyze_file(pcap)
    native_map = _build_flow_map(native_flows, wa1kpcap_flow_key)
    print(f"    -> {len(native_map)} flows")

    # --- flowcontainer ---
    print("  Running flowcontainer ...")
    from flowcontainer.extractor import extract

    fc_result = extract(pcap, filter="tcp or udp", extension=[])
    fc_map: dict[tuple, list[float]] = {}
    for key, f in fc_result.items():
        proto_str = key[1]
        proto_num = 6 if proto_str == "tcp" else (17 if proto_str == "udp" else 0)
        a = (f.src, f.sport)
        b = (f.dst, f.dport)
        if a > b:
            a, b = b, a
        nk = (a[0], b[0], a[1], b[1], proto_num)
        fc_map[nk] = list(f.ip_timestamps)
    print(f"    -> {len(fc_map)} flows")

    # ---- Build markdown ----
    lines = [
        "## 1. Consistency Check (dpkt vs native vs flowcontainer)",
        "",
        f"Test file: `{CONSISTENCY_PCAP}`",
        "",
        f'- wa1kpcap config: `filter_ack=False, filter_retrans=True, bpf_filter="{BPF_FILTER}"`',
        f'- flowcontainer config: `filter="{BPF_FILTER}"`',
        "",
    ]

    # 1A: dpkt vs flowcontainer
    lines.append("## 1A. wa1kpcap[dpkt] vs flowcontainer")
    lines.append("")
    _render_pair_section(lines, "dpkt", "flowcontainer", dpkt_map, fc_map, "1A")

    # 1B: native vs flowcontainer
    lines.append("## 1B. wa1kpcap[native] vs flowcontainer")
    lines.append("")
    _render_pair_section(lines, "native", "flowcontainer", native_map, fc_map, "1B")

    # 1C: dpkt vs native (supplementary)
    lines.append("## 1C. wa1kpcap[dpkt] vs wa1kpcap[native] (supplementary)")
    lines.append("")
    _render_pair_section(lines, "dpkt", "native", dpkt_map, native_map, "1C")

    return "\n".join(lines)


# ============================================================
# flowcontainer helper
# ============================================================
def flowcontainer_extract_flows(pcap_path: str):
    """Extract flows with flowcontainer, return (n_flows, elapsed_seconds)."""
    from flowcontainer.extractor import extract

    t0 = time.perf_counter()
    fc_result = extract(pcap_path, filter="tcp or udp", extension=[])
    elapsed = time.perf_counter() - t0
    return len(fc_result), elapsed


# ============================================================
# Speed benchmark for a single dataset
# ============================================================
def benchmark_dataset(name: str, directory: Path):
    """Benchmark dpkt vs native vs flowcontainer on each pcap file.

    For each file, runs all three engines sequentially for direct comparison.
    Returns (markdown_str, dpkt_total_time, native_total_time, fc_total_time).
    """
    pcaps = find_pcaps(directory)
    if not pcaps:
        msg = f"No pcap files found in {directory}"
        print(f"  WARNING: {msg}")
        return f"### {name}\n\n{msg}\n\n", 0.0, 0.0, 0.0

    total_size = get_total_size_gb(pcaps)
    print(f"\nDataset: {name}")
    print(f"  Path : {directory}")
    print(f"  Files: {len(pcaps)}")
    print(f"  Size : {total_size:.3f} GB")

    per_file = []
    dpkt_total = 0.0
    native_total = 0.0
    fc_total = 0.0

    for i, pcap in enumerate(pcaps, 1):
        size_mb = pcap.stat().st_size / (1024**2)
        print(f"\n  [{i}/{len(pcaps)}] {pcap.name} ({size_mb:.1f} MB)")

        rec = {"file": pcap.name, "size_mb": size_mb}

        # dpkt
        flows = None
        try:
            flows, elapsed = wa1kpcap_extract_flows(
                str(pcap), engine="dpkt", use_filter=True
            )
            rec["dpkt_time"] = elapsed
            rec["dpkt_flows"] = len(flows)
        except Exception as e:
            print(f"    dpkt ERROR: {e}")
            rec["dpkt_time"] = 0.0
            rec["dpkt_flows"] = -1
        dpkt_total += rec["dpkt_time"]
        print(f"    dpkt   : {rec['dpkt_time']:.2f}s, {rec['dpkt_flows']} flows")
        del flows
        gc.collect()

        # native
        flows = None
        try:
            flows, elapsed = wa1kpcap_extract_flows(
                str(pcap), engine="native", use_filter=True
            )
            rec["native_time"] = elapsed
            rec["native_flows"] = len(flows)
        except Exception as e:
            print(f"    native ERROR: {e}")
            rec["native_time"] = 0.0
            rec["native_flows"] = -1
        native_total += rec["native_time"]
        print(f"    native : {rec['native_time']:.2f}s, {rec['native_flows']} flows")
        del flows
        gc.collect()

        # flowcontainer
        try:
            n_flows, elapsed = flowcontainer_extract_flows(str(pcap))
            rec["fc_time"] = elapsed
            rec["fc_flows"] = n_flows
        except Exception as e:
            print(f"    fc ERROR: {e}")
            rec["fc_time"] = 0.0
            rec["fc_flows"] = -1
        fc_total += rec["fc_time"]
        print(f"    fc     : {rec['fc_time']:.2f}s, {rec['fc_flows']} flows")

        per_file.append(rec)

    # Build markdown
    lines = [
        f"### {name}",
        "",
        f"- Path: `{directory}`",
        f"- Files: {len(pcaps)}",
        f"- Total size: {total_size:.3f} GB",
        "",
        "| Metric | dpkt | native | flowcontainer |",
        "|--------|------|--------|---------------|",
        f"| Total time | {dpkt_total:.2f}s | {native_total:.2f}s | {fc_total:.2f}s |",
    ]
    if dpkt_total > 0 and native_total > 0 and fc_total > 0:
        lines.append(
            f"| Speed | {total_size / dpkt_total * 1024:.1f} MB/s "
            f"| {total_size / native_total * 1024:.1f} MB/s "
            f"| {total_size / fc_total * 1024:.1f} MB/s |"
        )
        lines.append(
            f"| Speedup (vs dpkt) | 1.00x | {dpkt_total / native_total:.2f}x "
            f"| {dpkt_total / fc_total:.2f}x |"
        )
    lines += [
        "",
        "#### Per-file results",
        "",
        "| File | Size (MB) | dpkt (s) | native (s) | fc (s) | native speedup | fc speedup |",
        "|------|-----------|----------|------------|--------|----------------|------------|",
    ]

    for rec in per_file:
        sp_native = (
            rec["dpkt_time"] / rec["native_time"] if rec["native_time"] > 0 else 0
        )
        sp_fc = rec["dpkt_time"] / rec["fc_time"] if rec["fc_time"] > 0 else 0
        lines.append(
            f"| {rec['file']} | {rec['size_mb']:.1f} "
            f"| {rec['dpkt_time']:.2f} | {rec['native_time']:.2f} | {rec['fc_time']:.2f} "
            f"| {sp_native:.2f}x | {sp_fc:.2f}x |"
        )
    lines.append("")

    return "\n".join(lines), dpkt_total, native_total, fc_total


# ============================================================
# Lite speed benchmark (dpkt vs native only, specific files)
# ============================================================
def benchmark_lite():
    """Quick dpkt vs native benchmark on a few specific pcap files."""
    print("=" * 60)
    print("Lite speed benchmark (dpkt vs native)")
    print("=" * 60)

    for pcap in LITE_PCAPS:
        if not pcap.exists():
            print(f"  SKIP: {pcap} not found")
            continue
        size_mb = pcap.stat().st_size / (1024**2)
        print(f"\n  {pcap.name} ({size_mb:.1f} MB)")

        # dpkt
        gc.collect()
        flows, dt = wa1kpcap_extract_flows(str(pcap), engine="dpkt", use_filter=True)
        print(f"    dpkt   : {dt:.3f}s, {len(flows)} flows")
        del flows
        gc.collect()

        # native
        flows, nt = wa1kpcap_extract_flows(str(pcap), engine="native", use_filter=True)
        print(f"    native : {nt:.3f}s, {len(flows)} flows")
        if dt > 0:
            print(f"    speedup: {dt / nt:.2f}x")
        del flows
        gc.collect()


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="wa1kpcap dpkt vs native engine benchmark"
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="all",
        choices=["all", "consistency", "speed", "lite-speed"],
        help="Run mode: all (default), consistency only, speed, or lite-speed",
    )
    args = parser.parse_args()

    run_consistency = args.mode in ("all", "consistency")
    run_speed = args.mode in ("all", "speed")
    run_lite = args.mode == "lite-speed"

    from wa1kpcap.native import NATIVE_AVAILABLE

    print(f"Benchmark started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python: {sys.version}")
    print(f"Native engine available: {NATIVE_AVAILABLE}")
    print(f"Mode: {args.mode}")
    print()

    if not NATIVE_AVAILABLE:
        print(
            "ERROR: Native C++ engine not available. Build with: pip install -e '.[native]'"
        )
        sys.exit(1)

    if run_lite:
        benchmark_lite()
        return

    report_sections = []

    report_sections.append(
        f"# wa1kpcap Benchmark: dpkt vs native C++ engine\n\n"
        f"- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"- Python: {sys.version.split()[0]}\n"
        f"- Mode: {args.mode}\n"
        f"- BPF filter: `{BPF_FILTER}`\n"
        f"- Config: `filter_ack=False, verbose_mode=False`\n"
    )

    # 1. Consistency check
    if run_consistency:
        try:
            consistency_md = consistency_check()
            report_sections.append(consistency_md)
        except Exception as e:
            print(f"Consistency check failed: {e}")
            import traceback

            traceback.print_exc()
            report_sections.append(f"## 1. Consistency Check\n\nFailed: {e}\n")

    # 2. Speed benchmarks
    if run_speed:
        report_sections.append("## 2. Speed Benchmark\n")

        summary_rows = []
        for ds_name, ds_path in DATASETS.items():
            try:
                md, dt, nt, ft = benchmark_dataset(ds_name, ds_path)
                pcaps = find_pcaps(ds_path)
                total_gb = get_total_size_gb(pcaps) if pcaps else 0.0
                summary_rows.append(
                    {
                        "name": ds_name,
                        "files": len(pcaps),
                        "size_gb": total_gb,
                        "dpkt_time": dt,
                        "native_time": nt,
                        "fc_time": ft,
                    }
                )
                report_sections.append(md)
            except Exception as e:
                print(f"Benchmark for {ds_name} failed: {e}")
                import traceback

                traceback.print_exc()
                report_sections.append(f"### {ds_name}\n\nFailed: {e}\n")

        if summary_rows:
            summary_lines = [
                "## 3. Summary",
                "",
                "| Dataset | Files | Size (GB) | dpkt (s) | native (s) | fc (s) | native speedup | fc speedup |",
                "|---------|-------|-----------|----------|------------|--------|----------------|------------|",
            ]
            for r in summary_rows:
                sp_native = (
                    r["dpkt_time"] / r["native_time"] if r["native_time"] > 0 else 0
                )
                sp_fc = r["dpkt_time"] / r["fc_time"] if r["fc_time"] > 0 else 0
                summary_lines.append(
                    f"| {r['name']} | {r['files']} | {r['size_gb']:.3f} "
                    f"| {r['dpkt_time']:.2f} | {r['native_time']:.2f} | {r['fc_time']:.2f} "
                    f"| {sp_native:.2f}x | {sp_fc:.2f}x |"
                )
            summary_lines.append("")
            report_sections.append("\n".join(summary_lines))

    report = "\n".join(report_sections)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"\nReport written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
