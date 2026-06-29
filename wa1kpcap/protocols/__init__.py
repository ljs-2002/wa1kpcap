"""
Protocol-specific native feature APIs.

Each function delegates to the C++ extractor, writes JSONL (or CSV) to disk,
and optionally loads records into Python dicts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wa1kpcap.extract import (
    extract,
    read_jsonl,
    _require_native,
    ExtractStats,
)


def _maybe_load(path: Path, load: bool) -> Path | list[dict[str, Any]]:
    return list(read_jsonl(path)) if load else path


def tls_features(
    pcap_path: str | Path,
    *,
    output_path: str | Path | None = None,
    filter_port: int = 0,
    load: bool = False,
    return_stats: bool = False,
) -> Path | list[dict[str, Any]] | tuple[Path | list[dict[str, Any]], ExtractStats]:
    """TLS handshake, certificates, cipher suites, SNI, ALPN (JSONL)."""
    out = extract(
        pcap_path, "tls",
        output_path=output_path,
        filter_port=filter_port,
        return_stats=return_stats,
    )
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def dns_features(
    pcap_path: str | Path,
    *,
    output_path: str | Path | None = None,
    verbose: bool = False,
    load: bool = False,
    return_stats: bool = False,
):
    """DNS queries/responses, RCODE, domain lists (JSONL)."""
    out = extract(
        pcap_path, "dns",
        output_path=output_path,
        verbose=verbose,
        return_stats=return_stats,
    )
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def smtp_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "smtp", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def dhcp_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "dhcp", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def ftp_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "ftp", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def http_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "http", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def ssh_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "ssh", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def mqtt_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "mqtt", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def sip_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "sip", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def quic_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "quic", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def rdp_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "rdp", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def vnc_features(pcap_path: str | Path, *, output_path=None, load: bool = False, return_stats: bool = False):
    out = extract(pcap_path, "vnc", output_path=output_path, return_stats=return_stats)
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def seq_features(
    pcap_path: str | Path,
    *,
    output_path: str | Path | None = None,
    n_packets: int = 0,
    workers: int = 0,
    load: bool = False,
    return_stats: bool = False,
):
    """Per-flow packet sequences (direction, lengths, IAT, TLS type, burst)."""
    out = extract(
        pcap_path, "seq",
        output_path=output_path,
        n_packets=n_packets,
        workers=workers,
        return_stats=return_stats,
    )
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def payload_features(
    pcap_path: str | Path,
    *,
    output_path: str | Path | None = None,
    n_packets: int = 0,
    workers: int = 0,
    load: bool = False,
    return_stats: bool = False,
):
    """Per-flow payload hex snapshots (JSONL)."""
    out = extract(
        pcap_path, "payload",
        output_path=output_path,
        n_packets=n_packets,
        workers=workers,
        return_stats=return_stats,
    )
    if return_stats:
        path, stats = out
        return _maybe_load(path, load), stats
    return _maybe_load(out, load)


def vpn_features(
    pcap_path: str | Path,
    *,
    output_path: str | Path | None = None,
    verbose: bool = False,
    return_stats: bool = False,
):
    """VPN protocol detection log (WireGuard, OpenVPN, Shadowsocks, …)."""
    return extract(
        pcap_path, "vpn",
        output_path=output_path,
        verbose=verbose,
        return_stats=return_stats,
    )


def im_features(
    pcap_path: str | Path,
    *,
    output_path: str | Path | None = None,
    verbose: bool = False,
    return_stats: bool = False,
):
    """Instant messaging app/protocol detection log."""
    return extract(
        pcap_path, "im",
        output_path=output_path,
        verbose=verbose,
        return_stats=return_stats,
    )


def flow_features(
    pcap_path: str | Path,
    *,
    output_path: str | Path | None = None,
    n_packets: int = 0,
    verbose: bool = False,
    return_stats: bool = False,
):
    """NetFlow v5 / IPFIX / Argus fields as JSON."""
    return extract(
        pcap_path, "flow",
        output_path=output_path,
        n_packets=n_packets,
        verbose=verbose,
        return_stats=return_stats,
    )


def sequence_fields_union() -> list[str]:
    """Union of wa1kpcap built-in sequence fields and nvers seq/payload fields."""
    _require_native()
    from wa1kpcap import _wa1kpcap_nvers as nv
    return list(nv.unified_sequence_fields())


def wa1k_nvers_seq_mapping() -> dict[str, str]:
    """Map wa1kpcap FlowFeatures attribute names to nvers JSONL keys."""
    _require_native()
    from wa1kpcap import _wa1kpcap_nvers as nv
    wa1k_names = [
        "packet_lengths", "ip_lengths", "trans_lengths", "app_lengths",
        "payload_bytes", "timestamps", "iats", "tcp_flags", "tcp_window_sizes",
    ]
    return {n: nv.wa1k_to_nvers_seq_key(n) for n in wa1k_names if nv.wa1k_to_nvers_seq_key(n)}


__all__ = [
    "tls_features",
    "dns_features",
    "smtp_features",
    "dhcp_features",
    "ftp_features",
    "http_features",
    "ssh_features",
    "mqtt_features",
    "sip_features",
    "quic_features",
    "rdp_features",
    "vnc_features",
    "seq_features",
    "payload_features",
    "vpn_features",
    "im_features",
    "flow_features",
    "sequence_fields_union",
    "wa1k_nvers_seq_mapping",
]
