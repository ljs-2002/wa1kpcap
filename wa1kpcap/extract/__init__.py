"""
Native C++ feature extraction (high-throughput libpcap pipeline).

Python only supplies paths and parameters; parsing, feature computation,
and file output are performed entirely in C++.

Quick start::

    from wa1kpcap.extract import extract_all, list_features

    paths = extract_all("traffic.pcap", "out/", features=["cic", "tls", "seq"])
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal, Sequence

try:
    from wa1kpcap import _wa1kpcap_nvers as _nv
except ImportError as _e:
    _nv = None
    _IMPORT_ERROR = _e
else:
    _IMPORT_ERROR = None

OutputFormat = Literal["csv", "jsonl", "json", "pcap_dir", "log"]


@dataclass(frozen=True)
class FeatureSpec:
    """Metadata for a built-in native extractor."""

    name: str
    aliases: tuple[str, ...]
    output_format: OutputFormat
    default_suffix: str
    description: str


@dataclass
class ExtractStats:
    """Statistics returned by a native extraction run."""

    exit_code: int
    message: str
    flows: int
    packets: int
    elapsed_sec: float
    output_path: Path

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


# Canonical feature registry (user-facing name → native kind)
FEATURE_REGISTRY: dict[str, FeatureSpec] = {
    "cic": FeatureSpec(
        "cic", ("cic",), "csv", "_cic.csv",
        "CIC-FlowMeter 80 维流级统计特征",
    ),
    "cicext": FeatureSpec(
        "cicext", ("cicext", "cic_ext"), "csv", "_cicext.csv",
        "CIC + 序列分布扩展特征（p10–p90、偏度、峰度等，272 列）",
    ),
    "seq": FeatureSpec(
        "seq", ("seq", "sequence"), "jsonl", "_seq.log",
        "每流包序列：direction/pkt_len/pay_len/iat_us/tls_type/burst 等",
    ),
    "payload": FeatureSpec(
        "payload", ("payload",), "jsonl", "_payload.log",
        "每流负载十六进制序列（可限包数与截断长度）",
    ),
    "tls": FeatureSpec(
        "tls", ("tls",), "jsonl", "_tls.log",
        "TLS 握手、证书、密码套件、SNI、ALPN 等",
    ),
    "dns": FeatureSpec(
        "dns", ("dns",), "jsonl", "_dns.log",
        "DNS 查询/响应、RCODE、域名列表等",
    ),
    "smtp": FeatureSpec(
        "smtp", ("smtp",), "jsonl", "_smtp.log",
        "SMTP 命令与响应序列",
    ),
    "dhcp": FeatureSpec(
        "dhcp", ("dhcp",), "jsonl", "_dhcp.log",
        "DHCP 消息与选项字段",
    ),
    "ftp": FeatureSpec(
        "ftp", ("ftp",), "jsonl", "_ftp.log",
        "FTP 控制通道命令特征",
    ),
    "http": FeatureSpec(
        "http", ("http",), "jsonl", "_http.log",
        "HTTP/1.x 与 HTTP/2 请求/响应头域与统计",
    ),
    "ssh": FeatureSpec(
        "ssh", ("ssh",), "jsonl", "_ssh.log",
        "SSH Banner、KEX 算法协商与认证元数据",
    ),
    "mqtt": FeatureSpec(
        "mqtt", ("mqtt",), "jsonl", "_mqtt.log",
        "MQTT CONNECT/PUBLISH/SUBSCRIBE 等控制面特征",
    ),
    "sip": FeatureSpec(
        "sip", ("sip",), "jsonl", "_sip.log",
        "SIP 信令、SDP 媒体描述与响应分布",
    ),
    "quic": FeatureSpec(
        "quic", ("quic",), "jsonl", "_quic.log",
        "QUIC 版本、连接 ID 与传输参数",
    ),
    "rdp": FeatureSpec(
        "rdp", ("rdp",), "jsonl", "_rdp.log",
        "RDP 协商、客户端 Core Data 与加密方式",
    ),
    "vnc": FeatureSpec(
        "vnc", ("vnc", "rfb"), "jsonl", "_vnc.log",
        "VNC/RFB 版本、安全类型与桌面参数",
    ),
    "pcap_split": FeatureSpec(
        "pcap_split", ("pcap_split", "split"), "pcap_dir", "_flows",
        "按双向五元组切分为独立 pcap 文件",
    ),
    "vpn": FeatureSpec(
        "vpn", ("vpn",), "log", "_vpn.log",
        "VPN 协议识别（WireGuard/OpenVPN/Shadowsocks/VMess 等）",
    ),
    "im": FeatureSpec(
        "im", ("im",), "log", "_im.log",
        "即时通讯应用/协议识别",
    ),
    "flow": FeatureSpec(
        "flow", ("flow",), "json", "_flow.json",
        "NetFlow v5 / IPFIX / Argus 流特征 JSON",
    ),
}

FEATURE_ALIASES: dict[str, str] = {}
for spec in FEATURE_REGISTRY.values():
    for alias in spec.aliases:
        FEATURE_ALIASES[alias] = spec.name

DEFAULT_BATCH: tuple[str, ...] = ("cic", "cicext", "seq", "payload", "tls", "dns")


def _require_native() -> None:
    if _nv is None:
        raise ImportError(
            "Native extractor module (_wa1kpcap_nvers) is not built. "
            "Install libpcap-dev and libssl-dev, then: pip install -e ."
        ) from _IMPORT_ERROR


def list_features() -> list[FeatureSpec]:
    """Return metadata for all registered native extractors."""
    return list(FEATURE_REGISTRY.values())


def resolve_feature(name: str) -> str:
    """Normalize user feature name to canonical key."""
    key = FEATURE_ALIASES.get(name.lower())
    if key is None:
        known = sorted({s.name for s in FEATURE_REGISTRY.values()} | set(FEATURE_ALIASES))
        raise ValueError(f"Unknown feature {name!r}. Known: {known}")
    return key


def _kind(name: str):
    canonical = resolve_feature(name)
    enum_name = canonical.upper() if canonical != "pcap_split" else "PCAP_SPLIT"
    if canonical == "cicext":
        enum_name = "CICEXT"
    return getattr(_nv.FeatureKind, enum_name)


def default_output_path(pcap: Path, feature: str, output_dir: Path | None = None) -> Path:
    """Compute default output path for a feature."""
    _require_native()
    canonical = resolve_feature(feature)
    base = _nv.default_output_name(_kind(canonical), pcap.stem)
    parent = output_dir if output_dir else pcap.parent
    return parent / base


def _stats_from_result(result, output: Path) -> ExtractStats:
    return ExtractStats(
        exit_code=result.exit_code,
        message=result.message,
        flows=result.flows,
        packets=result.packets,
        elapsed_sec=result.elapsed_sec,
        output_path=output,
    )


def _make_config(
    pcap: Path,
    output: str,
    *,
    n_packets: int,
    workers: int,
    filter_port: int,
    verbose: bool,
) -> object:
    cfg = _nv.ExtractConfig()
    cfg.pcap_path = str(pcap)
    cfg.output_path = output
    cfg.n_limit = n_packets
    cfg.workers = workers
    cfg.filter_port = filter_port
    cfg.verbose = verbose
    return cfg


def extract(
    pcap_path: str | os.PathLike,
    feature: str,
    *,
    output_path: str | os.PathLike | None = None,
    n_packets: int = 0,
    workers: int = 0,
    filter_port: int = 0,
    verbose: bool = False,
    return_stats: bool = False,
) -> Path | tuple[Path, ExtractStats]:
    """
    Run one native extractor and write results to disk.

    Parameters
    ----------
    pcap_path
        Input PCAP/PCAPNG file.
    feature
        Feature name (see ``list_features()``).
    output_path
        Output file or directory. Empty → default next to input pcap.
    n_packets
        Packets per flow to analyze (0 = entire flow).
    workers
        Worker threads for parallel extractors (0 = auto).
    filter_port
        TLS port filter (0 = all TCP).
    verbose
        Extra stderr diagnostics where supported (e.g. DNS).
    return_stats
        If True, return ``(path, ExtractStats)`` instead of just path.
    """
    _require_native()
    pcap = Path(pcap_path).resolve()
    if not pcap.is_file():
        raise FileNotFoundError(pcap)

    out = str(output_path) if output_path else ""
    cfg = _make_config(
        pcap, out,
        n_packets=n_packets, workers=workers,
        filter_port=filter_port, verbose=verbose,
    )

    canonical = resolve_feature(feature)
    result = _nv.run_feature(_kind(canonical), cfg)
    if not result:
        raise RuntimeError(
            f"extract {canonical} failed: {result.message} (code={result.exit_code})"
        )

    path = Path(out) if out else default_output_path(pcap, canonical)
    if return_stats:
        return path, _stats_from_result(result, path)
    return path


def extract_all(
    pcap_path: str | os.PathLike,
    output_dir: str | os.PathLike,
    features: Sequence[str] | None = None,
    *,
    n_packets: int = 0,
    workers: int = 0,
    filter_port: int = 0,
    verbose: bool = False,
    return_stats: bool = False,
) -> dict[str, Path] | tuple[dict[str, Path], ExtractStats]:
    """
    Batch extraction: one PCAP pass per feature type, all in C++.

    Returns mapping ``feature_name → output_path``.
    """
    _require_native()
    pcap = Path(pcap_path).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    names = [resolve_feature(n) for n in (features or DEFAULT_BATCH)]
    kinds = [_kind(n) for n in names]

    cfg = _make_config(
        pcap, str(out_dir),
        n_packets=n_packets, workers=workers,
        filter_port=filter_port, verbose=verbose,
    )

    batch = _nv.run_batch(kinds, cfg)
    if not batch:
        raise RuntimeError(f"batch extract failed: {batch.message}")

    paths = {n: default_output_path(pcap, n, out_dir) for n in names}
    if return_stats:
        stats = ExtractStats(
            exit_code=batch.exit_code,
            message=batch.message,
            flows=batch.flows,
            packets=batch.packets,
            elapsed_sec=batch.elapsed_sec,
            output_path=out_dir,
        )
        return paths, stats
    return paths


def split_pcap(
    pcap_path: str | os.PathLike,
    output_dir: str | os.PathLike | None = None,
    *,
    return_stats: bool = False,
) -> Path | tuple[Path, ExtractStats]:
    """Split PCAP by canonical 5-tuple into per-flow files."""
    return extract(
        pcap_path, "pcap_split",
        output_path=output_dir,
        return_stats=return_stats,
    )


def read_jsonl(path: str | os.PathLike) -> Iterator[dict]:
    """Read JSON Lines produced by seq/payload/protocol extractors."""
    import json
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


# Per-feature shortcuts
def extract_cic(pcap_path, **kwargs):
    return extract(pcap_path, "cic", **kwargs)


def extract_cicext(pcap_path, **kwargs):
    return extract(pcap_path, "cicext", **kwargs)


def extract_seq(pcap_path, **kwargs):
    return extract(pcap_path, "seq", **kwargs)


def extract_payload(pcap_path, **kwargs):
    return extract(pcap_path, "payload", **kwargs)


def extract_tls(pcap_path, **kwargs):
    return extract(pcap_path, "tls", **kwargs)


def extract_dns(pcap_path, **kwargs):
    return extract(pcap_path, "dns", **kwargs)


def extract_smtp(pcap_path, **kwargs):
    return extract(pcap_path, "smtp", **kwargs)


def extract_dhcp(pcap_path, **kwargs):
    return extract(pcap_path, "dhcp", **kwargs)


def extract_ftp(pcap_path, **kwargs):
    return extract(pcap_path, "ftp", **kwargs)


def extract_http(pcap_path, **kwargs):
    return extract(pcap_path, "http", **kwargs)


def extract_ssh(pcap_path, **kwargs):
    return extract(pcap_path, "ssh", **kwargs)


def extract_mqtt(pcap_path, **kwargs):
    return extract(pcap_path, "mqtt", **kwargs)


def extract_sip(pcap_path, **kwargs):
    return extract(pcap_path, "sip", **kwargs)


def extract_quic(pcap_path, **kwargs):
    return extract(pcap_path, "quic", **kwargs)


def extract_rdp(pcap_path, **kwargs):
    return extract(pcap_path, "rdp", **kwargs)


def extract_vnc(pcap_path, **kwargs):
    return extract(pcap_path, "vnc", **kwargs)


def extract_vpn(pcap_path, **kwargs):
    return extract(pcap_path, "vpn", **kwargs)


def extract_im(pcap_path, **kwargs):
    return extract(pcap_path, "im", **kwargs)


def extract_flow(pcap_path, **kwargs):
    return extract(pcap_path, "flow", **kwargs)


from wa1kpcap.extract.unified_seq import extract_unified_seq, canonical_key  # noqa: E402

__all__ = [
    "OutputFormat",
    "FeatureSpec",
    "ExtractStats",
    "FEATURE_REGISTRY",
    "FEATURE_ALIASES",
    "DEFAULT_BATCH",
    "list_features",
    "resolve_feature",
    "default_output_path",
    "extract",
    "extract_all",
    "split_pcap",
    "read_jsonl",
    "extract_cic",
    "extract_cicext",
    "extract_seq",
    "extract_payload",
    "extract_tls",
    "extract_dns",
    "extract_smtp",
    "extract_dhcp",
    "extract_ftp",
    "extract_http",
    "extract_ssh",
    "extract_mqtt",
    "extract_sip",
    "extract_quic",
    "extract_rdp",
    "extract_vnc",
    "extract_vpn",
    "extract_im",
    "extract_flow",
    "extract_unified_seq",
    "canonical_key",
]
