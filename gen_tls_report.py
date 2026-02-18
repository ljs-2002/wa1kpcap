"""Generate TLS report from multi.pcap comparing wa1kpcap native engine with tshark."""

import subprocess
import sys
from collections import defaultdict

sys.path.insert(0, r"D:\MyProgram\wa1kpcap1")
from wa1kpcap import Wa1kPcap
from wa1kpcap.protocols.application import parse_cert_der

PCAP = r"D:\MyProgram\wa1kpcap1\test\multi.pcap"
TSHARK = r"D:\Program Files\Wireshark\tshark"
OUTPUT = r"D:\MyProgram\wa1kpcap1\tls_report.md"

HANDSHAKE_NAMES = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}


def fmt_hex_list(vals):
    if not vals:
        return ""
    return ", ".join(f"0x{v:04x}" for v in vals)


def fmt_str_list(vals):
    if not vals:
        return ""
    return ", ".join(vals)


def get_cipher_suite_int(cs):
    """Extract int from cipher_suite which may be int or object with .value/.id."""
    if cs is None:
        return None
    if isinstance(cs, int):
        return cs
    for attr in ("value", "id", "code"):
        if hasattr(cs, attr):
            return getattr(cs, attr)
    return int(cs)


# ── 1. wa1kpcap native engine ──────────────────────────────────────────────
print("Analyzing with wa1kpcap native engine...")
analyzer = Wa1kPcap(engine="native")
flows = analyzer.analyze_file(PCAP)

# Collect TLS flows: { flow_label: [ {handshake info}, ... ] }
native_flows = {}  # key -> list of handshake dicts
native_app_data_counts = {}  # key -> count of app_data packets
native_certs = {}  # key -> list of cert dicts (from flow.tls.certificates)

for flow in flows:
    k = flow.key
    label = f"{k.src_ip}:{k.src_port} <-> {k.dst_ip}:{k.dst_port}"

    handshakes = []
    app_data_count = 0

    for p in flow.packets:
        if p.tls is None:
            continue
        t = p.tls
        if t.content_type == 23:
            app_data_count += 1
            continue
        if t.content_type != 22 and not getattr(t, '_handshake_types', None):
            continue

        src_ip = p.ip.src if p.ip else (p.ip6.src if p.ip6 else "?")
        dst_ip = p.ip.dst if p.ip else (p.ip6.dst if p.ip6 else "?")
        sport = p.tcp.sport if p.tcp else 0
        dport = p.tcp.dport if p.tcp else 0

        # Use _handshake_types list (from reassembly splitting) if available
        hs_types = getattr(t, '_handshake_types', None)
        if not hs_types:
            hs_types = [t.handshake_type] if t.handshake_type is not None else []

        for ht in hs_types:
            ht_name = HANDSHAKE_NAMES.get(ht, f"Unknown({ht})")
            info = {
                "src": f"{src_ip}:{sport}",
                "dst": f"{dst_ip}:{dport}",
                "type": ht,
                "type_name": ht_name,
                "sni": list(t.sni) if t.sni else [],
                "cipher_suites": list(t.cipher_suites) if ht == 1 and t.cipher_suites else [],
                "cipher_suite": get_cipher_suite_int(t.cipher_suite) if ht == 2 else None,
                "alpn": list(t.alpn) if t.alpn else [],
                "supported_groups": list(t.supported_groups) if ht == 1 and t.supported_groups else [],
                "signature_algorithms": list(t.signature_algorithms) if ht == 1 and t.signature_algorithms else [],
            }
            handshakes.append(info)

    if handshakes or app_data_count > 0:
        native_flows[label] = handshakes
        native_app_data_counts[label] = app_data_count
        # Collect certificates from flow-level TLS info
        if flow.tls and flow.tls.certificates:
            native_certs[label] = flow.tls.certificates

print(f"  Found {len(native_flows)} TLS flows, "
      f"{sum(len(v) for v in native_flows.values())} handshake messages")

# ── 2. tshark ──────────────────────────────────────────────────────────────
print("Running tshark for comparison...")
cmd = [
    TSHARK, "-r", PCAP,
    "-Y", "tls.handshake",
    "-T", "fields",
    "-e", "tcp.stream",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "tls.handshake.type",
    "-e", "tls.handshake.extensions_server_name",
    "-e", "tls.handshake.ciphersuite",
    "-e", "tls.handshake.extensions_supported_group",
    "-e", "tls.handshake.sig_hash_alg",
    "-e", "tls.handshake.extensions_alpn_str",
    "-E", "separator=|",
]
result = subprocess.run(cmd, capture_output=True, text=True)
tshark_lines = result.stdout.strip().split("\n") if result.stdout.strip() else []

# Parse tshark output into per-flow structure
# tshark groups by tcp.stream; we normalize to src:port <-> dst:port using first packet
tshark_flows = defaultdict(list)  # normalized_label -> list of handshake dicts
stream_labels = {}  # tcp.stream -> normalized label (from first ClientHello)

for line in tshark_lines:
    parts = line.split("|")
    if len(parts) < 11:
        parts += [""] * (11 - len(parts))
    stream, src_ip, dst_ip, sport, dport, hs_types_str, sni, ciphers, groups, sig_algs, alpn = parts

    # Parse handshake types (can be comma-separated like "11,12,14")
    hs_types = [int(x) for x in hs_types_str.split(",") if x.strip()] if hs_types_str.strip() else []

    # Determine flow label from first packet in stream
    if stream not in stream_labels:
        stream_labels[stream] = f"{src_ip}:{sport} <-> {dst_ip}:{dport}"
    label = stream_labels[stream]

    def parse_hex_list(s):
        if not s.strip():
            return []
        return [int(x, 16) if x.startswith("0x") else int(x) for x in s.split(",")]

    def parse_str_list(s):
        if not s.strip():
            return []
        return [x.strip() for x in s.split(",") if x.strip()]

    cipher_list = parse_hex_list(ciphers)
    group_list = parse_hex_list(groups)
    sig_list = parse_hex_list(sig_algs)
    alpn_list = parse_str_list(alpn)
    sni_list = [sni] if sni.strip() else []

    for ht in hs_types:
        info = {
            "src": f"{src_ip}:{sport}",
            "dst": f"{dst_ip}:{dport}",
            "type": ht,
            "type_name": HANDSHAKE_NAMES.get(ht, f"Unknown({ht})"),
            "sni": sni_list,
            "cipher_suites": cipher_list if ht == 1 else [],
            "cipher_suite": cipher_list[0] if ht == 2 and cipher_list else None,
            "alpn": alpn_list,
            "supported_groups": group_list if ht == 1 else [],
            "signature_algorithms": sig_list,
        }
        tshark_flows[label].append(info)

    # If no handshake types but line exists (e.g. Finished with encrypted data), skip
    if not hs_types and hs_types_str.strip() == "":
        pass  # encrypted handshake, skip

print(f"  tshark found {len(tshark_flows)} TLS flows, "
      f"{sum(len(v) for v in tshark_flows.values())} handshake messages")

# ── 3. Comparison ──────────────────────────────────────────────────────────
# For each flow, compare ClientHello and ServerHello fields
comparison_results = []

# Build a mapping from native flows to tshark flows by matching IPs/ports
# Native key format: "A:portA <-> B:portB"
# tshark key format: "A:portA <-> B:portB" (from first packet direction)

def normalize_key(label):
    """Return a frozenset of (ip:port, ip:port) for direction-independent matching."""
    parts = label.split(" <-> ")
    return frozenset(parts)

native_key_map = {normalize_key(k): k for k in native_flows}
tshark_key_map = {normalize_key(k): k for k in tshark_flows}

all_norm_keys = set(native_key_map.keys()) | set(tshark_key_map.keys())

for nk in sorted(all_norm_keys, key=lambda x: sorted(x)):
    n_label = native_key_map.get(nk)
    t_label = tshark_key_map.get(nk)

    display_label = n_label or t_label
    n_hs = native_flows.get(n_label, []) if n_label else []
    t_hs = tshark_flows.get(t_label, []) if t_label else []

    # Compare ClientHello (type=1)
    n_ch = [h for h in n_hs if h["type"] == 1]
    t_ch = [h for h in t_hs if h["type"] == 1]

    # Compare ServerHello (type=2)
    n_sh = [h for h in n_hs if h["type"] == 2]
    t_sh = [h for h in t_hs if h["type"] == 2]

    issues = []

    # Check handshake message counts
    n_types = [h["type"] for h in n_hs]
    t_types = [h["type"] for h in t_hs]
    if sorted(n_types) != sorted(t_types):
        issues.append(f"握手消息类型不一致: native={n_types}, tshark={t_types}")

    # Compare first ClientHello
    if n_ch and t_ch:
        nc, tc = n_ch[0], t_ch[0]
        if nc["sni"] != tc["sni"]:
            issues.append(f"SNI不一致: native={nc['sni']}, tshark={tc['sni']}")
        if nc["cipher_suites"] != tc["cipher_suites"]:
            issues.append(f"cipher_suites不一致: native有{len(nc['cipher_suites'])}个, tshark有{len(tc['cipher_suites'])}个")
        if nc["supported_groups"] != tc["supported_groups"]:
            issues.append(f"supported_groups不一致")
        if nc["signature_algorithms"] != tc["signature_algorithms"]:
            issues.append(f"signature_algorithms不一致")
        if nc["alpn"] != tc["alpn"]:
            issues.append(f"ALPN不一致: native={nc['alpn']}, tshark={tc['alpn']}")

    # Compare first ServerHello
    if n_sh and t_sh:
        ns, ts = n_sh[0], t_sh[0]
        if ns["cipher_suite"] != ts["cipher_suite"]:
            issues.append(f"ServerHello cipher_suite不一致: native=0x{ns['cipher_suite']:04x}, tshark=0x{ts['cipher_suite']:04x}")
        if ns["alpn"] != ts["alpn"]:
            issues.append(f"ServerHello ALPN不一致: native={ns['alpn']}, tshark={ts['alpn']}")

    status = "一致" if not issues else "不一致"
    comparison_results.append((display_label, status, issues))

# ── 4. Write report ────────────────────────────────────────────────────────
print("Writing report...")

lines = []
lines.append("# TLS 分析报告")
lines.append("")
lines.append(f"PCAP 文件: `{PCAP}`")
lines.append("")
lines.append(f"分析引擎: wa1kpcap native + tshark 对比")
lines.append("")
lines.append(f"TLS 流总数 (native): {len(native_flows)}")
lines.append("")

# Per-flow details
lines.append("## 各流详情 (wa1kpcap native 引擎)")
lines.append("")

for i, (label, handshakes) in enumerate(sorted(native_flows.items()), 1):
    app_count = native_app_data_counts.get(label, 0)
    lines.append(f"### 流 {i}: `{label}`")
    lines.append("")
    lines.append(f"握手消息数: {len(handshakes)}, 应用数据包数: {app_count}")
    lines.append("")

    if handshakes:
        lines.append("| # | 方向 | 类型 | 名称 | SNI | Cipher Suites | Cipher Suite | ALPN | Supported Groups | Signature Algorithms |")
        lines.append("|---|------|------|------|-----|---------------|--------------|------|------------------|---------------------|")

        for j, h in enumerate(handshakes, 1):
            direction = f"{h['src']} -> {h['dst']}"
            sni = fmt_str_list(h["sni"]) or "-"
            cs_list = fmt_hex_list(h["cipher_suites"]) or "-"
            cs_single = f"0x{h['cipher_suite']:04x}" if h["cipher_suite"] is not None else "-"
            alpn = fmt_str_list(h["alpn"]) or "-"
            sg = fmt_hex_list(h["supported_groups"]) or "-"
            sa = fmt_hex_list(h["signature_algorithms"]) or "-"

            # Truncate long cipher suite lists for readability
            if len(cs_list) > 80:
                cs_list = cs_list[:77] + "..."

            lines.append(f"| {j} | {direction} | {h['type']} | {h['type_name']} | {sni} | {cs_list} | {cs_single} | {alpn} | {sg} | {sa} |")

        lines.append("")

    # Certificate details
    certs = native_certs.get(label, [])
    if certs:
        lines.append(f"**证书链 ({len(certs)} 张证书):**")
        lines.append("")
        for ci, cert_der in enumerate(certs):
            cert = parse_cert_der(cert_der)
            if not cert:
                lines.append(f"**证书 {ci + 1}:** (解析失败, {len(cert_der)} bytes)")
                lines.append("")
                continue
            subj = cert.get("subject", {})
            iss = cert.get("issuer", {})
            def fmt_dn(d):
                return ", ".join(f"{k}={v}" for k, v in d.items()) if d else "-"
            lines.append(f"**证书 {ci + 1}:**")
            lines.append("")
            lines.append(f"- Subject: `{fmt_dn(subj)}`")
            lines.append(f"- Issuer: `{fmt_dn(iss)}`")
            lines.append(f"- Serial: `{cert.get('serial_number', '-')}`")
            lines.append(f"- Not Before: `{cert.get('not_before', '-')}`")
            lines.append(f"- Not After: `{cert.get('not_after', '-')}`")
            lines.append(f"- SHA-256: `{cert.get('sha256', '-')}`")
            lines.append("")

# Comparison section
lines.append("## Native vs tshark 对比结果")
lines.append("")

match_count = sum(1 for _, s, _ in comparison_results if s == "一致")
total = len(comparison_results)
lines.append(f"总计 {total} 个流, 其中 {match_count} 个一致, {total - match_count} 个不一致。")
lines.append("")

lines.append("| 流 | 结果 | 差异说明 |")
lines.append("|-----|------|---------|")

for label, status, issues in comparison_results:
    issue_text = "; ".join(issues) if issues else "-"
    emoji = "PASS" if status == "一致" else "FAIL"
    lines.append(f"| `{label}` | {emoji} ({status}) | {issue_text} |")

lines.append("")

# Detailed mismatch section if any
mismatches = [(l, s, iss) for l, s, iss in comparison_results if s != "一致"]
if mismatches:
    lines.append("## 不一致详情")
    lines.append("")
    for label, status, issues in mismatches:
        lines.append(f"### `{label}`")
        lines.append("")
        for issue in issues:
            lines.append(f"- {issue}")
        lines.append("")
else:
    lines.append("所有流的 TLS 握手信息在 native 引擎和 tshark 之间完全一致。")
    lines.append("")

report = "\n".join(lines)

with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write(report)

print(f"Report written to {OUTPUT}")
print(f"  {match_count}/{total} flows match between native and tshark")
