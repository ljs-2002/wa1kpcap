# wa1kpcap

[![PyPI](https://img.shields.io/pypi/v/wa1kpcap?cacheSeconds=60)](https://pypi.org/project/wa1kpcap/)
[![Python](https://img.shields.io/pypi/pyversions/wa1kpcap?cacheSeconds=60)](https://pypi.org/project/wa1kpcap/)
[![License](https://img.shields.io/pypi/l/wa1kpcap?cacheSeconds=60)](https://github.com/ShituoMa/wa1kpcap/blob/main/LICENSE)
[![Tests](https://github.com/ShituoMa/wa1kpcap/actions/workflows/tests.yml/badge.svg)](https://github.com/ShituoMa/wa1kpcap/actions/workflows/tests.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)](https://pypi.org/project/wa1kpcap/)

[English](README.md)

高效、易于扩展、开箱即用的 PCAP 分析库。基于 **两套互补的 C++ 管线**，从抓包文件中提取流级特征与各层协议字段：

| 管线 | 模块 | 适用场景 |
|------|------|----------|
| **YAML 协议引擎** | `_wa1kpcap_native` | 自定义协议、QUIC/TLS/DNS 字段解析、流重组 |
| **Native 批量提取器 (nvers)** | `_wa1kpcap_nvers` | CIC/CICext、序列、TLS/DNS/L7 JSONL、VPN/IM、高吞吐离线任务 |

## v0.2.0 更新摘要

- **集成 nvers 提取器** — 全部 libpcap 高性能代码位于 `src/cpp/nvers/`，统一 Python 入口 `wa1kpcap.extract` / `wa1kpcap.protocols`。
- **20 种原生特征** — `extract_all()` 一键批量落盘。
- **L7 协议 JSONL** — HTTP、SSH、MQTT、SIP、QUIC、RDP、VNC（原仅 `.h` 的解析器已接入提取管线）。
- **合并序列** — `extract_unified_seq()` 将 YAML 引擎与 native seq 合并为单一 JSONL，序列字段扁平存放于 `sequences`。
- **移除 dpkt 引擎** — `Wa1kPcap()` 仅保留 native C++ 引擎（详见 [CHANGELOG](CHANGELOG.md)）。

## 安装

```bash
pip install wa1kpcap
```

**Python 3.10–3.13** 且平台有预编译 wheel 时，无需本地编译。

若无匹配 wheel，需安装编译依赖后从源码构建：

```bash
# Debian/Ubuntu
sudo apt install build-essential cmake libpcap-dev libssl-dev
pip install wa1kpcap
```

可选依赖：

```bash
pip install wa1kpcap[export]    # pandas DataFrame 导出
pip install wa1kpcap[crypto]    # TLS 证书解析
pip install wa1kpcap[dev]       # 开发环境（pytest、scapy 等）
```

## 快速开始

### YAML 引擎 — 逐流协议字段

```python
from wa1kpcap import Wa1kPcap

flows = Wa1kPcap().analyze_file("traffic.pcap")
for flow in flows:
    print(flow.key, flow.packet_count, flow.duration)
```

### Native 提取器 — 批量 CIC / TLS / 序列

```python
from wa1kpcap.extract import extract_all, extract

# 默认批量：cic, cicext, seq, payload, tls, dns
paths = extract_all("traffic.pcap", output_dir="out/")

# 单特征
extract("traffic.pcap", "http", output_path="out/http.log")
```

### 合并序列（YAML + native，单文件 JSONL）

```python
from wa1kpcap.extract import extract_unified_seq

path = extract_unified_seq("traffic.pcap", "out/seq_unified.log")
```

完整 API 见 [docs/API_EXTRACT_CN.md](docs/API_EXTRACT_CN.md)。

## Native 特征一览

| 名称 | 输出 | 说明 |
|------|------|------|
| `cic` / `cicext` | CSV | CIC-FlowMeter 80 维 / 扩展 272 维 |
| `seq` / `payload` | JSONL | 包级序列 / 负载十六进制 |
| `tls` / `dns` | JSONL | TLS 握手与证书 / DNS 查询 |
| `smtp` / `dhcp` / `ftp` | JSONL | 邮件、DHCP、FTP 控制通道 |
| `http` / `ssh` / `mqtt` / `sip` / `quic` / `rdp` / `vnc` | JSONL | L7 协议元数据 |
| `vpn` / `im` | log | VPN / 即时通讯识别 |
| `flow` | JSON | NetFlow v5 / IPFIX / Argus |
| `pcap_split` | 目录 | 按五元组切分 pcap |

## 支持的协议（YAML 引擎）

| 层级 | 协议 |
|------|------|
| 链路层 | Ethernet, VLAN (802.1Q), Linux SLL/SLL2, Raw IP, BSD Loopback, NFLOG |
| 网络层 | IPv4, IPv6, ARP, ICMP, ICMPv6 |
| 隧道层 | GRE, VXLAN, MPLS |
| 传输层 | TCP, UDP |
| 应用层 | TLS, DNS, HTTP, DHCP, DHCPv6, QUIC (Initial 解密, SNI/ALPN) |

上述 Native 批量提取器另覆盖 SMTP、FTP、SIP、SSH、MQTT 等 L7 协议。

## 功能特性

- 快速 C++ 原生解析引擎，Python API 友好
- **双管线架构**：YAML 灵活解析 + libpcap 高吞吐提取
- 流级特征，带符号方向性包长度
- 每流 8 种序列特征及完整统计聚合
- BPF 过滤器，支持协议关键字
- 跨包重组：IP 分片、TCP 流、TLS 记录、QUIC CRYPTO 帧
- 导出 DataFrame / CSV / JSON
- YAML 协议扩展，无需为字段布局改动而重编译

## 文档

- [docs/README_CN.md](docs/README_CN.md) — 详细中文文档
- [docs/API_EXTRACT_CN.md](docs/API_EXTRACT_CN.md) — Native 提取 API
- [examples/](examples/) — 示例脚本（`demo_01` … `demo_08`）

## 路线图

- [x] SMTP、SIP、SSH、HTTP 等 L7 native 提取器
- [ ] 原始字节字段遮蔽，降低模型过拟合
- [ ] CLI 命令行快速查看 pcap
- [ ] 单次读包多特征提取（共享 pcap 扫描）

## 许可证

MIT License

## 作者

1in_js · 维护仓库：[ShituoMa/wa1kpcap](https://github.com/ShituoMa/wa1kpcap)
