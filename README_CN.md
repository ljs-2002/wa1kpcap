# wa1kpcap

[![PyPI](https://img.shields.io/pypi/v/wa1kpcap?cacheSeconds=60)](https://pypi.org/project/wa1kpcap/)
[![Python](https://img.shields.io/pypi/pyversions/wa1kpcap?cacheSeconds=60)](https://pypi.org/project/wa1kpcap/)
[![License](https://img.shields.io/pypi/l/wa1kpcap?cacheSeconds=60)](https://github.com/ljs-2002/wa1kpcap/blob/main/LICENSE)
[![Tests](https://github.com/ljs-2002/wa1kpcap/actions/workflows/tests.yml/badge.svg)](https://github.com/ljs-2002/wa1kpcap/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/ljs-2002/wa1kpcap/graph/badge.svg?token=WQF6D61HD2)](https://codecov.io/github/ljs-2002/wa1kpcap)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)](https://pypi.org/project/wa1kpcap/)

[English](https://github.com/ljs-2002/wa1kpcap/blob/main/README.md)

高效、易于扩展、开箱即用的 PCAP 分析库。基于 C++ 引擎，从网络流量捕获文件中提取多维度流级特征和各层协议字段。

## 安装

```bash
pip install wa1kpcap
```

可选依赖：

```bash
pip install wa1kpcap[dpkt]      # dpkt 引擎支持
pip install wa1kpcap[export]    # pandas DataFrame 导出
pip install wa1kpcap[crypto]    # TLS 证书解析
pip install wa1kpcap[dev]       # 开发环境（pytest、scapy 等）
```

## 快速开始

```python
from wa1kpcap import Wa1kPcap

analyzer = Wa1kPcap()
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    print(f"{flow.key}  packets={flow.packet_count}  duration={flow.duration:.3f}s")
```

## 支持的协议

| 层级 | 协议 |
|------|------|
| 链路层 | Ethernet, VLAN (802.1Q), Linux SLL/SLL2, Raw IP, BSD Loopback, NFLOG |
| 网络层 | IPv4, IPv6, ARP, ICMP, ICMPv6 |
| 隧道层 | GRE, VXLAN, MPLS |
| 传输层 | TCP, UDP |
| 应用层 | TLS (SNI/ALPN/证书), DNS, HTTP, DHCP, DHCPv6, QUIC (Initial 解密, SNI/ALPN) |

所有协议均有 C++ 快速路径实现。隧道协议（GRE、VXLAN、MPLS）支持递归内层包分发。

## 功能特性

- 快速 C++ 原生解析引擎，提供 Python API，同时支持 dpkt 作为备选引擎（`pip install wa1kpcap[dpkt]`）
- 流级特征提取，带符号方向性包长度
- 每流 8 种序列特征：packet_lengths、ip_lengths、trans_lengths、app_lengths、timestamps、iats、tcp_flags、tcp_window_sizes
- 统计聚合：mean、std、var、min、max、range、median、skew、kurt、cv，以及上行/下行方向性统计
- 从链路层到应用层的多层协议字段提取
- BPF 过滤器，支持协议关键字（dhcp、dhcpv6、vlan、gre、vxlan、mpls）
- 跨包重组：IP 分片、TCP 流、TLS 记录、QUIC CRYPTO 帧
- 导出为 DataFrame、CSV、JSON
- 自定义增量特征注册
- 基于 YAML 的协议扩展，无需编写 C++ 代码即可添加新协议

## 文档

详细用法、API 参考和示例请参阅 [docs/README_CN.md](https://github.com/ljs-2002/wa1kpcap/blob/main/docs/README_CN.md)。

## 路线图

- 更多协议支持（QUIC 0-RTT/Handshake、HTTP/3、SSH、SMTP、SIP 等）
- CLI 命令行工具，快速检查 pcap 文件
- 多进程并行解析，处理大规模抓包文件

## 测试覆盖率

![Coverage](https://codecov.io/github/ljs-2002/wa1kpcap/graphs/tree.svg?token=WQF6D61HD2)

## 许可证

MIT License

## 作者

1in_js
