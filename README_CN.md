# wa1kpcap

[English](https://github.com/ljs-2002/wa1kpcap/blob/main/README.md)

Python 双引擎 PCAP 分析库。使用原生 C++ 引擎（默认）或 dpkt 作为后备，从网络流量捕获文件中提取流级特征和协议字段。

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
| 应用层 | TLS (SNI/ALPN/证书), DNS, HTTP, DHCP, DHCPv6 |

所有协议均有 C++ 快速路径实现。隧道协议（GRE、VXLAN、MPLS）支持递归内层包分发。

## 功能特性

- 双引擎：原生 C++（默认）或 dpkt 后备
- 流级特征提取，带符号方向长度
- 每流 8 种序列特征：packet_lengths、ip_lengths、trans_lengths、app_lengths、timestamps、iats、tcp_flags、tcp_window_sizes
- 统计聚合：mean、std、var、min、max、range、median、skew、kurt、cv，以及方向性统计
- BPF 过滤器，支持协议关键字（dhcp、dhcpv6、vlan、gre、vxlan、mpls）
- 应用层解析控制：full / port_only / none
- IP/TCP/TLS 重组
- 导出为 DataFrame、CSV、JSON
- 自定义增量特征注册
- 基于 YAML 的协议扩展

## 文档

详细用法、API 参考和示例请参阅 [docs/README_CN.md](https://github.com/ljs-2002/wa1kpcap/blob/main/docs/README_CN.md)。

## 许可证

MIT License

## 作者

1in_js
