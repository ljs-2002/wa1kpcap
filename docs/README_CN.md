# wa1kpcap — 详细文档

[English](README.md)

## 目录

1. [安装](#安装)
2. [快速开始](#快速开始)
3. [核心概念](#核心概念)
4. [引擎选择](#引擎选择)
5. [BPF 过滤](#bpf-过滤)
6. [应用层解析控制](#应用层解析控制)
7. [特征提取](#特征提取)
8. [自定义特征](#自定义特征)
9. [协议解析](#协议解析)
10. [数据导出](#数据导出)
11. [API 参考](#api-参考)
12. [支持的 DLT 类型](#支持的-dlt-类型)
13. [项目结构](#项目结构)

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

## 核心概念

### 流（Flow）

**流**是两个端点之间的双向通信，由五元组标识（src_ip、dst_ip、src_port、dst_port、protocol）。创建流的第一个数据包定义"正向"（up）方向。

### 方向

数据包长度使用**带符号值**表示方向：
- **正值** → 正向（客户端到服务器）
- **负值** → 反向（服务器到客户端）

### 详细模式

| 模式 | `verbose_mode` | 行为 |
|------|---------------|------|
| 非详细 | `False`（默认） | 仅聚合流级数据，内存占用低 |
| 详细 | `True` | 存储包级数据，可逐包迭代 |

## 引擎选择

wa1kpcap 提供两种解析引擎：

```python
# 原生 C++ 引擎（默认，更快）
analyzer = Wa1kPcap(engine="native")

# dpkt 引擎（需要 pip install wa1kpcap[dpkt]）
analyzer = Wa1kPcap(engine="dpkt")
```

如果指定 `engine="dpkt"` 但未安装 dpkt，会自动回退到 native 引擎并发出警告。

## BPF 过滤

### 默认过滤器

默认排除 ARP/ICMP/DHCP 数据包：

```python
# 默认: "not arp and not icmp and not icmpv6 and not dhcp and not dhcpv6"
analyzer = Wa1kPcap()

# 禁用默认过滤器
analyzer = Wa1kPcap(default_filter=None)
```

### 自定义 BPF 过滤器

```python
# 标准 BPF 语法
analyzer = Wa1kPcap(bpf_filter="tcp port 443")
analyzer = Wa1kPcap(bpf_filter="host 192.168.1.1 and tcp")
analyzer = Wa1kPcap(bpf_filter="net 10.0.0.0/8")
```

### 协议感知关键字

扩展的 BPF 关键字，支持应用层协议过滤：

```python
analyzer = Wa1kPcap(bpf_filter="not vlan and not gre")
analyzer = Wa1kPcap(bpf_filter="dhcp or dhcpv6")
analyzer = Wa1kPcap(bpf_filter="not vxlan and not mpls")
```

支持的关键字：`dhcp`、`dhcpv6`、`vlan`、`gre`、`vxlan`、`mpls`。

### 过滤器组合

`bpf_filter` 与 `default_filter` 通过 AND 逻辑组合：

```python
# 实际过滤器: "(not arp and not icmp and ...) and (tcp port 443)"
analyzer = Wa1kPcap(bpf_filter="tcp port 443")
```

### 包级过滤

```python
analyzer = Wa1kPcap(
    filter_ack=True,       # 排除纯 ACK 包（无载荷）
    filter_rst=True,       # 排除 RST 包
    filter_retrans=True,   # 排除 TCP 重传（默认: True）
)
```

## 应用层解析控制

控制解析器在传输层之上的解析深度：

```python
# full（默认）：解析所有协议 — TLS 握手、DNS、HTTP 等
analyzer = Wa1kPcap(app_layer_parsing="full")

# port_only：仅按端口号分发，跳过慢路径解析（TLS 握手等）
analyzer = Wa1kPcap(app_layer_parsing="port_only")

# none：仅解析 TCP/UDP 头部，不进行应用层解析
analyzer = Wa1kPcap(app_layer_parsing="none")
```

当只需要流级特征且希望加快处理速度时，使用 `"port_only"` 或 `"none"`。

## 特征提取

### 序列特征

```python
analyzer = Wa1kPcap(compute_statistics=True)
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    if flow.features:
        print(flow.features.packet_lengths)    # 带符号总包长
        print(flow.features.ip_lengths)        # 带符号 IP 层长度
        print(flow.features.trans_lengths)     # 带符号传输层长度
        print(flow.features.app_lengths)       # 带符号应用层载荷长度
        print(flow.features.timestamps)        # 数据包时间戳
        print(flow.features.iats)              # 到达间隔时间
        print(flow.features.tcp_flags)         # 每包 TCP 标志
        print(flow.features.tcp_window_sizes)  # TCP 窗口大小
```

### 统计特征

当 `compute_statistics=True` 时，每个序列会生成完整的统计量：

```python
for flow in flows:
    # 包长统计
    print(f"mean={flow.pkt_mean:.1f}  std={flow.pkt_std:.1f}")
    print(f"min={flow.pkt_min}  max={flow.pkt_max}  range={flow.pkt_range}")
    print(f"median={flow.pkt_median}  skew={flow.pkt_skew:.3f}  kurt={flow.pkt_kurt:.3f}")

    # 方向性统计
    print(f"up: count={flow.pkt_up_count}  mean={flow.pkt_up_mean:.1f}  sum={flow.pkt_up_sum}")
    print(f"down: count={flow.pkt_down_count}  mean={flow.pkt_down_mean:.1f}  sum={flow.pkt_down_sum}")

    # IAT 统计
    print(f"iat mean={flow.iat_mean:.6f}  max={flow.iat_max:.6f}")

    # IP / 传输层 / 应用层 — 同样的模式
    print(f"ip mean={flow.ip_mean:.1f}  trans mean={flow.trans_mean:.1f}  app mean={flow.app_mean:.1f}")
```

### 统计字典

```python
stats = flow.stats
# stats['packet_count']       → int
# stats['total_bytes']        → int
# stats['duration']           → float
# stats['packet_lengths']     → {'mean': ..., 'std': ..., 'min': ..., 'max': ..., ...}
# stats['ip_lengths']         → 同上结构
# stats['trans_lengths']      → 同上结构
# stats['app_lengths']        → 同上结构
# stats['iats']               → 同上结构
# stats['tcp_flags']          → 同上结构
# stats['up_down_pkt_ratio']  → float
# stats['up_down_byte_ratio'] → float
```

每个子字典包含：`mean`、`std`、`var`、`min`、`max`、`range`、`median`、`skew`、`kurt`、`cv`、`sum`、`count`，以及 `up_*` 和 `down_*` 变体。

### 流指标

```python
for flow in flows:
    print(f"总包数: {flow.packet_count}")
    print(f"正向包数: {flow.metrics.up_packet_count}")
    print(f"反向包数: {flow.metrics.down_packet_count}")
    print(f"正向字节: {flow.metrics.up_byte_count}")
    print(f"反向字节: {flow.metrics.down_byte_count}")
    print(f"持续时间: {flow.duration:.3f}s")
```

## 自定义特征

注册自定义增量特征，在分析过程中逐包计算。

```python
from wa1kpcap import Wa1kPcap, Flow
from wa1kpcap.features.registry import BaseIncrementalFeature, FeatureType
from dataclasses import dataclass, field
import numpy as np
import math

@dataclass
class EntropyState:
    values: list[float] = field(default_factory=list)

class PayloadEntropyFeature(BaseIncrementalFeature):
    def __init__(self):
        super().__init__("payload_entropy", FeatureType.SEQUENCE)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['payload_entropy'] = EntropyState()

    def update(self, flow: Flow, pkt) -> None:
        state = flow._feature_state.get('payload_entropy')
        if state is None:
            return
        payload = pkt.payload or b''
        if payload:
            counts = [0] * 256
            for b in payload:
                counts[b] += 1
            n = len(payload)
            entropy = -sum(
                (c / n) * math.log2(c / n) for c in counts if c > 0
            )
            state.values.append(entropy)

    def get_value(self, flow: Flow) -> dict:
        state = flow._feature_state.get('payload_entropy')
        if state is None:
            return {}
        arr = np.array(state.values)
        return {
            'sequence': arr,
            'mean': float(arr.mean()) if len(arr) > 0 else 0.0,
        }

# 使用
analyzer = Wa1kPcap(verbose_mode=True)
analyzer.register_feature('payload_entropy', PayloadEntropyFeature())
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    features = flow.get_features()
    if 'payload_entropy' in features:
        print(f"熵均值: {features['payload_entropy']['mean']:.3f}")
```

要点：
- 继承 `BaseIncrementalFeature`
- 实现 `initialize()`、`update()`、`get_value()`
- 在调用 `analyze_file()` 之前注册
- 通过 `flow.get_features()[name]` 访问结果

## 协议解析

### TLS

SNI、ALPN 和版本信息始终可用。证书详细字段（`subject`、`issuer`、`not_before` 等）需要安装 `pip install wa1kpcap[crypto]`。未安装时，`flow.tls.certificates` 包含原始 DER 字节，可自行解析。

```python
for flow in flows:
    if flow.tls:
        print(f"版本: {flow.tls.version}")
        print(f"SNI: {flow.tls.sni}")
        print(f"ALPN: {flow.tls.alpn}")
        if flow.tls.certificate:
            cert = flow.tls.certificate
            print(f"主题: {cert.get('subject')}")
            print(f"颁发者: {cert.get('issuer')}")
            print(f"有效期: {cert.get('not_before')} - {cert.get('not_after')}")
```

### DNS

```python
for flow in flows:
    if flow.dns:
        print(f"查询: {flow.dns.queries}")
        print(f"响应码: {flow.dns.response_code}")
```

### HTTP

```python
for flow in flows:
    if flow.http:
        print(f"方法: {flow.http.method}")
        print(f"主机: {flow.http.host}")
        print(f"URI: {flow.http.path}")
        print(f"User-Agent: {flow.http.user_agent}")
```

## 数据导出

### DataFrame

```python
from wa1kpcap import to_dataframe

df = to_dataframe(flows)
print(df[['src_ip', 'dst_ip', 'packet_count', 'feature.packet_lengths.mean']].head())
```

### CSV / JSON

```python
from wa1kpcap import to_csv, to_json

to_csv(flows, 'output.csv')
to_json(flows, 'output.json', indent=2)
```

### FlowExporter

```python
from wa1kpcap import FlowExporter

exporter = FlowExporter(include_features=True)
exporter.to_csv(flows, 'output.csv')
exporter.to_json(flows, 'output.json')
exporter.save(flows, 'output.csv')  # 根据扩展名自动检测格式
```

## API 参考

### Wa1kPcap

```python
Wa1kPcap(
    # 引擎
    engine: str = "native",                # "native"（C++）或 "dpkt"

    # 流管理
    udp_timeout: float = 0,                # UDP 流超时（0=不超时）
    tcp_cleanup_timeout: float = 300.0,    # TCP 清理超时（秒）

    # 包过滤
    filter_ack: bool = False,              # 过滤纯 ACK 包
    filter_rst: bool = False,              # 过滤 RST 包
    filter_retrans: bool = True,           # 过滤 TCP 重传
    bpf_filter: str | None = None,         # BPF 过滤表达式
    default_filter: str | None = "not arp and not icmp and not icmpv6 and not dhcp and not dhcpv6",

    # 特征提取
    verbose_mode: bool = False,            # 存储包级数据
    save_raw_bytes: bool = False,          # 保存原始字节
    compute_statistics: bool = True,       # 计算统计特征
    enabled_features: list[str] | None = None,

    # 协议解析
    enable_reassembly: bool = True,        # IP/TCP/TLS 重组
    protocols: list[str] | None = None,    # 限制解析的协议
    app_layer_parsing: str = "full",       # "full"、"port_only" 或 "none"
)
```

方法：
- `analyze_file(pcap_path) -> list[Flow]` — 分析 PCAP/PCAPNG 文件
- `analyze_directory(directory, pattern="*.pcap") -> dict` — 分析目录中所有匹配文件
- `register_feature(name, processor)` — 注册自定义增量特征

### Flow

```python
# 五元组
flow.key.src_ip / dst_ip / src_port / dst_port / protocol

# 时间
flow.start_time / end_time / duration

# 计数
flow.packet_count
flow.metrics.up_packet_count / down_packet_count
flow.metrics.up_byte_count / down_byte_count

# 特征
flow.features                    # FlowFeatures 对象
flow.features.packet_lengths     # numpy 数组（带符号）
flow.features.timestamps         # numpy 数组
flow.features.iats               # numpy 数组
flow.features.tcp_flags          # numpy 数组
flow.features.tcp_window_sizes   # numpy 数组

# 统计属性（快捷属性）
flow.pkt_mean / pkt_std / pkt_var / pkt_min / pkt_max / pkt_range
flow.pkt_median / pkt_skew / pkt_kurt / pkt_cv
flow.pkt_up_mean / pkt_up_std / pkt_up_min / pkt_up_max / pkt_up_sum / pkt_up_count
flow.pkt_down_mean / pkt_down_std / pkt_down_min / pkt_down_max / pkt_down_sum / pkt_down_count
# ip_*、trans_*、app_*、iat_* 同样模式

# 完整统计字典
flow.stats

# 协议信息
flow.tls / flow.dns / flow.http
```

## 支持的 DLT 类型

| DLT | 值 | 描述 |
|-----|---|------|
| DLT_NULL | 0 | BSD Loopback |
| DLT_EN10MB | 1 | Ethernet |
| DLT_RAW | 101 | Raw IP |
| DLT_LOOP | 108 | OpenBSD Loopback |
| DLT_LINUX_SLL | 113 | Linux Cooked Capture v1 |
| DLT_NFLOG | 239 | NFLOG |
| DLT_LINUX_SLL2 | 276 | Linux Cooked Capture v2 |

## 项目结构

```
wa1kpcap/
├── __init__.py              # 公共 API
├── core/
│   ├── analyzer.py          # Wa1kPcap 主类
│   ├── filter.py            # BPF 过滤器编译器
│   ├── flow.py              # Flow、FlowKey、FlowManager
│   ├── packet.py            # ParsedPacket、ProtocolInfo 类
│   └── reader.py            # 多格式 PCAP 读取器
├── native/
│   ├── engine.py            # C++ 引擎 Python 封装
│   ├── converter.py         # Native→Python 类型转换
│   └── protocols/           # YAML 协议定义
├── protocols/
│   ├── base.py              # BaseProtocolHandler
│   ├── registry.py          # 协议处理器注册表
│   ├── link.py              # 链路层（dpkt 引擎）
│   ├── network.py           # IPv4/IPv6（dpkt 引擎）
│   ├── transport.py         # TCP/UDP（dpkt 引擎）
│   └── application.py       # TLS/HTTP/DNS（dpkt 引擎）
├── reassembly/
│   ├── ip_fragment.py       # IP 分片重组
│   ├── tcp_stream.py        # TCP 流重组
│   └── tls_record.py        # TLS 记录重组
├── features/
│   ├── extractor.py         # FeatureExtractor、FlowFeatures
│   └── registry.py          # 特征注册表
└── exporters.py             # DataFrame/CSV/JSON 导出
```
