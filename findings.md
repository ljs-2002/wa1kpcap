# Findings

## Info 类架构

两层基类体系（wa1kpcap/core/packet.py）：

- `_ProtocolInfoBase` — 抽象基类，`__slots__ = ()`
- `ProtocolInfo(_ProtocolInfoBase)` — 自定义/YAML 协议用，`__slots__ = ('_fields',)`，数据存 dict
- `_SlottedInfoBase(_ProtocolInfoBase)` — 内置协议用，子类定义 `__slots__` + `_SLOT_NAMES` + `_SLOT_DEFAULTS`

### merge() 方法

用于流聚合时合并多个包的协议信息。

- `_SlottedInfoBase.merge()` — 默认策略：当前字段为 None 时从 other 复制（first-wins）
- `ProtocolInfo.merge()` — 同上，遍历 `_fields` dict
- `TLSInfo.merge()` — 自定义：列表字段追加去重，标量 first-wins，扩展字典合并
- `HTTPInfo.merge()` — 自定义：标量 first-wins，headers 字典合并不覆盖
- `DNSInfo.merge()` — 自定义：标量 first-wins/0→非零，列表追加去重

### 现有内置 Info 类

EthernetInfo, IPInfo, IP6Info, TCPInfo, UDPInfo, ICMPInfo, ARPInfo, ICMP6Info, TLSInfo, HTTPInfo, DNSInfo, VLANInfo, SLLInfo, SLL2Info — 全部继承 `_SlottedInfoBase`

## Skill/文档中 merge 和继承的覆盖情况

| 文件 | merge() | _SlottedInfoBase | __slots__ | _SLOT_NAMES |
|------|---------|------------------|-----------|-------------|
| add-builtin-protocol/SKILL.md | ✅ | ✅ | ✅ | ✅ |
| add-custom-protocol/SKILL.md | ❌ | ❌ | 部分 | ❌ |
| add-yaml-protocol/SKILL.md | ❌ | ❌ | ❌ | ❌ |
| docs/add-custom-protocol-guide.md | ❌ | ❌ | 部分 | ❌ |
| docs/protocol-overview.md | ❌ | ❌ | ❌ | ❌ |

需要补充：custom protocol skill/doc 加 merge 说明；yaml protocol skill 说明通用 ProtocolInfo 的 merge 行为；protocol-overview 加两种 Info 类对比。

## 当前 Analyzer 参数

- `bpf_filter` — 简化 BPF 过滤（tcp/udp/icmp/arp/ip/ipv6/tls/http/dns + host/port + and/or/not）
- `filter_ack`, `filter_rst`, `filter_retrans` — 包级过滤
- `enable_reassembly` — IP/TCP/TLS 重组
- `protocols` — 限制解析的协议集合
- `engine` — "dpkt" 或 "native"
- 无默认过滤器参数，无应用层解析开关

## 应用层协议检测

- TCP → TLS：启发式（tcp.yaml heuristics，检查 content type + version 字节）
- UDP → DNS：端口映射（udp.yaml，port 53）
- 启发式在 `ProtocolEngine::evaluate_heuristics()` 中实现
- 在 `parse_layer()` 中，mapping 未命中时尝试 heuristics

## 现有 YAML 协议文件（23个）

链路层：link_types, ethernet, vlan, linux_sll, linux_sll2, bsd_loopback, raw_ip, nflog
网络层：ipv4, ipv6
传输层：tcp, udp
应用层：dns, tls_stream, tls_record, tls_handshake, tls_client_hello, tls_server_hello, tls_certificate, tls_ext_sni, tls_ext_alpn, tls_ext_supported_groups, tls_ext_signature_algorithms

## GRE/VXLAN/MPLS/DHCP/DHCPv6 支持

当前完全不支持，需要从零实现。

### 协议规格速查

- **GRE** (IP proto 47): 4字节基础头 + 可选字段（checksum/key/sequence），ethertype 路由下层
- **VXLAN** (UDP port 4789): 8字节头（flags + VNI），内层是完整以太网帧
- **MPLS** (ethertype 0x8847/0x8848): 4字节标签栈条目（label/TC/S/TTL），S=1 时到底，下层按首字节版本判断 IPv4/IPv6
- **DHCP** (UDP port 67/68): 基于 BOOTP 格式，236字节固定头 + magic cookie + options TLV
- **DHCPv6** (UDP port 546/547): msg_type(1) + transaction_id(3) + options TLV
