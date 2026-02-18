# Protocol System Overview / 协议系统概览

wa1kpcap supports three ways to add protocol support, each with different trade-offs.

wa1kpcap 支持三种添加协议的方式，各有不同的权衡。

## Decision Tree / 决策树

```
Need to add a new protocol?
需要添加新协议？
│
├─ Is it performance-critical (millions of packets)?
│  是否性能关键（百万级数据包）？
│  │
│  ├─ YES → Built-in Protocol (C++ fast-path + YAML + Python)
│  │        内置协议（C++ 快速路径 + YAML + Python）
│  │        → See: docs/add-builtin-protocol-guide.md
│  │
│  └─ NO ──┐
│           │
├─ Do you need custom Python logic (validation, computed properties)?
│  是否需要自定义 Python 逻辑（校验、计算属性）？
│  │
│  ├─ YES → Custom Protocol (YAML + Python class)
│  │        自定义协议（YAML + Python 类）
│  │        → See: docs/add-custom-protocol-guide.md
│  │
│  └─ NO → YAML-Only Protocol (just a .yaml file)
│          纯 YAML 协议（仅需一个 .yaml 文件）
│          → See: docs/yaml-primitives-reference.md
```

## Architecture / 架构

```
┌─────────────────────────────────────────────────────┐
│                    Wa1kPcap API                      │
│              (analyzer.py / Flow / etc.)             │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐          ┌──────────────────────┐ │
│  │  dpkt Engine  │          │   Native C++ Engine  │ │
│  │  (fallback)   │          │   (primary)          │ │
│  └──────────────┘          │                      │ │
│                            │  ┌────────────────┐  │ │
│                            │  │  Fast Path      │  │ │
│                            │  │  (C++ structs)  │  │ │
│                            │  │  ETH/IP/TCP/..  │  │ │
│                            │  └───────┬────────┘  │ │
│                            │          │ fallback   │ │
│                            │  ┌───────▼────────┐  │ │
│                            │  │  Slow Path      │  │ │
│                            │  │  (YAML-driven)  │  │ │
│                            │  │  Any protocol   │  │ │
│                            │  └────────────────┘  │ │
│                            └──────────────────────┘ │
├─────────────────────────────────────────────────────┤
│  ParsedPacket                                       │
│  ├── .eth  (EthernetInfo)                           │
│  ├── .ip   (IPInfo)     .ip6  (IP6Info)             │
│  ├── .tcp  (TCPInfo)    .udp  (UDPInfo)             │
│  ├── .icmp (ICMPInfo)   .icmp6 (ICMP6Info)          │
│  ├── .arp  (ARPInfo)                                │
│  ├── .tls  (TLSInfo)    .dns  (DNSInfo)             │
│  └── .layers["custom"]  (ProtocolInfo / custom cls) │
└─────────────────────────────────────────────────────┘
```

## Three Approaches Compared / 三种方式对比

| | YAML-Only / 纯 YAML | Custom Protocol / 自定义协议 | Built-in Protocol / 内置协议 |
|---|---|---|---|
| Files to create / 需创建文件 | 1 YAML | 1 YAML + 1 Python class | YAML + C++ struct + C++ functions + Python class + bindings |
| C++ changes / C++ 改动 | None / 无 | None / 无 | Yes / 是 |
| Rebuild required / 需重新编译 | No / 否 | No / 否 | Yes / 是 |
| Access pattern / 访问方式 | `pkt.layers["name"]` | `pkt.layers["name"]` | `pkt.protocol_name` (typed property) |
| Performance / 性能 | Good (YAML slow-path) | Good (YAML slow-path) | Best (C++ fast-path) |
| Use case / 适用场景 | Quick field extraction / 快速字段提取 | Need Python properties / 需要 Python 属性 | Core protocols, high throughput / 核心协议，高吞吐 |

## Key Concepts / 关键概念

### X-Macro Protocol Registry / X-Macro 协议注册表

All built-in protocols are registered in `src/cpp/protocol_registry.h` via a single macro:

所有内置协议通过单一宏注册在 `src/cpp/protocol_registry.h` 中：

```cpp
#define BUILTIN_PROTOCOLS(X) \
    X(Ethernet, eth,   NativeEthernetInfo, "EthernetInfo") \
    X(IP,       ip,    NativeIPInfo,       "IPInfo")       \
    X(TCP,      tcp,   NativeTCPInfo,      "TCPInfo")      \
    ...
```

This macro is expanded in `parsed_packet.h` (struct fields + has-flags) and `bindings.cpp` (Python class cache).

该宏在 `parsed_packet.h`（结构体字段 + has 标志）和 `bindings.cpp`（Python 类缓存）中展开。

### ProtocolRegistry (Python) / 协议注册表（Python）

Custom Python protocol classes are registered via:

自定义 Python 协议类通过以下方式注册：

```python
from wa1kpcap.core.packet import ProtocolRegistry
ProtocolRegistry.get_instance().register("my_proto", MyProtoInfo)
```

When the native engine parses an unknown protocol via YAML, it looks up the registry to instantiate the correct Python class. If not registered, a generic `ProtocolInfo` is used.

当原生引擎通过 YAML 解析未知协议时，会查找注册表以实例化正确的 Python 类。若未注册，则使用通用 `ProtocolInfo`。

## Related Docs / 相关文档

- [YAML Primitives Reference / YAML 原语参考](yaml-primitives-reference.md)
- [Add a Built-in Protocol / 添加内置协议](add-builtin-protocol-guide.md)
- [Add a Custom Protocol / 添加自定义协议](add-custom-protocol-guide.md)
