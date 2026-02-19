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
│  ├─ YES → Built-in Protocol (C++ struct + dispatch table + YAML + Python)
│  │        内置协议（C++ 结构体 + 分发表 + YAML + Python）
│  │        → See: docs/add-builtin-protocol-guide.md
│  │        │
│  │        ├─ Simple fixed-layout wire format?
│  │        │  简单固定布局的线上格式？
│  │        │  (fixed offsets, no variable-length lists)
│  │        │  │
│  │        │  ├─ YES → Type A: Fast-Path (fast_parse_xxx + fill_xxx)
│  │        │  │        快速路径（如 Ethernet, ARP, ICMP, TCP, UDP）
│  │        │  │
│  │        │  └─ NO → Type B: Fill-Only (fill_xxx only, YAML parses)
│  │        │          仅填充（如 DNS, TLS 系列）
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
│                            │  │  [Type A only]  │  │ │
│                            │  └───────┬────────┘  │ │
│                            │          │ fallback   │ │
│                            │  ┌───────▼────────┐  │ │
│                            │  │  Slow Path      │  │ │
│                            │  │  (YAML-driven)  │  │ │
│                            │  │  Any protocol   │  │ │
│                            │  │  [Type A+B+all] │  │ │
│                            │  └───────┬────────┘  │ │
│                            │          │            │ │
│                            │  ┌───────▼────────┐  │ │
│                            │  │  Dispatch Tables│  │ │
│                            │  │  unordered_map  │  │ │
│                            │  │  fast_dispatch_ │  │ │
│                            │  │  fill_dispatch_ │  │ │
│                            │  └────────────────┘  │ │
│                            └──────────────────────┘ │
├─────────────────────────────────────────────────────┤
│  ParsedPacket                                       │
│  ├── .eth  (EthernetInfo)    — Type A fast-path     │
│  ├── .ip   (IPInfo)          — Type A fast-path     │
│  ├── .ip6  (IP6Info)         — Type A fast-path     │
│  ├── .tcp  (TCPInfo)         — Type A fast-path     │
│  ├── .udp  (UDPInfo)         — Type A fast-path     │
│  ├── .arp  (ARPInfo)         — Type A fast-path     │
│  ├── .icmp (ICMPInfo)        — Type A fast-path     │
│  ├── .icmp6 (ICMP6Info)      — Type A fast-path     │
│  ├── .dns  (DNSInfo)         — Type B fill-only     │
│  ├── .tls  (TLSInfo)         — Type B fill-only     │
│  └── .layers["custom"]  (ProtocolInfo / custom cls) │
└─────────────────────────────────────────────────────┘
```

## Three Approaches Compared / 三种方式对比

| | YAML-Only / 纯 YAML | Custom Protocol / 自定义协议 | Built-in Protocol / 内置协议 |
|---|---|---|---|
| Files to create / 需创建文件 | 1 YAML | 1 YAML + 1 Python class | YAML + C++ struct + C++ functions + Python class + bindings |
| C++ changes / C++ 改动 | None / 无 | None / 无 | Yes / 是 |
| Rebuild required / 需重新编译 | No / 否 | No / 否 | Yes / 是 |
| Parent YAML edit / 编辑父 YAML | Yes or `routing` param / 是或 `routing` 参数 | No (`routing` param) / 否（`routing` 参数） | Yes / 是 |
| Access pattern / 访问方式 | `pkt.layers["name"]` | `pkt.layers["name"]` | `pkt.protocol_name` (typed property) |
| Performance / 性能 | Good (YAML slow-path) | Good (YAML slow-path) | Best (Type A: C++ fast-path) / Good (Type B: YAML + fill) |
| Use case / 适用场景 | Quick field extraction / 快速字段提取 | Need Python properties / 需要 Python 属性 | Core protocols, high throughput / 核心协议，高吞吐 |

## Built-in Protocol Subtypes / 内置协议子类型

| | Type A: Fast-Path / 快速路径 | Type B: Fill-Only / 仅填充 |
|---|---|---|
| C++ functions / C++ 函数 | `fast_parse_xxx` + `fill_xxx` | `fill_xxx` only |
| Dispatch tables / 分发表 | `fast_dispatch_` + `fill_dispatch_` | `fill_dispatch_` only |
| Parsing / 解析 | C++ direct byte parsing (hot path) | YAML engine (slow path) |
| YAML file / YAML 文件 | Optional (slow-path fallback) | Required (primary parser) |
| Best for / 适用于 | Simple fixed-layout formats / 简单固定布局 | Complex variable formats / 复杂可变格式 |
| Examples / 示例 | Ethernet, IPv4, TCP, UDP, ARP, ICMP | DNS, TLS series |

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

### Dispatch Tables / 分发表

The C++ engine uses `unordered_map` dispatch tables (populated in the `ProtocolEngine` constructor) instead of if-else chains:

C++ 引擎使用 `unordered_map` 分发表（在 `ProtocolEngine` 构造函数中填充）而非 if-else 链：

- `fast_dispatch_`: maps protocol name → fast-path parser function (Type A protocols only)
- `fill_dispatch_`: maps protocol name → fill function (both Type A and Type B protocols)

New built-in protocols register into these tables by adding lambdas in the constructor. See `src/cpp/protocol_engine.cpp` for examples.

新的内置协议通过在构造函数中添加 lambda 注册到这些表中。参见 `src/cpp/protocol_engine.cpp` 中的示例。

### ProtocolRegistry (Python) / 协议注册表（Python）

Custom Python protocol classes are registered via:

自定义 Python 协议类通过以下方式注册：

```python
from wa1kpcap.core.packet import ProtocolRegistry

ProtocolRegistry.get_instance().register(
    "my_proto",
    MyProtoInfo,
    yaml_path="/path/to/my_proto.yaml",       # optional: extra YAML file to load
    routing={"udp": {5000: "my_proto"}},       # optional: inject next_protocol mappings
)
```

- `yaml_path`: Loaded by `NativeParser.load_extra_file()` at engine init. Use when the YAML file is outside the default `wa1kpcap/native/protocols/` directory.
- `routing`: Injected via `NativeParser.add_protocol_routing()` at engine init. Format: `{parent_proto: {value: target_proto}}`. Eliminates the need to edit built-in YAML files.

- `yaml_path`：引擎初始化时由 `NativeParser.load_extra_file()` 加载。当 YAML 文件不在默认目录时使用。
- `routing`：引擎初始化时由 `NativeParser.add_protocol_routing()` 注入。格式：`{父协议名: {值: 目标协议名}}`。无需编辑内置 YAML 文件。

All fast-path parsers (ethernet, ipv4, ipv6, tcp, udp, vlan, sll, sll2) have YAML fallback: when the hardcoded switch doesn't match, they query the YAML `next_protocol.mapping`. This means injected routing works for both fast-path and slow-path protocols.

所有快速路径解析器（ethernet、ipv4、ipv6、tcp、udp、vlan、sll、sll2）均有 YAML 回退：当硬编码 switch 不匹配时，会查询 YAML 的 `next_protocol.mapping`。因此注入的路由对快速路径和慢速路径协议均有效。

When the native engine parses an unknown protocol via YAML, it looks up the registry to instantiate the correct Python class. If not registered, a generic `ProtocolInfo` is used.

当原生引擎通过 YAML 解析未知协议时，会查找注册表以实例化正确的 Python 类。若未注册，则使用通用 `ProtocolInfo`。

## Info Class Architecture / Info 类架构

Two base classes for protocol info objects, optimized for different use cases:

两种协议信息对象基类，针对不同场景优化：

```
_ProtocolInfoBase          (abstract, __slots__ = ())
├── ProtocolInfo           (custom/YAML protocols, _fields dict)
└── _SlottedInfoBase       (built-in protocols, direct __slots__ attributes)
```

| | `ProtocolInfo` | `_SlottedInfoBase` |
|---|---|---|
| Used by / 使用者 | Custom & YAML-only protocols / 自定义和纯 YAML 协议 | Built-in protocols / 内置协议 |
| Storage / 存储 | `_fields` dict | Direct `__slots__` attributes / 直接 `__slots__` 属性 |
| Subclass requires / 子类需要 | `__slots__ = ()` | `__slots__`, `_SLOT_NAMES`, `_SLOT_DEFAULTS` tuples |
| Performance / 性能 | Good | ~40% faster attribute access / 属性访问快约 40% |

### Flow Aggregation: merge() / 流聚合：merge()

When multiple packets belong to the same flow, their protocol info is merged via `merge(self, other)`. Both base classes provide a default implementation (first-wins: copy from `other` if current value is `None`).

当多个包属于同一流时，通过 `merge(self, other)` 合并协议信息。两个基类都提供默认实现（first-wins：当前值为 None 时从 other 复制）。

Override `merge()` when your protocol needs special aggregation logic:

当协议需要特殊聚合逻辑时，覆写 `merge()`：

- List fields: append unique items (e.g., DNS queries/answers) / 列表字段：追加不重复元素
- Dict fields: merge keys without overwriting (e.g., HTTP headers) / 字典字段：合并键不覆盖
- Accumulation: combine values across packets (e.g., TLS handshake types) / 累积：跨包合并值

Examples: `TLSInfo.merge()`, `HTTPInfo.merge()`, `DNSInfo.merge()` in `wa1kpcap/core/packet.py`.

示例：`wa1kpcap/core/packet.py` 中的 `TLSInfo.merge()`、`HTTPInfo.merge()`、`DNSInfo.merge()`。

## Related Docs / 相关文档

- [YAML Primitives Reference / YAML 原语参考](yaml-primitives-reference.md)
- [Add a Built-in Protocol / 添加内置协议](add-builtin-protocol-guide.md)
- [Add a Custom Protocol / 添加自定义协议](add-custom-protocol-guide.md)
