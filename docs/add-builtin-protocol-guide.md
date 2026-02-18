# Add a Built-in Protocol / 添加内置协议

This guide walks through adding a new built-in protocol to wa1kpcap. Built-in protocols have C++ struct fields on `NativeParsedPacket` and typed Python properties on `ParsedPacket`.

本指南演示如何向 wa1kpcap 添加内置协议。内置协议在 `NativeParsedPacket` 上有 C++ 结构体字段，在 `ParsedPacket` 上有类型化 Python 属性。

## Two Subtypes of Built-in Protocols / 内置协议的两种子类型

Built-in protocols come in two flavors depending on whether they implement a C++ fast-path parser:

内置协议根据是否实现 C++ 快速路径解析器分为两种：

### Type A: Fast-Path Protocol (fast_parse + fill) / 快速路径协议

Has both `fast_parse_xxx()` (parses raw bytes directly) and `fill_xxx()` (populates struct from YAML FieldMap). The fast-path is used in the hot loop for maximum throughput.

同时拥有 `fast_parse_xxx()`（直接解析原始字节）和 `fill_xxx()`（从 YAML FieldMap 填充结构体）。快速路径在热循环中使用以获得最大吞吐量。

**Current fast-path protocols / 当前快速路径协议:** Ethernet, IPv4, IPv6, TCP, UDP, ARP, ICMP, ICMPv6

### Type B: Fill-Only Protocol (fill only) / 仅填充协议

Has only `fill_xxx()` — no `fast_parse_xxx()`. Parsing is always done by the YAML slow-path engine; the fill function just copies parsed fields into the C++ struct for typed access.

仅有 `fill_xxx()`——没有 `fast_parse_xxx()`。解析始终由 YAML 慢路径引擎完成；fill 函数只是将解析后的字段复制到 C++ 结构体以提供类型化访问。

**Current fill-only protocols / 当前仅填充协议:** DNS, TLS (tls_stream, tls_record, tls_handshake, tls_client_hello, tls_server_hello, tls_certificate)

### How to Choose / 如何选择

```
Should I implement fast_parse_xxx?
是否应该实现 fast_parse_xxx？
│
├─ Is the wire format simple and fixed-layout?
│  线上格式是否简单且固定布局？
│  (fixed offsets, no variable-length lists, no compression)
│  （固定偏移、无变长列表、无压缩）
│  │
│  ├─ YES → Type A: Fast-Path
│  │  Examples: Ethernet (14 bytes fixed), ARP (28 bytes fixed),
│  │  ICMP (fixed header), IPv4/IPv6 (fixed header + options),
│  │  TCP/UDP (fixed header)
│  │
│  └─ NO ──┐
│           │
├─ Does parsing require complex logic?
│  解析是否需要复杂逻辑？
│  (domain name compression, TLV extensions, variable sub-layers,
│   counted lists, conditional fields)
│  （域名压缩、TLV 扩展、可变子层、计数列表、条件字段）
│  │
│  ├─ YES → Type B: Fill-Only
│  │  Examples: DNS (name compression, variable RR lists),
│  │  TLS (extensions, handshake sub-types, certificate chains)
│  │
│  └─ NO → Type A if performance matters, Type B otherwise
│          性能重要选 A，否则选 B
```

**Rule of thumb / 经验法则:** If you can parse the protocol with simple pointer arithmetic and fixed offsets in < 50 lines of C++, use fast-path. If you'd need to reimplement what the YAML engine already handles (TLV parsing, counted lists, compression), use fill-only.

如果能用简单的指针运算和固定偏移在 50 行 C++ 以内解析协议，用快速路径。如果需要重新实现 YAML 引擎已有的功能（TLV 解析、计数列表、压缩），用仅填充。

## Prerequisites / 前提条件

- C++ compiler (MSVC / GCC / Clang)
- pybind11 (included in build)
- Understanding of the target protocol's wire format / 了解目标协议的线上格式

## Step-by-Step / 分步指南

### Step 1: Add to X-Macro Registry / 添加到 X-Macro 注册表

**File:** `src/cpp/protocol_registry.h`

Add one line to `BUILTIN_PROTOCOLS`:

```cpp
#define BUILTIN_PROTOCOLS(X) \
    X(Ethernet, eth,   NativeEthernetInfo, "EthernetInfo") \
    ...
    X(ARP,      arp,   NativeARPInfo,      "ARPInfo")      // ← new
```

Parameters: `X(PascalName, snake_name, CppStruct, PyClass)`

| Parameter | Usage / 用途 |
|-----------|-------------|
| `PascalName` | ClassCache field name (e.g. `ARPInfo_cls`) / 类缓存字段名 |
| `snake_name` | Struct field + has-flag in `NativeParsedPacket` (e.g. `arp`, `has_arp`) / 结构体字段名 |
| `CppStruct` | C++ struct type / C++ 结构体类型 |
| `PyClass` | Python class name for import / Python 类名 |

This macro auto-generates:
- `NativeParsedPacket::arp` field + `has_arp` flag (in `parsed_packet.h`)
- ClassCache entry for Python class lookup (in `bindings.cpp`)

此宏自动生成：
- `NativeParsedPacket::arp` 字段 + `has_arp` 标志（在 `parsed_packet.h` 中）
- Python 类查找的 ClassCache 条目（在 `bindings.cpp` 中）

---

### Step 2: Define C++ Struct / 定义 C++ 结构体

**File:** `src/cpp/parsed_packet.h`

Add a struct for the protocol's parsed fields:

```cpp
struct NativeARPInfo {
    uint16_t hw_type = 0;
    uint16_t proto_type = 0;
    uint16_t opcode = 0;
    std::string sender_mac;
    std::string sender_ip;
    std::string target_mac;
    std::string target_ip;
};
```

Guidelines / 准则:
- Use fixed-width types for numeric fields / 数值字段使用定宽类型
- Use `std::string` for addresses, variable-length data / 地址和变长数据使用 `std::string`
- Default-initialize all fields / 所有字段默认初始化

---

### Step 3: Create YAML Protocol File / 创建 YAML 协议文件

**File:** `wa1kpcap/native/protocols/arp.yaml` (if needed for slow-path)

ARP doesn't need a YAML file because it's fully handled by the fast-path. But if your protocol needs YAML slow-path fallback:

ARP 不需要 YAML 文件，因为完全由快速路径处理。但如果你的协议需要 YAML 慢路径回退：

```yaml
name: arp
fields:
  - name: hw_type
    type: fixed
    size: 2
    format: uint
  - name: proto_type
    type: fixed
    size: 2
    format: uint
  # ... etc
```

Also wire the parent protocol's `next_protocol` mapping. For ARP, Ethernet already has:

同时在父协议的 `next_protocol` 映射中添加。对于 ARP，以太网已有：

```yaml
# ethernet.yaml
next_protocol:
  field: ether_type
  mapping:
    0x0806: arp    # ← routes to ARP
```

---

### Step 4: Implement C++ Functions / 实现 C++ 函数

**Files:** `src/cpp/protocol_engine.h` (declarations), `src/cpp/protocol_engine.cpp` (implementations)

The functions you need depend on the protocol subtype:

需要实现的函数取决于协议子类型：

- **Type A (Fast-Path):** `fast_parse_xxx` + `fill_xxx` + register both dispatch tables
- **Type B (Fill-Only):** `fill_xxx` only + register fill dispatch table only

#### 4a. `fast_parse_xxx` — Fast Path (Type A only) / 快速路径（仅 A 类型）

Parses raw bytes directly into the C++ struct. This is the hot path. **Skip this for fill-only protocols.**

直接将原始字节解析到 C++ 结构体。这是热路径。**仅填充协议跳过此步。**

```cpp
// protocol_engine.h — declaration
FastResult fast_parse_arp(const uint8_t* buf, size_t len,
                          NativeParsedPacket& pkt) const;

// protocol_engine.cpp — implementation
ProtocolEngine::FastResult ProtocolEngine::fast_parse_arp(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 28) return {};  // ARP is 28 bytes for IPv4/Ethernet
    pkt.has_arp = true;
    auto& arp = pkt.arp;

    arp.hw_type    = (buf[0] << 8) | buf[1];
    arp.proto_type = (buf[2] << 8) | buf[3];
    // buf[4] = hw_size, buf[5] = proto_size
    arp.opcode     = (buf[6] << 8) | buf[7];
    arp.sender_mac = util::format_mac(buf + 8);
    arp.sender_ip  = util::format_ipv4(buf + 14);
    arp.target_mac = util::format_mac(buf + 18);
    arp.target_ip  = util::format_ipv4(buf + 24);

    return {28, ""};  // {bytes_consumed, next_protocol}
}
```

#### 4b. `fill_xxx` — Slow Path (both types) / 慢路径（两种类型都需要）

Populates the C++ struct from a YAML-parsed `FieldMap` dict. For Type A, used when the fast-path is bypassed. For Type B, this is the only path.

从 YAML 解析的 `FieldMap` 字典填充 C++ 结构体。A 类型在快速路径被跳过时使用；B 类型这是唯一路径。

```cpp
// Type A example (ARP — simple struct fill):
void ProtocolEngine::fill_arp(const FieldMap& fm, NativeParsedPacket& pkt) const {
    pkt.has_arp = true;
    auto& a = pkt.arp;
    a.opcode    = get_int(fm, "opcode");
    a.hw_type   = get_int(fm, "hw_type");
    a.proto_type = get_int(fm, "proto_type");
    a.sender_mac = get_str(fm, "sender_mac");
    a.sender_ip  = get_str(fm, "sender_ip");
    a.target_mac = get_str(fm, "target_mac");
    a.target_ip  = get_str(fm, "target_ip");
}

// Type B example (DNS — fill-only, complex parsing done by YAML engine):
void ProtocolEngine::fill_dns(const FieldMap& fm, NativeParsedPacket& pkt) const {
    pkt.has_dns = true;
    auto& d = pkt.dns;
    d.id       = get_int(fm, "id");
    d.qr       = get_int(fm, "qr");
    d.opcode   = get_int(fm, "opcode");
    // ... YAML engine already handled domain name compression, RR lists, etc.
}
```

#### 4c. Register in Dispatch Tables / 注册到分发表

The engine uses `unordered_map` dispatch tables instead of if-else chains. Register your protocol in the `ProtocolEngine` constructor (`protocol_engine.cpp`):

引擎使用 `unordered_map` 分发表而非 if-else 链。在 `ProtocolEngine` 构造函数（`protocol_engine.cpp`）中注册协议：

**Type A (Fast-Path) — register in both tables:**

```cpp
// In ProtocolEngine::ProtocolEngine() constructor:

// fast_dispatch_: unified signature (buf, len, remaining, pkt)
// Protocols that don't need `remaining` simply ignore it.
fast_dispatch_["arp"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
    return fast_parse_arp(buf, len, pkt);
};

// fill_dispatch_: uses SlowFillContext
fill_dispatch_["arp"] = [this](SlowFillContext& ctx) {
    fill_arp(ctx.pkt, ctx.fields);
};
```

**Type B (Fill-Only) — register in fill table only:**

```cpp
// In ProtocolEngine::ProtocolEngine() constructor:

// No fast_dispatch_ entry — YAML slow-path always handles parsing.
// Only register fill_dispatch_:
fill_dispatch_["dns"] = [this](SlowFillContext& ctx) {
    fill_dns(ctx.pkt, ctx.fields);
};
```

**Note on special cases / 特殊情况说明:**

Some protocols need extra context from `SlowFillContext`. For example, TCP/UDP compute `app_len` from `ctx.remaining - ctx.bytes_consumed`. TLS sub-layers store fields into `ctx.tls_layers` for deferred processing. See existing registrations in the constructor for patterns.

某些协议需要 `SlowFillContext` 中的额外上下文。例如 TCP/UDP 从 `ctx.remaining - ctx.bytes_consumed` 计算 `app_len`。TLS 子层将字段存入 `ctx.tls_layers` 以延迟处理。参见构造函数中的现有注册了解模式。

---

### Step 5: Add pybind11 Bindings / 添加 pybind11 绑定

**File:** `src/cpp/bindings.cpp`

#### 5a. Struct Binding / 结构体绑定

Add before `NativeParsedPacket`:

```cpp
py::class_<NativeARPInfo>(m, "NativeARPInfo")
    .def(py::init<>())
    .def_readwrite("hw_type", &NativeARPInfo::hw_type)
    .def_readwrite("proto_type", &NativeARPInfo::proto_type)
    .def_readwrite("opcode", &NativeARPInfo::opcode)
    .def_readwrite("sender_mac", &NativeARPInfo::sender_mac)
    .def_readwrite("sender_ip", &NativeARPInfo::sender_ip)
    .def_readwrite("target_mac", &NativeARPInfo::target_mac)
    .def_readwrite("target_ip", &NativeARPInfo::target_ip);
```

#### 5b. NativeParsedPacket Property / NativeParsedPacket 属性

Add property accessor (same pattern as other protocols):

```cpp
.def_property("arp",
    [](py::object self_py) -> py::object {
        auto& self = self_py.cast<NativeParsedPacket&>();
        if (!self.has_arp) return py::none();
        return py::cast(&self.arp, py::return_value_policy::reference_internal, self_py);
    },
    [](NativeParsedPacket& self, py::object val) {
        if (val.is_none()) { self.has_arp = false; }
        else { self.arp = val.cast<NativeARPInfo&>(); self.has_arp = true; }
    })
```

#### 5c. `build_dataclass_from_struct` Helper / 构建辅助函数

Add the Python object construction:

```cpp
py::object arp = cc.none;
if (pkt.has_arp) {
    arp = cc.ARPInfo_cls(
        pkt.arp.hw_type, pkt.arp.proto_type, pkt.arp.opcode,
        pkt.arp.sender_mac, pkt.arp.sender_ip,
        pkt.arp.target_mac, pkt.arp.target_ip, cc.empty_bytes);
}
```

Pass `arp` to the `ParsedPacket_cls(...)` constructor call.

将 `arp` 传递给 `ParsedPacket_cls(...)` 构造函数调用。

---

### Step 6: Python Info Class / Python Info 类

**File:** `wa1kpcap/core/packet.py`

Built-in Info classes inherit from `_SlottedInfoBase` (not `ProtocolInfo`) and store fields as direct `__slots__` attributes for performance. The `_SlottedInfoBase` base class provides `copy()`, `merge()`, `get()`, and a `_fields` property (returns a dict view of all slots).

内置 Info 类继承 `_SlottedInfoBase`（而非 `ProtocolInfo`），将字段存储为直接的 `__slots__` 属性以提升性能。`_SlottedInfoBase` 基类提供 `copy()`、`merge()`、`get()` 和 `_fields` 属性（返回所有 slot 的字典视图）。

```python
class ARPInfo(_SlottedInfoBase):
    """ARP message information."""
    __slots__ = ('hw_type', 'proto_type', 'opcode',
                 'sender_mac', 'sender_ip', 'target_mac', 'target_ip', '_raw')
    _SLOT_NAMES = ('hw_type', 'proto_type', 'opcode',
                   'sender_mac', 'sender_ip', 'target_mac', 'target_ip', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, '', '', '', '', b'')

    def __init__(self, hw_type=0, proto_type=0, opcode=0,
                 sender_mac="", sender_ip="", target_mac="", target_ip="",
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.hw_type = fields.get('hw_type', 0)
            self.proto_type = fields.get('proto_type', 0)
            self.opcode = fields.get('opcode', 0)
            self.sender_mac = fields.get('sender_mac', "")
            self.sender_ip = fields.get('sender_ip', "")
            self.target_mac = fields.get('target_mac', "")
            self.target_ip = fields.get('target_ip', "")
            self._raw = fields.get('_raw', b"")
        else:
            self.hw_type = hw_type
            self.proto_type = proto_type
            self.opcode = opcode
            self.sender_mac = sender_mac
            self.sender_ip = sender_ip
            self.target_mac = target_mac
            self.target_ip = target_ip
            self._raw = _raw
```

Key points / 要点:
- `__slots__` lists all field names — no `_fields` dict, no property accessors needed / 列出所有字段名——无需 `_fields` 字典和 property 访问器
- `_SLOT_NAMES` must match `__slots__` (used by `copy()`, `merge()`, `_fields` property) / 必须与 `__slots__` 一致
- `_SLOT_DEFAULTS` provides defaults for `copy()` fallback / 为 `copy()` 回退提供默认值
- `fields=` dict path is required for the converter/custom protocol fallback / `fields=` 字典路径用于转换器/自定义协议回退
- If the protocol needs flow-level aggregation, override `merge(self, other)` / 如需流级聚合，重写 `merge(self, other)`

Also:
- Add to `_PROTO_KEY_TO_LAYER`: `'arp': 'arp'`
- Add `arp=None` parameter to `ParsedPacket.__init__`
- Add `arp` property on `ParsedPacket`
- Export from `wa1kpcap/core/__init__.py`

同时：
- 添加到 `_PROTO_KEY_TO_LAYER`：`'arp': 'arp'`
- 在 `ParsedPacket.__init__` 中添加 `arp=None` 参数
- 在 `ParsedPacket` 上添加 `arp` 属性
- 从 `wa1kpcap/core/__init__.py` 导出

---

### Step 7: Converter Dict Path / 转换器字典路径

**File:** `wa1kpcap/native/converter.py`

Add import and conversion logic:

```python
from wa1kpcap.core.packet import ARPInfo

# In dict_to_parsed_packet():
arp_d = d.get("arp")
if arp_d and isinstance(arp_d, dict):
    pkt.arp = ARPInfo(
        hw_type=arp_d.get("hw_type", 0),
        proto_type=arp_d.get("proto_type", 0),
        opcode=arp_d.get("opcode", 0),
        sender_mac=arp_d.get("sender_mac", ""),
        sender_ip=arp_d.get("sender_ip", ""),
        target_mac=arp_d.get("target_mac", ""),
        target_ip=arp_d.get("target_ip", ""),
    )
```

Add `'arp'` to `_KNOWN_KEYS`.

将 `'arp'` 添加到 `_KNOWN_KEYS`。

---

### Step 8: Build and Test / 编译和测试

```bash
pip install -e . --no-build-isolation
python -m pytest tests/ -x -q
```

Write tests covering:
- Python Info class construction and properties / Python Info 类构造和属性
- Converter dict path / 转换器字典路径
- Native fast-path end-to-end (raw bytes → ParsedPacket) / 原生快速路径端到端
- C++ struct path (`parse_packet_struct`) / C++ 结构体路径

See `tests/test_arp_icmp.py` for a complete example.

参见 `tests/test_arp_icmp.py` 获取完整示例。

---

## Checklist / 检查清单

- [ ] Decide subtype: Type A (fast-path) or Type B (fill-only) / 决定子类型：A 类型（快速路径）或 B 类型（仅填充）
- [ ] `src/cpp/protocol_registry.h` — X-Macro entry / X-Macro 条目
- [ ] `src/cpp/parsed_packet.h` — C++ struct / C++ 结构体
- [ ] `wa1kpcap/native/protocols/xxx.yaml` — YAML definition (required for Type B, optional for Type A) / YAML 定义（B 类型必需，A 类型可选）
- [ ] `src/cpp/protocol_engine.h` — Function declarations / 函数声明
- [ ] `src/cpp/protocol_engine.cpp`:
  - [ ] `fast_parse_xxx` (Type A only) / 快速解析（仅 A 类型）
  - [ ] `fill_xxx` (both types) / 填充（两种类型都需要）
  - [ ] Register in `fast_dispatch_` table in constructor (Type A only) / 注册到 `fast_dispatch_` 分发表（仅 A 类型）
  - [ ] Register in `fill_dispatch_` table in constructor (both types) / 注册到 `fill_dispatch_` 分发表（两种类型都需要）
- [ ] `src/cpp/bindings.cpp` — pybind11 struct binding + property + build helper / pybind11 绑定
- [ ] `wa1kpcap/core/packet.py` — Python Info class (`_SlottedInfoBase` with `__slots__` direct attrs) + ParsedPacket integration / Python Info 类（`_SlottedInfoBase` + `__slots__` 直接属性）
- [ ] `wa1kpcap/core/__init__.py` — Export / 导出
- [ ] `wa1kpcap/native/converter.py` — Dict-path handler + `_KNOWN_KEYS` / 字典路径处理
- [ ] Parent protocol YAML `next_protocol` mapping / 父协议 YAML 映射
- [ ] Tests / 测试
- [ ] Build passes / 编译通过
- [ ] All tests pass / 所有测试通过
