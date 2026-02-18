# Add a Built-in Protocol / 添加内置协议

This guide walks through adding a new built-in protocol to wa1kpcap, using **ARP** as a worked example. Built-in protocols get a C++ fast-path for maximum performance.

本指南以 **ARP** 为例，演示如何向 wa1kpcap 添加内置协议。内置协议拥有 C++ 快速路径以获得最佳性能。

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

You need two functions per protocol:

每个协议需要两个函数：

#### 4a. `fast_parse_xxx` — Fast Path / 快速路径

Parses raw bytes directly into the C++ struct. This is the hot path.

直接将原始字节解析到 C++ 结构体。这是热路径。

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

#### 4b. `fill_xxx` — Slow Path / 慢路径

Populates the C++ struct from a YAML-parsed `FieldMap` dict. Used when the fast-path is bypassed.

从 YAML 解析的 `FieldMap` 字典填充 C++ 结构体。在快速路径被跳过时使用。

```cpp
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
```

#### 4c. Wire into Dispatch Loop / 接入分发循环

In `protocol_engine.cpp`, add to the fast-path dispatch:

在 `protocol_engine.cpp` 中，添加到快速路径分发：

```cpp
} else if (current_proto == "arp") {
    fr = fast_parse_arp(cur, remaining, pkt);
    used_fast_path = (fr.bytes_consumed > 0);
}
```

And to the slow-path dispatch:

以及慢路径分发：

```cpp
if (proto_name == "arp") fill_arp(fm, pkt);
```

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

```python
class ARPInfo(ProtocolInfo):
    """ARP message information."""
    __slots__ = ()

    def __init__(self, hw_type=0, proto_type=0, opcode=0,
                 sender_mac="", sender_ip="", target_mac="", target_ip="",
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'hw_type': hw_type, 'proto_type': proto_type, 'opcode': opcode,
                'sender_mac': sender_mac, 'sender_ip': sender_ip,
                'target_mac': target_mac, 'target_ip': target_ip, '_raw': _raw,
            })

    @property
    def opcode(self) -> int: return self._fields.get('opcode', 0)
    @opcode.setter
    def opcode(self, v): self._fields['opcode'] = v

    # ... other properties
```

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

- [ ] `src/cpp/protocol_registry.h` — X-Macro entry / X-Macro 条目
- [ ] `src/cpp/parsed_packet.h` — C++ struct / C++ 结构体
- [ ] `wa1kpcap/native/protocols/xxx.yaml` — YAML definition (if needed) / YAML 定义（如需要）
- [ ] `src/cpp/protocol_engine.h` — Function declarations / 函数声明
- [ ] `src/cpp/protocol_engine.cpp` — `fast_parse_xxx` + `fill_xxx` + dispatch wiring / 快速解析 + 填充 + 分发接入
- [ ] `src/cpp/bindings.cpp` — pybind11 struct binding + property + build helper / pybind11 绑定
- [ ] `wa1kpcap/core/packet.py` — Python Info class + ParsedPacket integration / Python Info 类
- [ ] `wa1kpcap/core/__init__.py` — Export / 导出
- [ ] `wa1kpcap/native/converter.py` — Dict-path handler + `_KNOWN_KEYS` / 字典路径处理
- [ ] Parent protocol YAML `next_protocol` mapping / 父协议 YAML 映射
- [ ] Tests / 测试
- [ ] Build passes / 编译通过
- [ ] All tests pass / 所有测试通过
