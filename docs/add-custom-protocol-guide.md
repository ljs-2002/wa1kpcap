# Add a Custom Protocol / 添加自定义协议

This guide explains how to add a custom protocol using only YAML and Python — no C++ changes or recompilation needed.

本指南说明如何仅使用 YAML 和 Python 添加自定义协议——无需 C++ 改动或重新编译。

## When to Use This Approach / 何时使用此方式

- The protocol is not performance-critical / 协议非性能关键
- You want typed Python properties beyond raw field access / 需要超越原始字段访问的类型化 Python 属性
- You don't want to modify C++ code / 不想修改 C++ 代码

If you only need field extraction without custom Python logic, a YAML-only protocol (just the `.yaml` file) is sufficient — parsed fields are accessible via `pkt.layers["protocol_name"].fields`.

如果只需字段提取而无需自定义 Python 逻辑，纯 YAML 协议（仅 `.yaml` 文件）即可——解析字段通过 `pkt.layers["protocol_name"].fields` 访问。

## Step-by-Step / 分步指南

### Step 1: Create YAML Protocol Definition / 创建 YAML 协议定义

**File:** `wa1kpcap/native/protocols/my_protocol.yaml`

Define the wire format using YAML primitives (see [yaml-primitives-reference.md](yaml-primitives-reference.md)):

使用 YAML 原语定义线上格式（参见 [yaml-primitives-reference.md](yaml-primitives-reference.md)）：

```yaml
name: my_protocol
fields:
  - name: msg_type
    type: fixed
    size: 1
    format: uint
  - name: msg_length
    type: fixed
    size: 2
    format: uint
  - name: payload
    type: length_prefixed
    length_size: 0        # use msg_length field value
    format: bytes
```

### Step 2: Wire Parent Protocol Dispatch / 接入父协议分发

Edit the parent protocol's YAML to route to your new protocol.

编辑父协议的 YAML 以路由到新协议。

**Example — adding to UDP port-based heuristic:**

```yaml
# In the parent protocol's YAML (e.g., udp.yaml or a custom dispatcher)
next_protocol:
  heuristics:
    - protocol: my_protocol
      min_length: 3
      conditions:
        - offset: 0
          byte_eq: 0x42    # magic byte
```

**Example — adding to a field-based mapping:**

```yaml
next_protocol:
  field: some_type_field
  mapping:
    0x99: my_protocol
```

### Step 3: Create Python Info Class / 创建 Python Info 类

**File:** Create in your project or add to `wa1kpcap/core/packet.py`

```python
from wa1kpcap.core.packet import ProtocolInfo

class MyProtocolInfo(ProtocolInfo):
    """Custom protocol information."""
    __slots__ = ()

    def __init__(self, msg_type=0, msg_length=0, payload=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'msg_type': msg_type,
                'msg_length': msg_length,
                'payload': payload,
            })

    @property
    def msg_type(self) -> int:
        return self._fields.get('msg_type', 0)

    @property
    def msg_length(self) -> int:
        return self._fields.get('msg_length', 0)

    @property
    def payload(self) -> bytes:
        return self._fields.get('payload', b"")

    @property
    def is_request(self) -> bool:
        """Example computed property."""
        return self.msg_type == 1
```

### Step 4: Register the Class / 注册类

Register your class so the engine instantiates it (instead of generic `ProtocolInfo`) when parsing:

注册类，使引擎在解析时实例化它（而非通用 `ProtocolInfo`）：

```python
from wa1kpcap.core.packet import ProtocolRegistry

ProtocolRegistry.get_instance().register("my_protocol", MyProtocolInfo)
```

Call this at module import time (e.g., in your package's `__init__.py`).

在模块导入时调用（如在包的 `__init__.py` 中）。

### Step 5: Use It / 使用

```python
from wa1kpcap import Wa1kPcap

analyzer = Wa1kPcap(engine="native")
flows = analyzer.analyze_file("capture.pcap")

for flow in flows:
    for pkt in flow.packets:
        proto = pkt.layers.get("my_protocol")
        if proto:
            print(f"Type: {proto.msg_type}, Length: {proto.msg_length}")
            print(f"Is request: {proto.is_request}")
```

## How It Works / 工作原理

```
Raw bytes
    │
    ▼
┌──────────────────────┐
│  Native C++ Engine    │
│  YAML slow-path       │
│  Parses fields into   │
│  FieldMap (dict)      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  extra_layers         │
│  (unknown protocols)  │
│  Stored as dicts in   │
│  NativeParsedPacket   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  ParsedPacket.__init__│
│  Looks up             │
│  ProtocolRegistry     │
│  for "my_protocol"    │
│  → MyProtocolInfo()   │
│  Stored in            │
│  pkt.layers[name]     │
└──────────────────────┘
```

The native engine parses the YAML-defined fields into a dict. During `ParsedPacket` construction, it checks `ProtocolRegistry` for a registered class. If found, it instantiates that class with the parsed fields. Otherwise, a generic `ProtocolInfo` is used.

原生引擎将 YAML 定义的字段解析为字典。在 `ParsedPacket` 构造期间，检查 `ProtocolRegistry` 中是否有注册类。若有，则用解析的字段实例化该类；否则使用通用 `ProtocolInfo`。

## Complete Example: QUIC Initial / 完整示例：QUIC Initial

```yaml
# wa1kpcap/native/protocols/quic_initial.yaml
name: quic_initial
fields:
  - name: header_form
    type: bitfield
    group_size: 1
    fields:
      - name: form
        bits: 1
      - name: fixed_bit
        bits: 1
      - name: long_packet_type
        bits: 2
      - name: reserved
        bits: 2
      - name: packet_number_length
        bits: 2
  - name: version
    type: fixed
    size: 4
    format: uint
  - name: dcid
    type: length_prefixed
    length_size: 1
    format: hex
  - name: scid
    type: length_prefixed
    length_size: 1
    format: hex
```

```python
# quic_protocol.py
from wa1kpcap.core.packet import ProtocolInfo, ProtocolRegistry

class QUICInitialInfo(ProtocolInfo):
    __slots__ = ()

    def __init__(self, fields=None, **kwargs):
        super().__init__(fields=fields or {}, **kwargs)

    @property
    def version(self) -> int:
        return self._fields.get('version', 0)

    @property
    def dcid(self) -> str:
        return self._fields.get('dcid', '')

    @property
    def scid(self) -> str:
        return self._fields.get('scid', '')

    @property
    def is_quic_v1(self) -> bool:
        return self.version == 0x00000001

ProtocolRegistry.get_instance().register("quic_initial", QUICInitialInfo)
```

## Checklist / 检查清单

- [ ] `wa1kpcap/native/protocols/xxx.yaml` — YAML protocol definition / YAML 协议定义
- [ ] Parent protocol YAML — `next_protocol` mapping or heuristic / 父协议 YAML 映射
- [ ] Python Info class (extends `ProtocolInfo`) / Python Info 类
- [ ] `ProtocolRegistry.register()` call / 注册调用
- [ ] Tests / 测试
