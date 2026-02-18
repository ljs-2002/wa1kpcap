# YAML Primitives Reference / YAML 原语参考

wa1kpcap uses YAML-driven protocol definitions parsed by the native C++ engine. Each protocol is a `.yaml` file in `wa1kpcap/native/protocols/`.

wa1kpcap 使用 YAML 驱动的协议定义，由原生 C++ 引擎解析。每个协议是 `wa1kpcap/native/protocols/` 下的一个 `.yaml` 文件。

## Protocol File Structure / 协议文件结构

```yaml
name: protocol_name          # unique protocol identifier / 唯一协议标识符
header_size_field: field_name # (optional) dynamic header size / （可选）动态头部大小
total_length_field: field_name # (optional) total PDU length / （可选）PDU 总长度
fields:
  - name: field_name
    type: primitive_type
    # ... primitive-specific parameters
next_protocol:                # (optional) next layer dispatch / （可选）下一层分发
  field: field_name
  mapping:
    value: protocol_name
```

### Special Top-Level Fields / 特殊顶层字段

| Field | Description / 描述 |
|-------|-------------------|
| `header_size_field` | Names a field whose value gives the header length in bytes. The engine uses this to know where the payload starts. / 指定一个字段，其值为头部字节长度。引擎据此确定载荷起始位置。 |
| `total_length_field` | Names a field whose value gives the total PDU length (header + payload). Used to bound parsing. / 指定一个字段，其值为 PDU 总长度（头部+载荷），用于限定解析范围。 |

Example (IPv4): `header_size_field: header_length` + `total_length_field: total_length`

---

## Primitive Types / 原语类型

### 1. `fixed` — Fixed-Size Field / 定长字段

Reads a fixed number of bytes and interprets them according to `format`.

读取固定字节数，按 `format` 解释。

```yaml
- name: src_port
  type: fixed
  size: 2          # bytes to read / 读取字节数
  format: uint     # interpretation format / 解释格式
```

### 2. `bitfield` — Bit-Level Fields / 位域字段

Reads `group_size` bytes and splits them into sub-fields by bit widths. Bits are extracted MSB-first.

读取 `group_size` 字节，按位宽拆分为子字段。高位优先提取。

```yaml
- name: ver_ihl
  type: bitfield
  group_size: 1    # bytes to read / 读取字节数
  fields:
    - name: version
      bits: 4
    - name: ihl
      bits: 4
```

### 3. `length_prefixed` — Length-Prefixed Data / 长度前缀数据

Reads a length prefix of `length_size` bytes, then reads that many bytes of data.

先读取 `length_size` 字节的长度前缀，再读取相应长度的数据。

```yaml
- name: session_id
  type: length_prefixed
  length_size: 1   # bytes for the length prefix / 长度前缀字节数
  format: bytes    # data interpretation / 数据解释格式
```

### 4. `computed` — Computed Field / 计算字段

Evaluates an arithmetic expression over previously parsed fields. Consumes zero bytes.

对已解析字段求算术表达式。不消耗字节。

```yaml
- name: header_length
  type: computed
  expression: ihl * 4
```

Supported operators: `+`, `-`, `*`, `/` (integer division). Operands are field names or integer literals.

支持运算符：`+`、`-`、`*`、`/`（整数除法）。操作数为字段名或整数字面量。

### 5. `counted_list` — Counted Array / 计数数组

Reads `count_field` items, each of `size` bytes, interpreted by `format`. Returns a list.

读取 `count_field` 个元素，每个 `size` 字节，按 `format` 解释。返回列表。

```yaml
- name: cipher_suites
  type: counted_list
  count_field: cipher_suites_count  # field with item count / 元素计数字段
  size: 2                           # bytes per item / 每个元素字节数
  format: uint
```

### 6. `prefixed_list` — TLV / Length-Prefixed Item List / TLV/长度前缀项列表

Reads a list of items from a length-prefixed container. Two modes:

从长度前缀容器中读取项列表。两种模式：

**Mode A — Typed items with sub-protocol dispatch (TLV):**

```yaml
- name: extensions
  type: prefixed_list
  list_length_size: 2    # bytes for total list length / 列表总长度字节数
  type_size: 2           # bytes for item type tag / 项类型标签字节数
  item_length_size: 2    # bytes for item length / 项长度字节数
  type_mapping:           # type value → sub-protocol / 类型值 → 子协议
    0x0000: tls_ext_sni
    0x0010: tls_ext_alpn
```

**Mode B — Simple length-prefixed strings:**

```yaml
- name: protocols
  type: prefixed_list
  list_length_size: 2
  item_length_size: 1
  item_format: string    # each item is a length-prefixed string / 每项为长度前缀字符串
```

### 7. `hardcoded` — Custom C++ Parser / 自定义 C++ 解析器

Delegates parsing to a named C++ function. Used for protocols that cannot be expressed in YAML (e.g., NFLOG with its complex TLV structure).

委托给命名的 C++ 函数解析。用于无法用 YAML 表达的协议（如 NFLOG 的复杂 TLV 结构）。

```yaml
- name: payload
  type: hardcoded
  parser: nflog_payload   # C++ function name / C++ 函数名
```

### 8. `repeat` — Repeated Sub-Protocol / 重复子协议

Repeatedly parses a sub-protocol from the remaining buffer until exhausted. Results are merged into the parent output.

从剩余缓冲区重复解析子协议直到耗尽。结果合并到父输出。

```yaml
- name: records
  type: repeat
  sub_protocol: tls_record   # protocol to repeat / 重复的协议
  merge: tls                 # merge results under this key / 合并结果到此键下
```

---

## Format Types / 格式类型

Used with `fixed`, `length_prefixed`, and `counted_list` primitives.

用于 `fixed`、`length_prefixed` 和 `counted_list` 原语。

| Format | Description / 描述 | Example |
|--------|-------------------|---------|
| `uint` | Unsigned integer (big-endian). Size: 1/2/3/4 bytes. / 无符号整数（大端序）。 | `src_port: 443` |
| `int` | Signed integer (big-endian). / 有符号整数（大端序）。 | `-1` |
| `mac` | 6-byte MAC address → `"aa:bb:cc:dd:ee:ff"`. / 6 字节 MAC 地址。 | `"aa:bb:cc:00:00:01"` |
| `ipv4` | 4-byte IPv4 address → `"192.168.1.1"`. / 4 字节 IPv4 地址。 | `"192.168.1.1"` |
| `ipv6` | 16-byte IPv6 address → `"::1"`. / 16 字节 IPv6 地址。 | `"::1"` |
| `hex` | Raw bytes → hex string `"0a1b2c"`. / 原始字节 → 十六进制字符串。 | `"0a1b2c3d"` |
| `bytes` | Raw bytes (returned as binary). / 原始字节（返回二进制）。 | `b"\x00\x01"` |
| `ascii` / `string` | Raw bytes → UTF-8 string. / 原始字节 → UTF-8 字符串。 | `"h2"` |

---

## Next Protocol Dispatch / 下一层协议分发

### Field-Based Mapping / 基于字段的映射

Routes to the next protocol based on a parsed field value.

根据已解析字段值路由到下一层协议。

```yaml
next_protocol:
  field: ether_type
  mapping:
    0x0800: ipv4
    0x86DD: ipv6
    0x0806: arp
```

### Heuristic Detection / 启发式检测

Routes based on byte-level conditions on the payload. Checked in order; first match wins.

基于载荷的字节级条件路由。按顺序检查，首个匹配生效。

```yaml
next_protocol:
  heuristics:
    - protocol: tls_stream
      min_length: 5
      conditions:
        - offset: 0
          byte_in: [0x14, 0x15, 0x16, 0x17]
        - offset: 1
          byte_eq: 3
        - offset: 2
          byte_le: 4
```

Condition operators: `byte_eq`, `byte_in`, `byte_le`, `byte_ge`.

条件运算符：`byte_eq`、`byte_in`、`byte_le`、`byte_ge`。

---

## Complete Example / 完整示例

A minimal protocol definition (Ethernet):

一个最小协议定义（以太网）：

```yaml
name: ethernet
fields:
  - name: dst
    type: fixed
    size: 6
    format: mac
  - name: src
    type: fixed
    size: 6
    format: mac
  - name: ether_type
    type: fixed
    size: 2
    format: uint

next_protocol:
  field: ether_type
  mapping:
    0x0800: ipv4
    0x86DD: ipv6
    0x0806: arp
    0x8100: vlan
```
