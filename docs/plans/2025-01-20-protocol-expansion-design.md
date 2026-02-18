# Protocol Expansion Design / 协议扩展设计

Date: 2025-01-20

## Overview / 概述

Four tasks to improve protocol extensibility and add new built-in protocols:

1. X-Macro encapsulation for built-in protocol boilerplate / X-Macro 封装内置协议样板代码
2. Documentation + Skills for protocol authoring / 协议编写文档 + Skill
3. TCP/IPv4/IPv6 options raw bytes / TCP/IPv4/IPv6 选项原始字节
4. Built-in ARP, ICMP, ICMPv6 / 内置 ARP、ICMP、ICMPv6

---

## Task 1: X-Macro Encapsulation / X-Macro 封装

### Problem / 问题

Adding a new built-in protocol requires touching 5+ files with repetitive boilerplate:
- `parsed_packet.h`: struct field + `has_xxx` flag
- `bindings.cpp`: ClassCache field + `ensure_ready` import + `build_dataclass_from_struct` construction
- `protocol_engine.cpp`: slow-path dispatch in `parse_packet_struct`

新增内置协议需要在 5+ 个文件中编写重复的样板代码。

### Solution / 方案

Create `src/cpp/protocol_registry.h` with a single X-macro:

```cpp
// X(PascalName, snake_name, CppStruct, PyClass)
#define BUILTIN_PROTOCOLS(X) \
    X(Ethernet, eth,   NativeEthernetInfo, "EthernetInfo") \
    X(IP,       ip,    NativeIPInfo,       "IPInfo")       \
    X(IP6,      ip6,   NativeIP6Info,      "IP6Info")      \
    X(TCP,      tcp,   NativeTCPInfo,      "TCPInfo")      \
    X(UDP,      udp,   NativeUDPInfo,      "UDPInfo")      \
    X(TLS,      tls,   NativeTLSInfo,      "TLSInfo")      \
    X(DNS,      dns,   NativeDNSInfo,      "DNSInfo")      \
    X(ARP,      arp,   NativeARPInfo,      "ARPInfo")      \
    X(ICMP,     icmp,  NativeICMPInfo,     "ICMPInfo")     \
    X(ICMP6,    icmp6, NativeICMP6Info,    "ICMP6Info")
```

**Expansion sites / 展开位置:**

1. `parsed_packet.h` — struct fields + has_flags:
   ```cpp
   #define X_FIELD(P, s, S, Py) S s;
   BUILTIN_PROTOCOLS(X_FIELD)
   #undef X_FIELD
   #define X_HAS(P, s, S, Py) bool has_##s = false;
   BUILTIN_PROTOCOLS(X_HAS)
   #undef X_HAS
   ```

2. `bindings.cpp` — ClassCache fields + ensure_ready:
   ```cpp
   #define X_CLS(P, s, S, Py) py::object P##Info_cls;
   BUILTIN_PROTOCOLS(X_CLS)
   #undef X_CLS
   // in ensure_ready():
   #define X_INIT(P, s, S, Py) P##Info_cls = mod.attr(Py);
   BUILTIN_PROTOCOLS(X_INIT)
   #undef X_INIT
   ```

3. `bindings.cpp` — `build_dataclass_from_struct`: each protocol has unique construction args, so per-protocol `build_xxx()` helper functions are hand-written. The macro generates the `if (pkt.has_xxx) { xxx = build_xxx(pkt, cc); }` dispatch chain.

4. `protocol_engine.cpp` — `parse_packet_struct` slow-path dispatch stays hand-written (each protocol has unique fill logic with different signatures).

**What stays hand-written / 仍需手写的部分:**
- `NativeXxxInfo` struct definition (unique fields per protocol)
- `fill_xxx()` function (unique field mapping)
- `fast_parse_xxx()` function (unique binary parsing)
- `build_xxx()` helper in bindings.cpp (unique Python constructor args)
- Python `XxxInfo` class in packet.py

**Adding a new built-in protocol / 新增内置协议步骤:**
1. Add one line to `BUILTIN_PROTOCOLS` macro
2. Define `NativeXxxInfo` struct in `parsed_packet.h`
3. Write YAML protocol definition
4. Write `fill_xxx()` + optional `fast_parse_xxx()` in `protocol_engine.cpp`
5. Write `build_xxx()` helper in `bindings.cpp`
6. Add Python `XxxInfo` class in `packet.py`
7. Register in `ProtocolRegistry`
8. Wire `converter.py` dict path

---

## Task 2: Documentation + Skills / 文档 + Skill

### File Structure / 文件结构

```
.claude/commands/
  protocol-guide.md            # Overview: routes to the right sub-skill
  add-yaml-protocol.md         # Write a new YAML protocol definition
  add-builtin-protocol.md      # Add a built-in C++ protocol end-to-end
  add-custom-protocol.md       # Add a custom Python-only protocol

docs/
  protocol-overview.md              # Overview: decision tree + links
  yaml-primitives-reference.md      # Full reference of YAML primitives
  add-builtin-protocol-guide.md     # Step-by-step guide for built-in
  add-custom-protocol-guide.md      # Step-by-step guide for custom
```

### Skills (English, in .claude/commands/)

**protocol-guide.md**: Entry point skill. Decision tree:
- Built-in protocol (C++ fast-path) → `/add-builtin-protocol`
- Custom protocol (Python-only) → `/add-custom-protocol`
- YAML definition only → `/add-yaml-protocol`

**add-yaml-protocol.md**: Steps to create a YAML protocol file. References `docs/yaml-primitives-reference.md`.

**add-builtin-protocol.md**: Full checklist: BUILTIN_PROTOCOLS macro → struct → YAML → fill/fast_parse → bindings → Python class → registry → converter → tests. References `docs/add-builtin-protocol-guide.md`.

**add-custom-protocol.md**: YAML + Python class + ProtocolRegistry.register(). No C++ changes. References `docs/add-custom-protocol-guide.md`.

### Docs (Bilingual CN+EN, in docs/)

**protocol-overview.md**: Decision tree, architecture overview, links to sub-docs.

**yaml-primitives-reference.md**: All 10 primitive types (fixed, bitfield, length_prefixed, computed, tlv, counted_list, rest, hardcoded, prefixed_list, repeat). Format types. next_protocol mechanisms. Special fields.

**add-builtin-protocol-guide.md**: Detailed walkthrough with template snippets for each file. Uses ARP as reference example.

**add-custom-protocol-guide.md**: YAML + Python class walkthrough. How extra_layers and ProtocolRegistry work.

---

## Task 3: TCP/IPv4/IPv6 Options Raw Bytes / 选项原始字节

### C++ Struct Changes / 结构体变更

```cpp
struct NativeIPInfo {
    // ... existing fields ...
    std::string options_raw;  // buf[20..ihl*4], raw IP options
};

struct NativeIP6Info {
    // ... existing fields ...
    std::string options_raw;  // all extension headers raw bytes
};

// NativeTCPInfo.options already exists (std::string), just populate it
```

### Fast-Path Implementation / 快速路径实现

**fast_parse_ipv4**: `if (header_length > 20) ip.options_raw.assign(buf+20, header_length-20)`

**fast_parse_tcp**: `if (header_length > 20) tcp.options.assign(buf+20, header_length-20)`

**fast_parse_ipv6 (NEW)**: New fast-path function:
- Parse 40-byte fixed header (version, traffic_class, flow_label, payload_length, next_header, hop_limit, src, dst)
- Walk extension header chain: hop-by-hop(0), routing(43), fragment(44), destination(60), auth(51), esp(50)
  - Each ext header: next_hdr(1) + hdr_len(1) + data(hdr_len*8+6 bytes). Fragment header is fixed 8 bytes.
  - Collect all ext header raw bytes into `options_raw`
  - Update `next_header` to final transport protocol
- Return bytes_consumed = 40 + extension headers length

### Slow-Path / 慢路径

Add `rest` type field to ipv4.yaml and tcp.yaml to capture options bytes. fill_xxx reads from FieldMap.

### Python Side / Python 侧

- `IPInfo`: add `options` property (bytes)
- `IP6Info`: add `options` property (bytes)
- `TCPInfo`: `options` property already exists, just needs population

### bindings.cpp

Pass `options_raw`/`options` as `py::bytes` in constructor calls.

---

## Task 4: ARP + ICMP + ICMPv6

### ARP

**YAML** (`arp.yaml`): 28-byte fixed layout — hw_type(2), proto_type(2), hw_size(1), proto_size(1), opcode(2), sender_mac(6), sender_ip(4), target_mac(6), target_ip(4). No next_protocol (leaf).

**C++ struct**:
```cpp
struct NativeARPInfo {
    int64_t hw_type = 0;
    int64_t proto_type = 0;
    int64_t opcode = 0;
    std::string sender_mac;
    std::string sender_ip;
    std::string target_mac;
    std::string target_ip;
};
```

**Python**: `ARPInfo(ProtocolInfo)` with all fields + `is_request`/`is_reply` computed properties.

**Fast-path**: Yes, 28 bytes fixed.

**Parent wiring**: ethernet.yaml `0x0806: arp` ✓, fast_parse_ethernet `case 0x0806` ✓.

### ICMP

**YAML** (`icmp.yaml`): type(1), code(1), checksum(2), rest_data(rest/bytes). No next_protocol (leaf).

**C++ struct**:
```cpp
struct NativeICMPInfo {
    int64_t type = 0;
    int64_t code = 0;
    int64_t checksum = 0;
    std::string rest_data;  // raw bytes after 4-byte header
};
```

**Python**: Extend existing `ICMPInfo` — add `checksum`, `rest_data` properties. Add `is_echo_request` (type=8), `is_echo_reply` (type=0).

**Fast-path**: Yes, 4 bytes fixed + rest.

**Parent wiring**: ipv4.yaml `1: icmp` ✓, fast_parse_ipv4 `case 1` ✓.

### ICMPv6

**YAML** (`icmpv6.yaml`): Same structure as ICMP — type(1), code(1), checksum(2), rest_data(rest/bytes). No next_protocol (leaf).

**C++ struct**:
```cpp
struct NativeICMP6Info {
    int64_t type = 0;
    int64_t code = 0;
    int64_t checksum = 0;
    std::string rest_data;
};
```

**Python**: New `ICMP6Info(ProtocolInfo)` class. Computed properties: `is_echo_request` (type=128), `is_echo_reply` (type=129), `is_neighbor_solicitation` (type=135), `is_neighbor_advertisement` (type=136).

**Fast-path**: Yes, identical to ICMP.

**Parent wiring**: ipv6.yaml `58: icmpv6` ✓, fast_parse_ipv4 `case 58` ✓, fast_parse_ipv6 (new) will also dispatch.

---

## Implementation Order / 实施顺序

1. **Task 1** (X-Macro) — foundation, must come first
2. **Task 3** (Options) — modifies existing structs, includes new fast_parse_ipv6
3. **Task 4** (ARP/ICMP/ICMPv6) — uses X-Macro pattern, adds new protocols
4. **Task 2** (Docs/Skills) — written last, references final code as examples
