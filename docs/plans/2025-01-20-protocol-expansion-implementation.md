# Protocol Expansion — Implementation Plan / 协议扩展实施计划

Date: 2025-01-20
Design doc: `docs/plans/2025-01-20-protocol-expansion-design.md`

## Execution Order / 执行顺序

4 tasks, 13 steps total. Each step is a buildable+testable checkpoint.

---

## Task 1: X-Macro Encapsulation / X-Macro 封装

### Step 1.1 — Create `protocol_registry.h` + refactor `parsed_packet.h`

**Files:**
- NEW `src/cpp/protocol_registry.h`
- EDIT `src/cpp/parsed_packet.h`

**Actions:**
1. Create `protocol_registry.h` with the `BUILTIN_PROTOCOLS(X)` macro listing all 7 existing protocols:
   ```cpp
   // X(PascalName, snake_name, CppStruct, PyClass)
   #define BUILTIN_PROTOCOLS(X) \
       X(Ethernet, eth,   NativeEthernetInfo, "EthernetInfo") \
       X(IP,       ip,    NativeIPInfo,       "IPInfo")       \
       X(IP6,      ip6,   NativeIP6Info,      "IP6Info")      \
       X(TCP,      tcp,   NativeTCPInfo,      "TCPInfo")      \
       X(UDP,      udp,   NativeUDPInfo,      "UDPInfo")      \
       X(TLS,      tls,   NativeTLSInfo,      "TLSInfo")      \
       X(DNS,      dns,   NativeDNSInfo,      "DNSInfo")
   ```
2. In `parsed_packet.h`, `#include "protocol_registry.h"` and replace the hand-written struct fields + has_flags in `NativeParsedPacket` with macro expansions:
   ```cpp
   // Protocol layers
   #define X_FIELD(P, s, S, Py) S s;
   BUILTIN_PROTOCOLS(X_FIELD)
   #undef X_FIELD

   // Presence flags
   #define X_HAS(P, s, S, Py) bool has_##s = false;
   BUILTIN_PROTOCOLS(X_HAS)
   #undef X_HAS
   ```

**Verify:** Build compiles. All 282 existing tests pass (no behavioral change).

### Step 1.2 — Refactor `bindings.cpp` ClassCache + ensure_ready

**Files:**
- EDIT `src/cpp/bindings.cpp`

**Actions:**
1. Replace hand-written `ClassCache` fields (EthernetInfo_cls, IPInfo_cls, ...) with macro:
   ```cpp
   #define X_CLS(P, s, S, Py) py::object P##Info_cls;
   BUILTIN_PROTOCOLS(X_CLS)
   #undef X_CLS
   ```
2. Replace hand-written `ensure_ready()` imports with macro:
   ```cpp
   #define X_INIT(P, s, S, Py) P##Info_cls = mod.attr(Py);
   BUILTIN_PROTOCOLS(X_INIT)
   #undef X_INIT
   ```
3. In `build_dataclass_from_struct`, keep per-protocol `build_xxx` helpers hand-written (each has unique constructor args), but generate the dispatch chain:
   ```cpp
   // Each build_xxx is a static function: py::object build_xxx(const NativeParsedPacket&, ClassCache&)
   // Dispatch:
   #define X_BUILD(P, s, S, Py) \
       py::object s##_py = cc.none; \
       if (pkt.has_##s) { s##_py = build_##s(pkt, cc); }
   BUILTIN_PROTOCOLS(X_BUILD)
   #undef X_BUILD
   ```
   - Extract existing inline construction code into `build_eth()`, `build_ip()`, `build_ip6()`, `build_tcp()`, `build_udp()`, `build_dns()`, `build_tls()` static functions.

**Verify:** Build compiles. All tests pass. Benchmark shows no regression.

### Step 1.3 — Verify X-Macro end-to-end

**Files:**
- No new files

**Actions:**
1. Run full test suite: `python -m pytest tests/ -x`
2. Run benchmark to confirm no performance regression
3. Verify that adding a dummy protocol entry to `BUILTIN_PROTOCOLS` causes expected compile errors (struct not defined) — confirms the macro is actually being used

**Verify:** All tests green. Performance within 5% of baseline.

---

## Task 3: TCP/IPv4/IPv6 Options / 选项原始字节

> Task 3 before Task 4 because it modifies existing structs and adds `fast_parse_ipv6` which Task 4 needs.

### Step 3.1 — IPv4 + TCP options in C++ structs and fast-path

**Files:**
- EDIT `src/cpp/parsed_packet.h` — add `std::string options_raw` to `NativeIPInfo`
- EDIT `src/cpp/protocol_engine.cpp` — update `fast_parse_ipv4` and `fast_parse_tcp`
- EDIT `src/cpp/protocol_engine.cpp` — update `fill_ipv4` and `fill_tcp` (slow path)
- EDIT `src/cpp/bindings.cpp` — pass options bytes in `build_ip()` and `build_tcp()`

**Actions:**
1. `NativeIPInfo`: add `std::string options_raw;`
2. `fast_parse_ipv4`: after computing `header_length`, if `header_length > 20`:
   ```cpp
   ip.options_raw.assign(reinterpret_cast<const char*>(buf + 20), header_length - 20);
   ```
3. `fast_parse_tcp`: after computing `header_length`, if `header_length > 20`:
   ```cpp
   tcp.options.assign(reinterpret_cast<const char*>(buf + 20), header_length - 20);
   ```
4. `fill_ipv4` slow path: check for `"options_raw"` key in FieldMap, assign to `ip.options_raw`
5. `fill_tcp` slow path: check for `"options"` key in FieldMap, assign to `tcp.options`
6. `build_ip()` in bindings.cpp: pass `py::bytes(pkt.ip.options_raw)` instead of `cc.empty_bytes` for the `_raw` parameter
7. `build_tcp()` in bindings.cpp: pass `py::bytes(pkt.tcp.options)` instead of `cc.empty_bytes` for the `options` parameter

**Python side** (no changes needed — `IPInfo._raw` and `TCPInfo.options` properties already exist and will receive the bytes).

**Verify:** Build + tests pass. Write a unit test that crafts a TCP packet with options (e.g., MSS option) and verifies `pkt.tcp.options` is non-empty bytes.

### Step 3.2 — IPv6 fast-path parser with extension header traversal

**Files:**
- EDIT `src/cpp/parsed_packet.h` — add `std::string options_raw` to `NativeIP6Info`
- EDIT `src/cpp/protocol_engine.h` — declare `fast_parse_ipv6`
- EDIT `src/cpp/protocol_engine.cpp` — implement `fast_parse_ipv6`, wire into `parse_packet_struct` dispatch

**Actions:**
1. `NativeIP6Info`: add `std::string options_raw;`
2. Implement `fast_parse_ipv6`:
   ```cpp
   FastResult fast_parse_ipv6(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
   ```
   Logic:
   - If `len < 40` return `{}`
   - Parse 40-byte fixed header:
     - `version` = (buf[0] >> 4) & 0xF
     - `traffic_class` = ((buf[0] & 0xF) << 4) | ((buf[1] >> 4) & 0xF)
     - `flow_label` = ((buf[1] & 0xF) << 16) | (buf[2] << 8) | buf[3]
     - `payload_length` = (buf[4] << 8) | buf[5]
     - `next_header` = buf[6]
     - `hop_limit` = buf[7]
     - `src` = format_ipv6(buf + 8)
     - `dst` = format_ipv6(buf + 24)
   - Set `pkt.has_ip6 = true`, fill `pkt.ip6` fields, `pkt.ip_len = 40 + payload_length`
   - Walk extension header chain starting at offset 40:
     - Known extension headers: hop-by-hop(0), routing(43), fragment(44), destination(60), auth(51), esp(50)
     - For each: read `next_hdr = buf[offset]`, `hdr_ext_len = buf[offset+1]`
     - Header size = `(hdr_ext_len + 1) * 8` (except fragment = fixed 8 bytes)
     - Append raw bytes `buf[offset..offset+header_size]` to `pkt.ip6.options_raw`
     - Advance offset, update `next_header`
   - Return `{total_bytes_consumed, next_protocol_from_final_next_header}`
3. Add `format_ipv6` utility to `protocol_engine.cpp` (or `util` namespace) if not already present
4. Wire into `parse_packet_struct` dispatch loop:
   ```cpp
   } else if (current_proto == "ipv6") {
       fr = fast_parse_ipv6(cur, remaining, pkt);
       if (fr.bytes_consumed > 0) {
           used_fast_path = true;
           if (static_cast<size_t>(pkt.ip_len) < remaining) {
               remaining = static_cast<size_t>(pkt.ip_len);
           }
       }
   }
   ```
5. `build_ip6()` in bindings.cpp: pass `py::bytes(pkt.ip6.options_raw)` instead of `cc.empty_bytes` for the `_raw` parameter

**Python side:** `IP6Info._raw` property already exists and will receive the extension header bytes.

**Verify:** Build + tests pass. Write unit test with crafted IPv6 packet containing hop-by-hop extension header, verify `pkt.ip6._raw` contains the extension header bytes and `next_header` is the final transport protocol.

### Step 3.3 — converter.py dict-path options support

**Files:**
- EDIT `wa1kpcap/native/converter.py`

**Actions:**
1. In IPv4 section: read `ip.get("options_raw", b"")` and pass to `IPInfo(..., _raw=options_raw)`
2. In TCP section: read `tcp.get("options", b"")` and pass to `TCPInfo(..., options=options_bytes)`
3. In IPv6 section: read `ip6.get("options_raw", b"")` and pass to `IP6Info(..., _raw=options_raw)`

**Verify:** Dict-path tests pass with options populated.

---

## Task 4: ARP + ICMP + ICMPv6 / 新协议

### Step 4.1 — ARP: C++ struct + YAML + fast-path + Python class

**Files:**
- EDIT `src/cpp/parsed_packet.h` — add `NativeARPInfo` struct
- EDIT `src/cpp/protocol_registry.h` — add ARP to `BUILTIN_PROTOCOLS`
- NEW `wa1kpcap/native/protocols/arp.yaml`
- EDIT `src/cpp/protocol_engine.h` — declare `fast_parse_arp`, `fill_arp`
- EDIT `src/cpp/protocol_engine.cpp` — implement `fast_parse_arp`, `fill_arp`, wire dispatch
- EDIT `src/cpp/bindings.cpp` — add `build_arp()` helper
- EDIT `wa1kpcap/core/packet.py` — add `ARPInfo` class, register, add ParsedPacket property
- EDIT `wa1kpcap/native/converter.py` — add ARP dict-path conversion

**C++ struct:**
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

**YAML** (`arp.yaml`):
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
  - name: hw_size
    type: fixed
    size: 1
    format: uint
  - name: proto_size
    type: fixed
    size: 1
    format: uint
  - name: opcode
    type: fixed
    size: 2
    format: uint
  - name: sender_mac
    type: fixed
    size: 6
    format: mac
  - name: sender_ip
    type: fixed
    size: 4
    format: ipv4
  - name: target_mac
    type: fixed
    size: 6
    format: mac
  - name: target_ip
    type: fixed
    size: 4
    format: ipv4
```

**fast_parse_arp:** 28 bytes fixed, straightforward field extraction using `format_mac` and `format_ipv4` utils. No next_protocol (leaf).

**Python `ARPInfo`:**
```python
class ARPInfo(ProtocolInfo):
    __slots__ = ()
    def __init__(self, hw_type=0, proto_type=0, opcode=0,
                 sender_mac="", sender_ip="", target_mac="", target_ip="",
                 _raw=b"", fields: dict | None = None, **kwargs):
        ...
    # Properties: hw_type, proto_type, opcode, sender_mac, sender_ip, target_mac, target_ip
    # Computed: is_request (opcode==1), is_reply (opcode==2)
```

**ParsedPacket:** Add `arp` property → `self.layers.get('arp')`, add to `_PROTO_KEY_TO_LAYER`, add `arp=None` to `__init__`.

**Verify:** Build + tests. Write test crafting Ethernet(0x0806) + ARP bytes, verify all fields parsed correctly via both struct and dict paths.

### Step 4.2 — ICMP: C++ struct + YAML + fast-path + Python class

**Files:**
- EDIT `src/cpp/parsed_packet.h` — add `NativeICMPInfo` struct
- EDIT `src/cpp/protocol_registry.h` — add ICMP to `BUILTIN_PROTOCOLS`
- NEW `wa1kpcap/native/protocols/icmp.yaml`
- EDIT `src/cpp/protocol_engine.h` — declare `fast_parse_icmp`, `fill_icmp`
- EDIT `src/cpp/protocol_engine.cpp` — implement `fast_parse_icmp`, `fill_icmp`, wire dispatch
- EDIT `src/cpp/bindings.cpp` — add `build_icmp()` helper
- EDIT `wa1kpcap/core/packet.py` — extend existing `ICMPInfo` with checksum + rest_data
- EDIT `wa1kpcap/native/converter.py` — add ICMP dict-path conversion

**C++ struct:**
```cpp
struct NativeICMPInfo {
    int64_t type = 0;
    int64_t code = 0;
    int64_t checksum = 0;
    std::string rest_data;  // raw bytes after 4-byte header
};
```

**YAML** (`icmp.yaml`):
```yaml
name: icmp
fields:
  - name: type
    type: fixed
    size: 1
    format: uint
  - name: code
    type: fixed
    size: 1
    format: uint
  - name: checksum
    type: fixed
    size: 2
    format: uint
  - name: rest_data
    type: rest
    format: bytes
```

**fast_parse_icmp:** If `len < 4` return `{}`. Parse type(1), code(1), checksum(2). `rest_data = buf[4..len]`. No next_protocol (leaf).

**Python `ICMPInfo`:** Extend existing class — add `checksum` and `rest_data` properties. Add computed `is_echo_request` (type==8), `is_echo_reply` (type==0).

**Verify:** Build + tests. Craft IPv4(proto=1) + ICMP echo request bytes, verify fields.

### Step 4.3 — ICMPv6: C++ struct + YAML + fast-path + Python class

**Files:**
- EDIT `src/cpp/parsed_packet.h` — add `NativeICMP6Info` struct
- EDIT `src/cpp/protocol_registry.h` — add ICMP6 to `BUILTIN_PROTOCOLS`
- NEW `wa1kpcap/native/protocols/icmpv6.yaml`
- EDIT `src/cpp/protocol_engine.h` — declare `fast_parse_icmpv6`, `fill_icmpv6`
- EDIT `src/cpp/protocol_engine.cpp` — implement `fast_parse_icmpv6`, `fill_icmpv6`, wire dispatch
- EDIT `src/cpp/bindings.cpp` — add `build_icmp6()` helper
- EDIT `wa1kpcap/core/packet.py` — add `ICMP6Info` class, register, add ParsedPacket property
- EDIT `wa1kpcap/native/converter.py` — add ICMPv6 dict-path conversion

**C++ struct:** Same shape as `NativeICMPInfo`.

**YAML** (`icmpv6.yaml`): Same structure as `icmp.yaml`, name = `icmpv6`.

**fast_parse_icmpv6:** Identical logic to `fast_parse_icmp`.

**Python `ICMP6Info`:**
```python
class ICMP6Info(ProtocolInfo):
    __slots__ = ()
    # Properties: type, code, checksum, rest_data
    # Computed: is_echo_request (type==128), is_echo_reply (type==129),
    #           is_neighbor_solicitation (type==135), is_neighbor_advertisement (type==136)
```

**ParsedPacket:** Add `icmp6` property → `self.layers.get('icmpv6')`, add to `_PROTO_KEY_TO_LAYER`.

**Parent wiring:** `ipv6.yaml` already maps `58: icmpv6`. `fast_parse_ipv4` already has `case 58: next = "icmpv6"`. New `fast_parse_ipv6` will also dispatch `58 → "icmpv6"`.

**Verify:** Build + tests. Craft IPv6 + ICMPv6 neighbor solicitation, verify fields.

### Step 4.4 — Integration tests for all new protocols

**Files:**
- NEW `tests/test_new_protocols.py`

**Actions:**
1. Test ARP: craft raw Ethernet+ARP packet bytes, parse via both struct path (NativePipeline) and dict path (converter.py), verify all fields
2. Test ICMP: craft raw Ethernet+IPv4+ICMP echo request, verify type/code/checksum/rest_data
3. Test ICMPv6: craft raw Ethernet+IPv6+ICMPv6 neighbor solicitation, verify fields
4. Test IPv4 options: craft IPv4 packet with options (IHL > 5), verify `ip._raw` contains options bytes
5. Test TCP options: craft TCP packet with MSS option, verify `tcp.options` is populated
6. Test IPv6 extension headers: craft IPv6 with hop-by-hop ext header, verify `ip6._raw` and correct `next_header`
7. Test flow aggregation: verify ARP/ICMP/ICMPv6 packets create flows correctly (FlowManager)

**Verify:** All new + existing tests pass. `python -m pytest tests/ -x`

---

## Task 2: Documentation + Skills / 文档 + Skill

### Step 2.1 — YAML primitives reference doc

**Files:**
- NEW `docs/yaml-primitives-reference.md`

**Content:** Bilingual (CN+EN). Document all primitive types: fixed, bitfield, length_prefixed, computed, tlv, counted_list, rest, hardcoded, prefixed_list, repeat. Format types (uint, int, mac, ipv4, ipv6, hex, bytes, ascii). next_protocol mechanisms (field-based mapping, heuristic). Special fields (total_length_field, header_length_field).

### Step 2.2 — Protocol overview + builtin/custom guides

**Files:**
- NEW `docs/protocol-overview.md`
- NEW `docs/add-builtin-protocol-guide.md`
- NEW `docs/add-custom-protocol-guide.md`

**Content:**
- `protocol-overview.md`: Decision tree (builtin vs custom vs YAML-only), architecture diagram, links
- `add-builtin-protocol-guide.md`: Step-by-step using ARP as worked example. Covers: BUILTIN_PROTOCOLS macro → struct → YAML → fill/fast_parse → bindings build_xxx → Python class → registry → converter → tests
- `add-custom-protocol-guide.md`: YAML + Python class + ProtocolRegistry.register(). No C++ changes needed.

### Step 2.3 — Claude Code skills

**Files:**
- NEW `.claude/commands/protocol-guide.md`
- NEW `.claude/commands/add-yaml-protocol.md`
- NEW `.claude/commands/add-builtin-protocol.md`
- NEW `.claude/commands/add-custom-protocol.md`

**Content:** English. Each skill is a concise prompt template that references the corresponding doc and provides step-by-step instructions for Claude Code to follow.

**Verify:** Skills are invocable via `/protocol-guide`, `/add-yaml-protocol`, `/add-builtin-protocol`, `/add-custom-protocol`.

---

## Summary / 总结

| Step | Task | Key Deliverable | Build? | Test? |
|------|------|----------------|--------|-------|
| 1.1 | X-Macro | `protocol_registry.h` + `parsed_packet.h` refactor | ✓ | ✓ |
| 1.2 | X-Macro | `bindings.cpp` ClassCache + dispatch refactor | ✓ | ✓ |
| 1.3 | X-Macro | Verify no regression | — | ✓ |
| 3.1 | Options | IPv4 + TCP options in fast-path + bindings | ✓ | ✓ |
| 3.2 | Options | `fast_parse_ipv6` with ext header traversal | ✓ | ✓ |
| 3.3 | Options | converter.py dict-path options | — | ✓ |
| 4.1 | New Proto | ARP end-to-end | ✓ | ✓ |
| 4.2 | New Proto | ICMP end-to-end | ✓ | ✓ |
| 4.3 | New Proto | ICMPv6 end-to-end | ✓ | ✓ |
| 4.4 | New Proto | Integration tests | — | ✓ |
| 2.1 | Docs | YAML primitives reference | — | — |
| 2.2 | Docs | Overview + guides | — | — |
| 2.3 | Docs | Claude Code skills | — | — |

Total: 13 steps, each independently verifiable.
