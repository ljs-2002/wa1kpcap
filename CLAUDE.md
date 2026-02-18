# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment

- Conda environment: `web` (Python 3.10). If the active conda env is `base`, run `conda activate web` first.
- Python executable: `D:/miniconda3/envs/web/python.exe`
- Platform: Windows 11, but shell commands use Unix syntax (bash).

## Language

  - Respond in Chinese (中文) for explanatory, discussion, or conversational replies.
  - Internal thinking, code, comments, and commit messages can remain in English.

## Build & Install

The project uses scikit-build-core with CMake for the optional C++ native engine.

```bash
# Install Python package (dpkt engine only)
"D:/miniconda3/envs/web/python.exe" -m pip install -e .

# Install with native C++ engine
rm -rf build/cp310-cp310-win_amd64/*
"D:/miniconda3/envs/web/python.exe" -m pip install ".[native]" --force-reinstall --no-deps --no-cache-dir

# After native build, copy .pyd into source tree (editable install doesn't trigger C++ rebuild)
cp "/d/miniconda3/envs/web/Lib/site-packages/wa1kpcap/_wa1kpcap_native.cp310-win_amd64.pyd" "/d/MyProgram/wa1kpcap1/wa1kpcap/"
```

The C++ build requires CMake 3.15+, C++17, and fetches yaml-cpp 0.8.0 via FetchContent. pybind11 provides the Python bindings.

### MSVC Build Quirks

- `NOMINMAX` must be defined before any Windows headers to prevent `min`/`max` macro conflicts with STL and pybind11. `bindings.cpp` also `#undef`s leaked macros and provides `dabs()`/`dmax()` replacements.
- Use `Py_ssize_t` instead of `ssize_t` (not available on MSVC).
- `src/cpp/CMakeLists.txt` sets `CMAKE_POLICY_VERSION_MINIMUM 3.5` to allow yaml-cpp 0.8.0's old `cmake_minimum_required` to work under CMake 4.0+.

## Tests

```bash
# Run all tests
"D:/miniconda3/envs/web/python.exe" -m pytest tests/ -x -q

# Run a single test file
"D:/miniconda3/envs/web/python.exe" -m pytest tests/test_flow.py -x -q

# Run a specific test
"D:/miniconda3/envs/web/python.exe" -m pytest tests/test_flow.py::TestFlowManager::test_add_packet -x -q

# Benchmark dpkt vs native consistency
"D:/miniconda3/envs/web/python.exe" benchmark.py
```

Coverage threshold is 80%. There are ~285 tests across 17 test files.

## Architecture

### Dual Engine Design

The library has two independent parsing engines selected via `Wa1kPcap(engine="dpkt"|"native")`:

- **dpkt engine** (default): Uses the dpkt library for protocol parsing. Code path: `analyzer.py:_process_reader()` → `_parse_protocols()` using handlers in `wa1kpcap/protocols/`.
- **native engine**: C++ pybind11 module (`_wa1kpcap_native`) driven by YAML protocol configs. Code path: `analyzer.py:_process_native()` → `NativeEngine.read_and_parse()` → C++ `NativeParser.parse_to_dataclass()` which constructs Python dataclasses directly in C++ (bypasses dict + `converter.py`).

Both engines feed into the same Python flow management pipeline: `FlowManager` groups packets into bidirectional `Flow` objects, `FeatureExtractor` computes sequence/statistical features, and exporters produce DataFrame/CSV/JSON output.

### C++ Native Engine (`src/cpp/`)

The C++ engine is YAML-configuration-driven with 9 parsing primitives: `fixed`, `bitfield`, `length_prefixed`, `computed`, `tlv`, `counted_list`, `rest`, `hardcoded`, `ext_list`. Protocol definitions live in `wa1kpcap/native/protocols/*.yaml`.

Key mechanisms in `protocol_engine.cpp`:
- `header_size_field`: After parsing fixed fields, adjusts `bytes_consumed` to the computed header size (handles IP/TCP options).
- `total_length_field`: Bounds `remaining` bytes to IP total_length, excluding Ethernet padding.
- Computed fields (type `COMPUTED`) must evaluate even when `offset >= len` — they consume 0 bytes but produce values like `flags` and `header_length` that downstream logic depends on.
- `parse_packet()` chains layers via `next_protocol` mappings until no more protocols match or data runs out.
- `ext_list` primitive: TLS-style extension list with `[total_len][type][len][data]...` format. Sub-protocol fields are merged into the parent FieldMap with a prefix (e.g., `tls_ext_sni.server_name`). Used by `tls_client_hello.yaml` and `tls_server_hello.yaml` to parse TLS extensions via YAML instead of hardcoded C++.
- TLS is NOT chained from TCP via `next_protocol` — TCP's YAML has no next_protocol to TLS. Instead, TLS is parsed via a separate reassembly path: Python buffers TCP payloads, extracts complete TLS records, then calls C++ `NativeParser.parse_tls_record()` which uses `parse_from_protocol_struct("tls_record", ...)` to parse starting from the TLS layer.

#### Dispatch Tables

The engine uses `unordered_map` dispatch tables (populated in the `ProtocolEngine` constructor) instead of if-else chains:

- `fast_dispatch_` (`std::unordered_map<std::string, FastParseFn>`): maps protocol name → fast-path parser. Unified signature: `FastResult(const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt)`. Only Type A protocols register here.
- `fill_dispatch_` (`std::unordered_map<std::string, std::function<void(SlowFillContext&)>>`): maps protocol name → fill function. Both Type A and Type B protocols register here. `SlowFillContext` carries `pkt`, `fields`, `cur`, `bytes_consumed`, `remaining`, `has_tls`, `tls_layers`, `proto_name`.

New built-in protocols register by adding lambdas in the constructor. Some protocols have special fill logic (TCP/UDP compute `app_len`, TLS sub-layers store into `tls_layers` for deferred processing).

#### Two Built-in Protocol Subtypes

- **Type A: Fast-Path** — has both `fast_parse_xxx()` (raw byte parsing, registered in `fast_dispatch_`) and `fill_xxx()` (registered in `fill_dispatch_`). For simple fixed-layout wire formats. Current: Ethernet, IPv4, IPv6, TCP, UDP, ARP, ICMP, ICMPv6.
- **Type B: Fill-Only** — has only `fill_xxx()` (registered in `fill_dispatch_`). YAML engine handles all parsing; fill copies fields into the C++ struct. For complex variable formats. Current: DNS, TLS series (tls_stream, tls_record, tls_handshake, tls_client_hello, tls_server_hello, tls_certificate).

Rule of thumb: if you can parse with pointer arithmetic in < 50 lines of C++, use Type A. If parsing needs TLV, compression, counted lists — use Type B.

#### Profiling Infrastructure

Built-in timing instrumentation controlled by a global flag:

- `g_profiling_enabled` (bool): global toggle, default `false`.
- `g_prof` (`ProfilingStats`): atomic counters for `total_ns`, `parse_layer_ns`, `fill_struct_ns`, `next_proto_ns`, `fieldmap_insert_ns`, `total_packets`, `total_layers`, plus per-primitive counters (`fixed_ns`/`fixed_count`, `bitfield_ns`/`bitfield_count`, etc.).
- `ScopedTimer`: RAII timer that accumulates nanoseconds into a target `std::atomic<uint64_t>` when `g_profiling_enabled` is true.
- Python API (exposed in `bindings.cpp`): `profiling_enable()`, `profiling_disable()`, `profiling_reset()`, `profiling_get_stats()` → returns dict with all counters.

The fast path (`parse_to_dataclass` in `bindings.cpp`) parses to a C++ `NativeParsedPacket` struct, then constructs Python dataclasses directly with positional args (cached class references, pre-cached constants like `py::none()` and `py::bytes("")`). The legacy path (`parse_packet` → `py::dict` → `converter.py`) is only used for fallback BPF app-layer filtering.

`NativeParsedPacket` (`parsed_packet.h`) embeds all sub-structs (NativeIPInfo, NativeTCPInfo, etc.) directly — no heap allocation. Presence flags (`has_eth`, `has_ip`, etc.) replace nullptr checks. pybind11 bindings return `py::none()` when the flag is false. Unknown protocols parsed by YAML are stored in `extra_layers` (a `std::map<std::string, FieldMap>`), converted to Python dicts in `build_dataclass_from_struct`, and passed to `ParsedPacket.__init__` which wraps them in `ProtocolInfo` instances via `ProtocolRegistry`.

### ProtocolInfo & Extensibility (`wa1kpcap/core/packet.py`)

Protocol layer data uses a two-tier class hierarchy under a common `_ProtocolInfoBase`:

- **Built-in protocols** (`EthernetInfo`, `IPInfo`, `TCPInfo`, `UDPInfo`, `TLSInfo`, `DNSInfo`, `HTTPInfo`, etc.) inherit from `_SlottedInfoBase(_ProtocolInfoBase)` and store fields as direct `__slots__` attributes for performance (~40% faster construction than dict-based). Each class defines `__slots__`, `_SLOT_NAMES`, and `_SLOT_DEFAULTS`. The `_fields` property returns a dict view of all slots for compatibility.
- **Custom/user protocols** inherit from `ProtocolInfo(_ProtocolInfoBase)` and use a `_fields` dict as source of truth, with typed property accessors.

`ParsedPacket.layers` is a `dict[str, _ProtocolInfoBase]` keyed by protocol name; legacy properties like `pkt.ip`, `pkt.tls` are aliases into this dict. The `isinstance` check in `_aggregate_flow_info()` uses `_ProtocolInfoBase` (the common ancestor).

To add a new protocol without modifying C++:
1. Create `<name>.yaml` in `wa1kpcap/native/protocols/` (or a custom directory).
2. Write a `ProtocolInfo` subclass with typed properties and a `merge()` method.
3. Register it: `ProtocolRegistry.get_instance().register('<name>', MyProtoInfo)`.
4. Add the `next_protocol` mapping that routes to it (e.g., in `udp.yaml`: `7777: myproto`).

To add a new built-in protocol (with C++ fast path):
1. Follow the steps in `docs/add-builtin-protocol-guide.md` or use `/add-builtin-protocol`.
2. The Python Info class must inherit `_SlottedInfoBase` with `__slots__` direct attributes (not `ProtocolInfo` with `_fields` dict).

Known protocols use dispatch table lookups (`fast_dispatch_` / `fill_dispatch_`) for optimized C++ struct fill. Unknown protocols go through `extra_layers` → `ProtocolRegistry` lookup → `ProtocolInfo` construction. If no class is registered, a generic `ProtocolInfo(fields=dict)` is used as fallback.

Flow-level aggregation in `analyzer.py:_aggregate_flow_info()` iterates `pkt.layers` generically: first packet's layer is `copy()`'d, subsequent packets' layers are `merge()`'d. The `copy()` is a selective shallow copy (one-level `list()`/`dict()` for mutables, direct reference for scalars) — not `deepcopy`.

### Flow Management (`wa1kpcap/core/flow.py`)

- `FlowKey`: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol), normalized so the same pair always maps to the same flow regardless of direction.
- `Flow`: Bidirectional flow with TCP state machine (SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED etc.). First packet determines "up" direction.
- Signed packet lengths: positive = client-to-server (up), negative = server-to-client (down).
- TCP retransmission detection (`_check_retransmission` in analyzer.py) uses per-direction sequence number tracking.

### Reassembly Pipeline

`IPFragmentReassembler` → `TCPStreamReassembler` → `TLSRecordReassembler`. For the native engine, `FlowBuffer` bridges Python TCP reassembly with C++ application-layer parsing.

### Feature Extraction (`wa1kpcap/features/`)

Sequence features: `packet_lengths`, `ip_lengths`, `trans_lengths`, `app_lengths`, `timestamps`, `iats`, `tcp_flags`, `tcp_window_sizes`. Statistical features computed from sequences: mean, std, var, min, max, range, median, skew, kurtosis, cv — with directional (up/down) variants.

`compute_array_stats` in `bindings.cpp` provides a C++ single-pass implementation (O(n) median via `nth_element`) that `_compute_array_stats()` in `extractor.py` calls when the native module is available, with a pure-Python fallback.

## YAML Protocol Configs

Located in `wa1kpcap/native/protocols/`. When adding a new protocol:
1. Create `<name>.yaml` with `name`, `fields` (using the 9 primitives), and optionally `next_protocol`, `header_size_field`, `total_length_field`.
2. Add the DLT or next_protocol mapping that routes to it.
3. If the protocol has variable-length headers, declare `header_size_field` pointing to a computed field.
4. If the protocol carries a total length (like IPv4/IPv6), declare `total_length_field` to prevent Ethernet padding from inflating payload sizes.

## Conventions

- All protocol parsing in the dpkt path goes through handler classes in `wa1kpcap/protocols/` registered via `ProtocolHandlerRegistry`.
- `ParsedPacket` is the universal packet representation shared by both engines.
- The `wa1kpcap/__init__.py` re-exports all public API symbols — new public classes should be added to `__all__` there.
- Test pcap fixtures are referenced from `tests/conftest.py`.
