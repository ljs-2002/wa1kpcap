# Plan: Dict-Based Architecture Refactoring

## Goal

Migrate from C++ struct (`NativeParsedPacket`) + pybind11 property access to C++ `dict[str, dict]` as the primary output path. Add Python-side protocol class registry for extensibility. This gives ~46% speedup on the native path while making application-layer protocols extensible via pure YAML + Python.

## Key Design Decisions

1. C++ `parse_packet()` (returns `dict[str, dict]`) becomes the primary path
2. `ProtocolInfo` base class with `_fields: dict` storage, typed properties on subclasses
3. Each `ProtocolInfo` subclass has a `merge(other)` method for flow-level aggregation
4. `ProtocolRegistry` maps protocol name → info class
5. `ParsedPacket` gets top-level shortcuts: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
6. `ParsedPacket.layers: dict[str, ProtocolInfo]` holds all parsed layers
7. L2-L4 remain as typed properties (`eth`, `ip`, `ip6`, `tcp`, `udp`) for IDE autocomplete
8. Application layer: typed properties for built-ins (`tls`, `dns`, `http`), extensible via `layers`
9. `Flow` mirrors the same pattern — typed properties + `layers` dict
10. `_aggregate_flow_info()` replaced by generic merge loop using `ProtocolInfo.merge()`

## Constraints

- dpkt engine must still work (constructs Info classes directly)
- Feature system accesses `pkt.ip.src`, `pkt.tcp.sport`, `pkt.tcp.flags`, etc. — API unchanged
- Filter system accesses same fields — API unchanged
- TLS reassembly (`_handle_native_tls_reassembly`) must still work
- All 272 existing tests pass after adaptation
- Public API (`flow.tls.sni`, `pkt.tcp.sport`) unchanged

---

## Phase 1: ProtocolInfo Base Class + Registry

**Goal**: Create the foundation classes without changing any existing behavior.

### 1.1 `wa1kpcap/core/packet.py` — Add `ProtocolInfo` base class

```python
class ProtocolInfo:
    """Base class for protocol info objects.

    Stores parsed fields in _fields dict. Subclasses add typed properties.
    """
    __slots__ = ('_fields',)

    def __init__(self, fields: dict | None = None, **kwargs):
        self._fields = fields or {}
        self._fields.update(kwargs)

    def get(self, key: str, default=None):
        return self._fields.get(key, default)

    def merge(self, other: 'ProtocolInfo') -> None:
        """Merge another instance into this one. Override in subclasses."""
        for k, v in other._fields.items():
            if k not in self._fields or self._fields[k] is None:
                self._fields[k] = v
```

### 1.2 `wa1kpcap/core/packet.py` — Add `ProtocolRegistry`

```python
class ProtocolRegistry:
    """Maps protocol names to ProtocolInfo subclasses."""
    _instance = None

    def __init__(self):
        self._registry: dict[str, type[ProtocolInfo]] = {}

    @classmethod
    def get_instance(cls) -> 'ProtocolRegistry':
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, name: str, info_class: type[ProtocolInfo]):
        self._registry[name] = info_class

    def get(self, name: str) -> type[ProtocolInfo] | None:
        return self._registry.get(name)

    def create(self, name: str, fields: dict) -> ProtocolInfo | None:
        cls = self._registry.get(name)
        if cls is None:
            return ProtocolInfo(fields)  # generic fallback
        return cls(fields=fields)
```

### 1.3 Verify

No behavior change. All tests pass. New classes are importable but unused.

---

## Phase 2: Migrate Info Classes to ProtocolInfo

**Goal**: Make existing `EthernetInfo`, `IPInfo`, `TCPInfo`, `UDPInfo`, `TLSInfo`, `HTTPInfo`, `DNSInfo` inherit from `ProtocolInfo` while keeping their current constructor signatures and property access patterns.

### 2.1 Strategy

Each Info class currently uses `@dataclass` with named fields. We change them to:
- Inherit from `ProtocolInfo`
- Keep `__init__` accepting the same positional/keyword args (backward compat)
- Store values in `_fields` dict
- Expose typed `@property` accessors for all existing fields
- Add `merge()` method

Example for `TCPInfo`:
```python
class TCPInfo(ProtocolInfo):
    __slots__ = ()

    def __init__(self, sport=0, dport=0, seq=0, ack_num=0, flags=0,
                 win=0, urgent=0, options=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'sport': sport, 'dport': dport, 'seq': seq,
                'ack_num': ack_num, 'flags': flags, 'win': win,
                'urgent': urgent, 'options': options,
            })

    @property
    def sport(self) -> int: return self._fields.get('sport', 0)
    @sport.setter
    def sport(self, v): self._fields['sport'] = v
    # ... same for dport, seq, ack_num, flags, win, urgent, options
```

### 2.2 Migrate all Info classes

Apply the same pattern to:
- `EthernetInfo` (src, dst, type)
- `IPInfo` (version, src, dst, proto, ttl, len, id, flags, offset)
- `IP6Info` (version, src, dst, next_header, hop_limit, flow_label, len)
- `TCPInfo` (sport, dport, seq, ack_num, flags, win, urgent, options)
- `UDPInfo` (sport, dport, len)
- `ICMPInfo` (type, code)
- `TLSInfo` — complex, has many fields + lists. All become properties over `_fields`.
- `HTTPInfo` (method, uri, host, user_agent, status_code, content_type, content_length)
- `DNSInfo` (queries, answers, response_code, question_count, etc.)

### 2.3 Add `merge()` to TLSInfo

Move the merge logic from `_aggregate_flow_info()` into `TLSInfo.merge()`:
```python
def merge(self, other: 'TLSInfo') -> None:
    if other.version and not self.version:
        self.version = other.version
    for s in (other.sni or []):
        if s and s not in self.sni:
            self.sni.append(s)
    # ... same for alpn, cipher_suites, cipher_suite, etc.
```

### 2.4 Register built-in protocols

At module level in `packet.py`:
```python
_registry = ProtocolRegistry.get_instance()
_registry.register('ethernet', EthernetInfo)
_registry.register('ipv4', IPInfo)
_registry.register('ipv6', IP6Info)
_registry.register('tcp', TCPInfo)
_registry.register('udp', UDPInfo)
_registry.register('icmp', ICMPInfo)
_registry.register('tls_record', TLSInfo)
_registry.register('dns', DNSInfo)
_registry.register('http', HTTPInfo)
```

### 2.5 Update `bindings.cpp` — `build_dataclass_from_struct`

The C++ `ClassCache` constructs Info classes with positional args. Since we're keeping the same `__init__` signatures, `build_dataclass_from_struct` continues to work unchanged.

### 2.6 Verify

All 272 tests pass. dpkt path still works. Native path still works. No API changes visible to users.

---

## Phase 3: Refactor ParsedPacket + Converter

**Goal**: Add `layers` dict and top-level shortcuts to `ParsedPacket`. Refactor `converter.py` to use the registry.

### 3.1 `ParsedPacket` — add `layers` dict and shortcuts

```python
@dataclass
class ParsedPacket:
    # ... existing fields ...

    # New: all layers indexed by protocol name
    layers: dict[str, ProtocolInfo] = field(default_factory=dict)

    # New: top-level shortcuts (populated at construction)
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    protocol_stack: list[str] = field(default_factory=list)
```

Keep existing `eth`, `ip`, `ip6`, `tcp`, `udp`, `tls`, `http`, `dns` fields — they become aliases into `layers`:

```python
@property
def eth(self) -> EthernetInfo | None:
    return self.layers.get('ethernet')

@eth.setter
def eth(self, v):
    if v is not None:
        self.layers['ethernet'] = v
    elif 'ethernet' in self.layers:
        del self.layers['ethernet']
```

Wait — this creates a chicken-and-egg problem with the dataclass `__init__`. Instead:
- Keep `eth`, `ip`, etc. as regular dataclass fields (set to None by default)
- Add a `_sync_layers()` method that populates `layers` from the individual fields
- Call `_sync_layers()` at the end of construction (via `__post_init__`)
- OR: make `layers` the source of truth and `eth`/`ip`/etc. as properties

**Decision**: Make `layers` the source of truth. Convert `eth`, `ip`, `ip6`, `tcp`, `udp`, `tls`, `http`, `dns` to `@property` accessors over `layers`. Remove them as dataclass fields.

This means `ParsedPacket` can no longer be a `@dataclass` (properties don't work well with dataclass). Convert to a regular class with explicit `__init__`.

### 3.2 Refactor `ParsedPacket` to regular class

```python
class ParsedPacket:
    __slots__ = (
        'timestamp', 'raw_data', 'link_layer_type', 'caplen', 'wirelen',
        'ip_len', 'trans_len', 'app_len',
        'layers',  # dict[str, ProtocolInfo]
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'protocol_stack',
        'is_client_to_server', 'packet_index', 'flow_index',
        '_raw_eth', '_raw_ip', '_raw_transport', '_raw_app',
        '_raw_tcp_payload', '_flow_key_cache',
    )

    def __init__(self, timestamp=0.0, raw_data=b"", link_layer_type=0,
                 caplen=0, wirelen=0, **kwargs):
        self.timestamp = timestamp
        self.raw_data = raw_data
        self.link_layer_type = link_layer_type
        self.caplen = caplen
        self.wirelen = wirelen
        self.ip_len = kwargs.get('ip_len', 0)
        self.trans_len = kwargs.get('trans_len', 0)
        self.app_len = kwargs.get('app_len', 0)
        self.layers = kwargs.get('layers', {})
        self.src_ip = kwargs.get('src_ip', "")
        self.dst_ip = kwargs.get('dst_ip', "")
        self.src_port = kwargs.get('src_port', 0)
        self.dst_port = kwargs.get('dst_port', 0)
        self.protocol = kwargs.get('protocol', 0)
        self.protocol_stack = kwargs.get('protocol_stack', [])
        self.is_client_to_server = kwargs.get('is_client_to_server', True)
        self.packet_index = kwargs.get('packet_index', -1)
        self.flow_index = kwargs.get('flow_index', -1)
        self._raw_eth = None
        self._raw_ip = None
        self._raw_transport = None
        self._raw_app = None
        self._raw_tcp_payload = kwargs.get('_raw_tcp_payload', b"")
        self._flow_key_cache = kwargs.get('_flow_key_cache', None)

        # Populate layers from explicit protocol kwargs
        for proto_key in ('eth', 'ip', 'ip6', 'tcp', 'udp', 'icmp', 'tls', 'http', 'dns'):
            val = kwargs.get(proto_key)
            if val is not None:
                layer_name = _PROTO_KEY_TO_LAYER.get(proto_key, proto_key)
                self.layers[layer_name] = val

    # Protocol properties (source of truth = self.layers)
    @property
    def eth(self) -> EthernetInfo | None:
        return self.layers.get('ethernet')
    @eth.setter
    def eth(self, v):
        if v is not None: self.layers['ethernet'] = v
        else: self.layers.pop('ethernet', None)

    # ... same pattern for ip, ip6, tcp, udp, icmp, tls, http, dns
```

Map: `ip` → `'ipv4'`, `ip6` → `'ipv6'`, `eth` → `'ethernet'`, `tcp` → `'tcp'`, `udp` → `'udp'`, `tls` → `'tls_record'`, `dns` → `'dns'`, `http` → `'http'`.

### 3.3 Update `bindings.cpp` — `build_dataclass_from_struct`

The C++ code constructs `ParsedPacket` with positional args. Since we're changing to `__init__(**kwargs)`, we need to update the C++ side to pass keyword arguments:

```cpp
py::object pkt = cc.ParsedPacket_cls(
    py::arg("timestamp") = timestamp,
    py::arg("raw_data") = raw_data_py,
    py::arg("link_layer_type") = link_type,
    py::arg("caplen") = caplen,
    py::arg("wirelen") = wirelen,
    py::arg("eth") = eth,
    py::arg("ip") = ip,
    // ...
);
```

**Alternative (faster)**: Keep constructing with positional args by defining `__init__` to accept them positionally too. Or: construct an empty `ParsedPacket` and set attributes directly. The fastest approach is to keep the current positional-arg pattern and just update the `__init__` signature to match.

**Decision**: Keep `__init__` accepting the same positional args as the current dataclass `__init__` for backward compat with `build_dataclass_from_struct`. Add `layers` population in `__init__` body.

### 3.4 Refactor `converter.py` — use registry

```python
def dict_to_parsed_packet(d: dict, timestamp: float, raw_data: bytes,
                           link_type: int) -> ParsedPacket:
    registry = ProtocolRegistry.get_instance()
    layers = {}
    for proto_name, fields in d.items():
        if isinstance(fields, dict):
            info = registry.create(proto_name, fields)
            if info is not None:
                layers[proto_name] = info

    pkt = ParsedPacket(timestamp=timestamp, raw_data=raw_data,
                       link_layer_type=link_type, ...)
    pkt.layers = layers
    # Extract shortcuts
    pkt._extract_shortcuts()
    return pkt
```

But wait — the dict keys from C++ don't match the registry names perfectly. C++ returns keys like `"ipv4"`, `"tcp"`, `"tls_record"`, `"tls_client_hello"`, etc. The registry maps `"ipv4"` → `IPInfo`, `"tcp"` → `TCPInfo`. For TLS, multiple dict keys (`tls_record`, `tls_handshake`, `tls_client_hello`) all contribute to a single `TLSInfo`. This is currently handled by `converter.py` manually.

**Decision**: Keep `converter.py` as the dict→ParsedPacket bridge with protocol-specific logic for now. The registry is used for creating Info objects, but the mapping from C++ dict keys to layer names requires domain knowledge (e.g., `tls_record` + `tls_client_hello` → single `TLSInfo`). This can be generalized later.

### 3.5 Verify

All tests pass. Both engines produce identical results. `pkt.eth`, `pkt.ip`, `pkt.tcp` etc. still work. `pkt.layers` is populated. `pkt.src_ip` etc. work.

---

## Phase 4: Refactor Flow Aggregation

**Goal**: Replace `_aggregate_flow_info()` with generic merge loop using `ProtocolInfo.merge()`.

### 4.1 `Flow` — add `layers` dict

```python
class Flow:
    # ... existing fields ...
    layers: dict[str, ProtocolInfo] = field(default_factory=dict)

    @property
    def tls(self) -> TLSInfo | None:
        return self.layers.get('tls_record')
    @tls.setter
    def tls(self, v):
        if v is not None: self.layers['tls_record'] = v
        else: self.layers.pop('tls_record', None)

    # Same for dns, http
```

### 4.2 Simplify `_aggregate_flow_info()`

Replace the 150+ line method with:

```python
def _aggregate_flow_info(self, flow: Flow) -> None:
    # 1. Merge from _tls_state (reassembly results)
    if flow._tls_state:
        self._merge_tls_state_to_flow(flow)

    # 2. Generic merge: iterate packets, merge each layer
    for pkt in flow.packets:
        for layer_name, info in pkt.layers.items():
            if layer_name in flow.layers:
                flow.layers[layer_name].merge(info)
            else:
                # Clone first occurrence
                flow.layers[layer_name] = self._clone_info(info)

    # 3. Handle native certs (from reassembly)
    native_certs = getattr(flow, '_native_certs', None)
    if native_certs and flow.tls and not flow.tls.certificates:
        flow.tls.certificates = [bytes(c) for c in native_certs]
        flow.tls.certificate = flow.tls.certificates[0]

    # 4. Build protocol stack
    flow.build_ext_protocol()
```

The `_merge_tls_state_to_flow` method handles the `TLSFlowState` → `TLSInfo` conversion (same logic as current, but creates a `TLSInfo` and uses `merge()`).

### 4.3 Verify

All tests pass. TLS/DNS/HTTP aggregation produces identical results.

---

## Phase 5: Switch Native Engine to Dict Path

**Goal**: Use `parse_packet()` (dict) instead of `parse_packet_struct()` (struct) as the primary C++ output.

### 5.1 `NativePipeline` in `bindings.cpp`

Change `__next__` to call `parse_packet()` instead of `parse_packet_struct()` + `build_dataclass_from_struct()`:

```cpp
.def("__next__", [](NativePipeline& self) -> py::object {
    while (true) {
        auto view = self.reader.next_view();
        if (!view.has_value()) throw py::stop_iteration();

        // Fast raw-byte pre-filter
        if (self.filter && self.filter_can_raw) {
            if (!self.filter->matches_raw(view->data, view->caplen, view->link_type))
                continue;
        }

        // Parse to dict (faster than struct path)
        py::dict parsed = self.engine->parse_packet(
            view->data, view->caplen, view->link_type, self.save_raw_bytes);

        // App-layer filter
        if (self.filter && !self.filter_can_raw) {
            if (!self.filter->matches(parsed)) continue;
        }

        // Return (timestamp, raw_bytes, parsed_dict, link_type)
        py::bytes raw(reinterpret_cast<const char*>(view->data), view->caplen);
        return py::make_tuple(view->timestamp, raw, parsed, view->link_type,
                              view->caplen, view->wirelen);
    }
})
```

### 5.2 `wa1kpcap/native/engine.py` — update `read_and_parse()`

```python
def read_and_parse(self, pcap_path, save_raw_bytes=False):
    for ts, raw, parsed_dict, link_type, caplen, wirelen in pipeline:
        pkt = dict_to_parsed_packet(parsed_dict, ts, raw, link_type)
        pkt.caplen = caplen
        pkt.wirelen = wirelen
        yield pkt
```

### 5.3 `parse_tls_record` — return dict instead of struct

Change `NativeParser.parse_tls_record()` binding to call `parse_packet()` on the TLS record bytes and return a dict. Then `_parse_native_tls_chunk` in `analyzer.py` uses `converter.py` to build a `ParsedPacket` from the dict.

Or simpler: keep `parse_tls_record` returning a struct for now, and convert in Python. This avoids changing the reassembly path in this phase.

**Decision**: Keep `parse_tls_record` returning struct for now. Only change the main packet path. TLS reassembly refactoring can be a follow-up.

### 5.4 Remove `build_dataclass_from_struct` and `ClassCache`

After switching to dict path, these are no longer needed for the main path. Keep them for `parse_tls_record` (which still uses struct). Can remove fully when TLS reassembly is also migrated.

### 5.5 Verify

All tests pass. Benchmark shows ~46% speedup on native path.

---

## Phase 6: Update Tests + Exports

### 6.1 Update test imports

If any tests import `ParsedPacket` as a dataclass and construct it with positional args, update to keyword args.

### 6.2 Add new tests

- `test_protocol_registry.py`: register custom protocol, verify it appears in `pkt.layers`
- `test_protocol_merge.py`: verify `TLSInfo.merge()` produces correct results
- `test_packet_shortcuts.py`: verify `pkt.src_ip`, `pkt.dst_ip`, etc.

### 6.3 Update `__init__.py` exports

Add `ProtocolInfo`, `ProtocolRegistry` to public API.

### 6.4 Verify

All tests pass (272 existing + new tests).

---

## Phase 7: Final Verification

1. `pytest tests/ -x -q` — all pass
2. `python benchmark.py` — verify speedup
3. `python gen_tls_report.py` — correct TLS report
4. Test with `multi.pcap` and `ip_seg.pcap` — correct flows
5. dpkt engine still works: `Wa1kPcap(engine='dpkt').analyze_file(...)` produces same results

---

## Files Modified

| File | Phase | Changes |
|------|-------|---------|
| `wa1kpcap/core/packet.py` | 1,2,3 | Add ProtocolInfo, ProtocolRegistry; migrate Info classes; refactor ParsedPacket |
| `wa1kpcap/core/flow.py` | 4 | Add layers dict, property aliases for tls/dns/http |
| `wa1kpcap/core/analyzer.py` | 4 | Simplify _aggregate_flow_info using merge() |
| `wa1kpcap/native/converter.py` | 3 | Use registry for dict→Info construction |
| `wa1kpcap/native/engine.py` | 5 | Switch to dict path, update read_and_parse |
| `src/cpp/bindings.cpp` | 5 | NativePipeline returns (ts, raw, dict, link_type) tuples |
| `wa1kpcap/core/__init__.py` | 6 | Export ProtocolInfo, ProtocolRegistry |
| `wa1kpcap/__init__.py` | 6 | Export ProtocolInfo, ProtocolRegistry |
| `tests/` | 6 | Update constructions, add registry/merge/shortcut tests |

## Risk Mitigation

- Each phase is independently verifiable with full test suite
- Phase 2 is the riskiest (changing all Info classes) — do one class at a time, test after each
- Phase 3 (ParsedPacket refactor) needs careful handling of `build_dataclass_from_struct` positional args
- Phase 5 (dict path switch) is the performance win — can be reverted independently if issues arise
- dpkt engine is unaffected until Phase 3 (ParsedPacket changes), but since we keep the same constructor signature, it should work
