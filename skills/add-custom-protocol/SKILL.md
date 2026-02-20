---
name: add-custom-protocol
description: Add a custom protocol using YAML + Python class with no C++ changes needed. Use when the user needs typed Python properties beyond raw field access but the protocol isn't performance-critical.
argument-hint: [protocol-name]
allowed-tools: Read, Write, Edit, Grep, Glob, Bash
---

Add a custom protocol to wa1kpcap using YAML + Python class (no C++ changes or recompilation needed).

## Steps

### 1. Create YAML Protocol Definition
- File: `wa1kpcap/native/protocols/<name>.yaml` (or a custom path via `yaml_path`)
- Define fields using YAML primitives (see `docs/yaml-primitives-reference.md`)

### 2. Create Python Info Class
- Extend `ProtocolInfo` from `wa1kpcap.core.packet` (NOT `_SlottedInfoBase` — that's for built-in protocols only)
- Use `__slots__ = ()` (ProtocolInfo stores data in `_fields` dict)
- Add typed `@property` accessors for each field
- Add any computed properties or helper methods
- Override `merge(self, other)` if flow-level aggregation needs special logic (e.g., list append, dict merge). Default merge is first-wins (copy from other if current value is None).

### 3. Register the Class
- Use `ProtocolRegistry.register()` with optional `yaml_path` and `routing` parameters
- `yaml_path`: loads extra YAML file at engine init (for files outside `wa1kpcap/native/protocols/`)
- `routing`: injects next_protocol mappings into parent protocols at engine init (no YAML edits needed)
- Call at import time (e.g., in `__init__.py`)

### 4. Test
- Access via `pkt.layers.get("protocol_name")`
- No recompilation needed

For a complete working example (QUIC Initial over UDP), see [examples/complete-example.md](examples/complete-example.md).

## Additional resources

- For YAML primitive types reference, see `docs/yaml-primitives-reference.md`
- For full custom protocol walkthrough, see `docs/add-custom-protocol-guide.md`
