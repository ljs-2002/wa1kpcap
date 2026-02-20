---
name: add-yaml-protocol
description: Create a new YAML-only protocol definition for the native engine. Use when the user wants quick field extraction without custom Python logic or C++ changes.
argument-hint: [protocol-name]
allowed-tools: Read, Write, Edit, Grep, Glob, Bash
---

Create a new YAML-only protocol definition for the wa1kpcap native engine.

## Steps

1. **Gather protocol info**: Ask the user for the protocol name, wire format (field names, sizes, types), and how it's dispatched from the parent protocol.

2. **Create the YAML file** at `wa1kpcap/native/protocols/<name>.yaml` using the available primitives:
   - `fixed` — fixed-size field (params: `size`, `format`, optional `endian`)
   - `bitfield` — bit-level fields (params: `group_size`, `fields[].bits`)
   - `length_prefixed` — length-prefixed data (params: `length_size`, `format`, optional `sub_protocol`)
   - `computed` — arithmetic expression over parsed fields (params: `expression`)
   - `tlv` — type-length-value loop (params: `type_size`, `length_size`, optional `type_mapping`)
   - `counted_list` — array with count from another field (params: `count_field`, `size`, `format`, optional `item_protocol`)
   - `rest` — consume all remaining bytes (optional `format`, default `bytes`)
   - `hardcoded` — delegate to C++ function (params: `parser`)
   - `prefixed_list` — TLV or length-prefixed item list (params: `list_length_size`, `type_size`, `item_length_size`, `type_mapping` or `item_format`)
   - `repeat` — repeat sub-protocol until buffer exhausted (params: `sub_protocol`, optional `merge`)

   Format types: `uint`, `int`, `mac`, `ipv4`, `ipv6`, `hex`, `bytes`, `ascii`/`string`

3. **Wire next-layer dispatch** (if this protocol carries a payload with sub-protocols):

   Add a `next_protocol` section at the top level of the YAML file. Two modes:

   **Field-based mapping** — route by a parsed field value:
   ```yaml
   next_protocol:
     field: ether_type
     mapping:
       0x0800: ipv4
       0x86DD: ipv6
   ```

   **Heuristic detection** — route by byte-level conditions on the payload (first match wins):
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
   ```
   Condition operators: `byte_eq`, `byte_in`, `byte_le`, `prefix_in`.

4. **Wire parent dispatch**: Either edit the parent protocol's YAML `next_protocol` section to route to this new protocol, or use `ProtocolRegistry.register()` with `routing` param to inject the mapping at runtime (no YAML edits needed).

5. **Test**: The protocol is immediately available after adding the YAML file (no recompilation). Access parsed fields via `pkt.layers["protocol_name"].fields`.

6. **Flow aggregation note**: YAML-only protocols use the generic `ProtocolInfo` class, which has a default `merge()` (first-wins: copy from other if current value is None). If you need custom merge logic (list append, dict merge, etc.), upgrade to a Custom Protocol with a Python Info class that overrides `merge()`.

For a complete working example (Syslog over UDP), see [examples/syslog.yaml](examples/syslog.yaml).

## Additional resources

- For YAML primitive types reference, see `docs/yaml-primitives-reference.md`
- For existing YAML protocol examples, see `wa1kpcap/native/protocols/` directory
