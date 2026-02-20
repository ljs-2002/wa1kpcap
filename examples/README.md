# wa1kpcap Examples

This directory contains usage examples for wa1kpcap.

## Examples

### basic_usage.py
Demonstrates basic flow access:
```python
flow.src_ip          # Source IP address
flow.sport           # Source port
flow.dst_ip          # Destination IP address
flow.dport           # Destination port
flow.protocol        # Protocol number (6=TCP, 17=UDP)
flow.proto           # Protocol name ("TCP", "UDP")
flow.start_time      # Flow start timestamp
flow.end_time        # Flow end timestamp
flow.packet_count    # Number of packets
flow.byte_count      # Total bytes
flow.duration        # Flow duration
```

Run:
```bash
python examples/basic_usage.py
```

### feature_extraction.py
Demonstrates all available features:
- Sequence features (packet lengths, IP/transport/app lengths, timestamps, IATs, tcp_flags)
- Statistical features (mean, std, min, max, median, skew, kurt, cv, up/down variants)
- Bidirectional metrics (up/down packet and byte counts)
- TCP-specific metrics (SYN/FIN/RST/ACK/PSH counts, window sizes)
- Protocol fields (TLS, HTTP, DNS)

Run:
```bash
python examples/feature_extraction.py
```

### custom_feature.py
Demonstrates custom incremental feature registration:
- Defining `BaseIncrementalFeature` subclasses
- Registering features with `analyzer.register_feature()`
- Accessing results via `flow.get_features()`

Run:
```bash
python examples/custom_feature.py
```

### export_data.py
Demonstrates exporting flow data to different formats:
- DataFrame (pandas)
- CSV
- JSON

Run:
```bash
python examples/export_data.py
```

## Output Directory

The `output/` directory will contain exported files:
- `flows.csv` - Flow data in CSV format
- `flows.json` - Flow data in JSON format
