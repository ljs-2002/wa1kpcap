# wa1kpcap Examples

This directory contains usage examples for wa1kpcap.

## Examples

### basic_usage.py
Demonstrates basic flow access using convenient attributes:
```python
flow.src_ip       # Source IP address
flow.sport        # Source port
flow.dst_ip       # Destination IP address
flow.dport        # Destination port
flow.protocol     # Protocol number (6=TCP, 17=UDP)
flow.proto        # Protocol name ("TCP", "UDP")
flow.start_ts      # Flow start timestamp
flow.end_ts        # Flow end timestamp
flow.num_packets   # Number of packets
flow.duration      # Flow duration
```

Run:
```bash
python examples/basic_usage.py
```

### feature_extraction.py
Demonstrates all available features:
- Sequence features (packet lengths, timestamps, IATs, payload bytes)
- Statistical features (mean, std, min, max, median, etc.)
- TCP-specific metrics (flags, window sizes, retransmissions)
- Protocol fields (TLS, HTTP, DNS)

Run:
```bash
python examples/feature_extraction.py
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
