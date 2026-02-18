"""
Export example.

Demonstrates exporting flow data to different formats:
- DataFrame (pandas)
- CSV
- JSON
"""

from wa1kpcap import Wa1kPcap, to_dataframe, to_csv, to_json
import pandas as pd

# Create analyzer and analyze
analyzer = Wa1kPcap(
    verbose_mode=True,
    compute_statistics=True,
)

flows = analyzer.analyze_file('test/multi.pcap')

print(f"Total flows: {len(flows)}")
print()

# === Export to DataFrame ===
df = to_dataframe(flows)
print("DataFrame export:")
print(df.head())
print()

# Show DataFrame columns
print("DataFrame columns:")
print(df.columns.tolist())
print()

# Basic statistics from DataFrame
print("DataFrame info:")
print(f"  Shape: {df.shape}")
print(f"  Protocols:")
if 'protocol' in df.columns:
    print(df['protocol'].value_counts())
print()

# === Export to CSV ===
to_csv(flows, 'output/flows.csv')
print("Exported to CSV: output/flows.csv")
print()

# === Export to JSON ===
to_json(flows, 'output/flows.json')
print("Exported to JSON: output/flows.json")
print()

# === Example: Filter DataFrame ===
# Find TLS flows
tls_df = df[df['tls_version'].notna()]
print(f"TLS flows: {len(tls_df)}")
if len(tls_df) > 0:
    print(tls_df[['src_ip', 'sport', 'dst_ip', 'dport', 'tls_version', 'tls_sni']].head())
print()

# Find flows with high packet count
high_traffic_df = df[df['packet_count'] > 100].sort_values('packet_count', ascending=False)
print(f"Flows with >100 packets: {len(high_traffic_df)}")
if len(high_traffic_df) > 0:
    print(high_traffic_df[['src_ip', 'sport', 'dst_ip', 'dport', 'packet_count', 'byte_count']].head())
print()

# === Example: Aggregate statistics ===
print("Aggregate statistics:")
print(f"  Total flows: {len(df)}")
print(f"  Total packets: {df['packet_count'].sum()}")
print(f"  Total bytes: {df['byte_count'].sum()}")
print(f"  Average duration: {df['duration'].mean():.3f}s")
print(f"  Total duration: {df['duration'].sum():.3f}s")
print()

# Protocol breakdown
if 'protocol' in df.columns:
    proto_stats = df.groupby('protocol').agg({
        'packet_count': 'sum',
        'byte_count': 'sum',
        'duration': 'sum'
    })
    print("Protocol statistics:")
    print(proto_stats)
