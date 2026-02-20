"""
Basic wa1kpcap usage example.

Demonstrates:
- Reading a pcap file
- Accessing flow information
- Printing flow summary
- Accessing packet length sequences
"""

from wa1kpcap import Wa1kPcap

# Create analyzer
analyzer = Wa1kPcap(
    verbose_mode=True,         # Store packet-level data
    enable_reassembly=True,    # Enable IP/TCP/TLS reassembly
    compute_statistics=True,   # Compute statistical features
)

# Analyze a pcap file
flows = analyzer.analyze_file('test/single.pcap')

print(f"Total flows: {len(flows)}")
print()

for flow in flows:
    # Flow identification
    print(f"Flow: {flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport}, {flow.proto}")
    print(f"  Protocol: {flow.protocol} ({flow.proto})")
    print(f"  Packets: {flow.packet_count}")
    print(f"  Duration: {flow.duration:.3f}s")
    print(f"  Time range: {flow.start_time:.3f}s -> {flow.end_time:.3f}s")

    # Packet length sequence
    if flow.packet_lengths is not None:
        import numpy as np
        lengths = flow.packet_lengths
        print(f"  Packet lengths: {lengths.tolist()}")
        print(f"  Total bytes: {int(np.sum(np.abs(lengths)))}")

    # Inter-arrival times
    if flow.iats is not None:
        import numpy as np
        print(f"  IAT mean: {float(np.mean(flow.iats)):.6f}s")
        print(f"  IAT std: {float(np.std(flow.iats)):.6f}s")

    # TLS information
    if flow.tls:
        print(f"  TLS version: {flow.tls.version}")
        if flow.tls.sni:
            print(f"  TLS SNI: {flow.tls.sni}")
        if flow.tls.cipher_suite:
            print(f"  TLS cipher: {flow.tls.cipher_suite}")

    # HTTP information
    if flow.http:
        print(f"  HTTP host: {flow.http.host}")
        if flow.http.user_agent:
            print(f"  HTTP UA: {flow.http.user_agent[:50]}...")

    # DNS information
    if flow.dns:
        print(f"  DNS queries: {flow.dns.queries}")

    print()
