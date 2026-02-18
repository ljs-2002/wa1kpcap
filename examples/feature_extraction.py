"""
Feature extraction example.

Demonstrates all available features that can be extracted from flows:
"""

from wa1kpcap import Wa1kPcap
import json

# Create analyzer with all features enabled
analyzer = Wa1kPcap(
    verbose_mode=True,
    enable_reassembly=True,
    compute_statistics=True,
)

# Analyze
flows = analyzer.analyze_file('test/multi.pcap')

print(f"Total flows: {len(flows)}")
print()

# Show first few flows with all extracted information
for i, flow in enumerate(flows[:5]):
    print(f"=== Flow #{i+1} ===")
    print(f"Identifier: {flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport}, {flow.proto}")
    print()

    # === Basic Flow Info ===
    print("Basic Flow Info:")
    print(f"  Protocol: {flow.protocol} ({flow.proto})")
    print(f"  Packets: {flow.num_packets}")
    print(f"  Duration: {flow.duration:.3f}s")
    print(f"  Start: {flow.start_ts:.3f}s")
    print(f"  End: {flow.end_ts:.3f}s")
    print()

    # === Bidirectional Stats ===
    print("Bidirectional Stats:")
    print(f"  Forward packets: {flow.metrics.forward_packet_count}")
    print(f"  Forward bytes: {flow.metrics.forward_byte_count}")
    print(f"  Reverse packets: {flow.metrics.reverse_packet_count}")
    print(f"  Reverse bytes: {flow.metrics.reverse_byte_count}")
    print()

    # === TCP-specific Metrics ===
    if flow.protocol == 6:  # TCP
        print("TCP Metrics:")
        print(f"  SYN count: {flow.metrics.syn_count}")
        print(f"  FIN count: {flow.metrics.fin_count}")
        print(f"  RST count: {flow.metrics.rst_count}")
        print(f"  ACK count: {flow.metrics.ack_count}")
        print(f"  PSH count: {flow.metrics.psh_count}")
        print(f"  Window min: {flow.metrics.min_window}")
        print(f"  Window max: {flow.metrics.max_window}")
        print(f"  Window avg: {flow.metrics.sum_window / flow.num_packets if flow.num_packets > 0 else 0:.1f}")
        print()

    # === Sequence Features ===
    if flow.features:
        print("Sequence Features:")
        print(f"  Packet lengths: {flow.packet_lengths.tolist() if flow.packet_lengths is not None else 'N/A'}")
        print(f"  Timestamps: {flow.timestamps.tolist() if flow.timestamps is not None else 'N/A'}")
        print(f"  IATs: {flow.iats.tolist() if flow.iats is not None else 'N/A'}")
        print(f"  Payload bytes: {flow.payload_bytes.tolist() if flow.payload_bytes is not None else 'N/A'}")

        if flow.tcp_flags is not None:
            print(f"  TCP flags: {flow.tcp_flags.tolist()}")
        if flow.tcp_window_sizes is not None:
            print(f"  TCP windows: {flow.tcp_window_sizes.tolist()}")
        print()

    # === Statistical Features ===
    stats = flow.stats
    if stats:
        print("Statistical Features:")
        pkt_stats = stats.get('packet_lengths', {})
        if pkt_stats:
            print(f"  Packet length stats:")
            print(f"    Count: {pkt_stats.get('count', 0)}")
            print(f"    Mean: {pkt_stats.get('mean', 0):.2f}")
            print(f"    Std: {pkt_stats.get('std', 0):.2f}")
            print(f"    Min: {pkt_stats.get('min', 0)}")
            print(f"    Max: {pkt_stats.get('max', 0)}")
            print(f"    Median: {pkt_stats.get('median', 0):.2f}")
            print(f"    Range: {pkt_stats.get('range', 0):.2f}")
            print(f"    Skewness: {pkt_stats.get('skew', 0):.4f}")
            print(f"    Kurtosis: {pkt_stats.get('kurt', 0):.4f}")
            print(f"    CV: {pkt_stats.get('cv', 0):.4f}")



        iat_stats = stats.get('iats', {})
        if iat_stats:
            print(f"  IAT stats:")
            print(f"    Mean: {iat_stats.get('mean', 0):.6f}s")
            print(f"    Std: {iat_stats.get('std', 0):.6f}s")
            print(f"    Min: {iat_stats.get('min', 0):.6f}s")
            print(f"    Max: {iat_stats.get('max', 0):.6f}s")

        payload_stats = stats.get('payload_bytes', {})
        if payload_stats:
            print(f"  Payload byte stats:")
            print(f"    Mean: {payload_stats.get('mean', 0):.2f}")
            print(f"    Total: {payload_stats.get('sum', 0)}")
        print()

    # === Protocol-specific Fields ===
    # TLS
    if flow.tls:
        print("TLS Fields:")
        print(f"  Version: {flow.tls.version}")
        print(f"  Content type: {flow.tls.content_type}")
        print(f"  Handshake type: {flow.tls.handshake_type}")
        print(f"  Record length: {flow.tls.record_length}")
        if flow.tls.sni:
            print(f"  SNI: {flow.tls.sni}")
        if flow.tls.cipher_suite:
            print(f"  Cipher suite: {flow.tls.cipher_suite}")
        if flow.tls.alpn:
            print(f"  ALPN: {flow.tls.alpn}")
        if flow.tls.certificate:
            print(f"  Cert subject: {flow.tls.certificate.subject}")
            print(f"  Cert issuer: {flow.tls.certificate.issuer}")
        print()

    # HTTP
    if flow.http:
        print("HTTP Fields:")
        print(f"  Method: {flow.http.method}")
        print(f"  Host: {flow.http.host}")
        print(f"  User-Agent: {flow.http.user_agent}")
        print(f"  Path: {flow.http.path}")
        print()

    # DNS
    if flow.dns:
        print("DNS Fields:")
        print(f"  Queries: {flow.dns.queries}")
        print(f"  Response codes: {flow.dns.response_codes}")
        print()

    print("=" * 50)
    print()
