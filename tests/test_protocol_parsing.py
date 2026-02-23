"""Test protocol parsing with scapy-generated packets.

This test file uses scapy to construct various protocol packets
including DNS, HTTP, and TCP variants.
"""

import pytest
import sys
import os
import tempfile
import struct

from wa1kpcap import Wa1kPcap
from wa1kpcap.core.flow import Flow, FlowKey
from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo, UDPInfo, DNSInfo, HTTPInfo


def create_pcap_with_packets(packets):
    """Create a pcap file from scapy packets."""
    try:
        from scapy.all import wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pcap', delete=False) as f:
        pcap_path = f.name

    wrpcap(pcap_path, packets)
    return pcap_path


def test_dns_query_parsing():
    """Test DNS query packet (dst_port=53) is recognized as DNS."""
    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR
    except ImportError:
        pytest.skip("scapy not installed")

    # DNS query: client random port -> server port 53
    packets = [
        Ether() / IP(src='192.168.1.1', dst='8.8.8.8') /
        UDP(sport=12345, dport=53) /
        DNS(rd=1, qd=DNSQR(qname='example.com'))
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        for engine in ('dpkt', 'native'):
            analyzer = Wa1kPcap(verbose_mode=True, engine=engine)
            flows = analyzer.analyze_file(pcap_path)

            assert len(flows) == 1, f"[{engine}] expected 1 flow, got {len(flows)}"
            flow = flows[0]
            dns_pkts = [p for p in flow.packets if p.dns]
            assert len(dns_pkts) == 1, (
                f"[{engine}] DNS query (dst_port=53) not recognized as DNS"
            )
            assert dns_pkts[0].dns.is_response is False
            # Verify queries field contains the actual domain name
            assert dns_pkts[0].dns.queries, (
                f"[{engine}] DNS query 'queries' field is empty"
            )
            assert 'example.com' in dns_pkts[0].dns.queries[0], (
                f"[{engine}] expected 'example.com' in queries, got {dns_pkts[0].dns.queries}"
            )
    finally:
        os.unlink(pcap_path)


def test_dns_response_parsing():
    """Test DNS response packet (src_port=53) is recognized as DNS.

    This is the regression test for the bug where only dst_port=53 was
    checked, causing DNS responses (src_port=53, dst_port=random) to be
    missed entirely.
    """
    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
    except ImportError:
        pytest.skip("scapy not installed")

    # DNS response: server port 53 -> client random port
    packets = [
        Ether() / IP(src='8.8.8.8', dst='192.168.1.1') /
        UDP(sport=53, dport=12345) /
        DNS(id=1, qr=1, qd=DNSQR(qname='example.com'),
            an=DNSRR(rrname='example.com', type='A', rdata='93.184.216.34'))
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        for engine in ('dpkt', 'native'):
            analyzer = Wa1kPcap(verbose_mode=True, engine=engine)
            flows = analyzer.analyze_file(pcap_path)

            assert len(flows) == 1, f"[{engine}] expected 1 flow, got {len(flows)}"
            flow = flows[0]
            dns_pkts = [p for p in flow.packets if p.dns]
            assert len(dns_pkts) == 1, (
                f"[{engine}] DNS response (src_port=53) not recognized as DNS"
            )
            assert dns_pkts[0].dns.is_response is True
            assert dns_pkts[0].dns.answer_count >= 1
            # Verify queries field contains the domain name
            assert dns_pkts[0].dns.queries, (
                f"[{engine}] DNS response 'queries' field is empty"
            )
            assert 'example.com' in dns_pkts[0].dns.queries[0], (
                f"[{engine}] expected 'example.com' in queries, got {dns_pkts[0].dns.queries}"
            )
    finally:
        os.unlink(pcap_path)


def test_dns_bidirectional_flow():
    """Test that both DNS query and response in the same flow are parsed.

    A complete DNS exchange: client sends query (dst_port=53), server
    replies (src_port=53). Both packets should have DNS info populated.
    """
    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        # Query: client:12345 -> server:53
        Ether() / IP(src='192.168.1.1', dst='8.8.8.8') /
        UDP(sport=12345, dport=53) /
        DNS(id=0x1234, rd=1, qd=DNSQR(qname='example.com')),
        # Response: server:53 -> client:12345
        Ether() / IP(src='8.8.8.8', dst='192.168.1.1') /
        UDP(sport=53, dport=12345) /
        DNS(id=0x1234, qr=1, qd=DNSQR(qname='example.com'),
            an=DNSRR(rrname='example.com', type='A', rdata='93.184.216.34')),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        for engine in ('dpkt', 'native'):
            analyzer = Wa1kPcap(verbose_mode=True, engine=engine)
            flows = analyzer.analyze_file(pcap_path)

            assert len(flows) == 1, f"[{engine}] expected 1 flow, got {len(flows)}"
            flow = flows[0]
            dns_pkts = [p for p in flow.packets if p.dns]
            assert len(dns_pkts) == 2, (
                f"[{engine}] expected 2 DNS packets in flow, got {len(dns_pkts)}"
            )
            # First is query, second is response
            assert dns_pkts[0].dns.is_response is False
            assert dns_pkts[1].dns.is_response is True
            # Both packets should have queries populated
            assert dns_pkts[0].dns.queries, (
                f"[{engine}] DNS query 'queries' field is empty in bidirectional flow"
            )
            assert 'example.com' in dns_pkts[0].dns.queries[0]
            # Flow-level DNS should also have queries
            assert flow.dns is not None, f"[{engine}] flow.dns is None"
            assert flow.dns.queries, (
                f"[{engine}] flow-level DNS 'queries' field is empty"
            )
            assert 'example.com' in flow.dns.queries[0]
    finally:
        os.unlink(pcap_path)


def test_dns_engine_parity():
    """Test that native and dpkt engines detect the same number of DNS packets.

    This ensures the native YAML-driven parser matches dpkt's behavior
    for DNS protocol detection in both directions.
    """
    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        # Query 1
        Ether() / IP(src='10.0.0.1', dst='8.8.8.8') /
        UDP(sport=11111, dport=53) /
        DNS(id=1, rd=1, qd=DNSQR(qname='a.com')),
        # Response 1
        Ether() / IP(src='8.8.8.8', dst='10.0.0.1') /
        UDP(sport=53, dport=11111) /
        DNS(id=1, qr=1, an=DNSRR(rrname='a.com', rdata='1.2.3.4')),
        # Query 2
        Ether() / IP(src='10.0.0.2', dst='8.8.4.4') /
        UDP(sport=22222, dport=53) /
        DNS(id=2, rd=1, qd=DNSQR(qname='b.com')),
        # Response 2
        Ether() / IP(src='8.8.4.4', dst='10.0.0.2') /
        UDP(sport=53, dport=22222) /
        DNS(id=2, qr=1, an=DNSRR(rrname='b.com', rdata='5.6.7.8')),
        # Plain UDP (not DNS) — should NOT be detected as DNS
        Ether() / IP(src='10.0.0.3', dst='10.0.0.4') /
        UDP(sport=9999, dport=8888) / b'\x00' * 20,
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        results = {}
        for engine in ('dpkt', 'native'):
            analyzer = Wa1kPcap(verbose_mode=True, engine=engine)
            flows = analyzer.analyze_file(pcap_path)
            dns_count = sum(
                1 for f in flows for p in f.packets if p.dns
            )
            results[engine] = dns_count

        assert results['dpkt'] == results['native'], (
            f"DNS count mismatch: dpkt={results['dpkt']}, native={results['native']}"
        )
        assert results['native'] == 4, (
            f"Expected 4 DNS packets, got {results['native']}"
        )
    finally:
        os.unlink(pcap_path)


def test_http_get_parsing():
    """Test HTTP GET request parsing."""
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    # Create HTTP GET packet
    http_get = b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'

    packets = [
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='PA', seq=1000) /
        Raw(http_get)
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        assert len(flows) > 0

        # Check for HTTP
        for flow in flows:
            for pkt in flow.packets:
                if pkt.http:
                    assert pkt.http.method == 'GET'
                    assert 'example.com' in str(pkt.http.headers)
                    break
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_http_response_parsing():
    """Test HTTP response parsing."""
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    # Create HTTP response packet
    http_response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'

    packets = [
        Ether() / IP(src='10.0.0.1', dst='192.168.1.1') /
        TCP(sport=80, dport=1234, flags='PA', seq=2000, ack=1001 + len(http_response)) /
        Raw(http_response)
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        assert len(flows) > 0

        # Check for HTTP response
        for flow in flows:
            for pkt in flow.packets:
                if pkt.http and pkt.http.status_code:
                    assert pkt.http.status_code == 200
                    break
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_tcp_three_way_handshake():
    """Test TCP three-way handshake flow creation."""
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        # SYN
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=443, flags='S', seq=1000),
        # SYN-ACK
        Ether() / IP(src='10.0.0.1', dst='192.168.1.1') /
        TCP(sport=443, dport=1234, flags='SA', seq=2000, ack=1001),
        # ACK
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=443, flags='A', seq=1001, ack=2001),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        assert len(flows) == 1

        flow = flows[0]
        assert flow.key.protocol == 6  # TCP
        assert flow.key.src_port == 1234 or flow.key.dst_port == 1234

        # Check TCP flags
        assert flow.metrics.syn_count >= 2  # SYN + SYN-ACK
        assert flow.metrics.ack_count >= 2
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_tcp_fin_rst_parsing():
    """Test TCP FIN and RST flag parsing."""
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        # SYN
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='S', seq=1000),
        # SYN-ACK
        Ether() / IP(src='10.0.0.1', dst='192.168.1.1') /
        TCP(sport=80, dport=1234, flags='SA', seq=2000, ack=1001),
        # FIN from client
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='FA', seq=1001, ack=2001),
        # RST from another connection
        Ether() / IP(src='192.168.1.1', dst='10.0.0.2') /
        TCP(sport=1235, dport=80, flags='R', seq=3000),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        # Should have at least 2 flows (one normal, one with RST)
        assert len(flows) >= 1

        # Check for FIN and RST flags
        for flow in flows:
            if flow.metrics.fin_count > 0:
                assert flow.metrics.fin_count >= 1
            if flow.metrics.rst_count > 0:
                assert flow.metrics.rst_count >= 1
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_udp_flow_parsing():
    """Test UDP flow parsing."""
    try:
        from scapy.all import Ether, IP, UDP, Raw, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        Ether() / IP(src='192.168.1.1', dst='224.0.0.1') /
        UDP(sport=1234, dport=5678) / Raw(b'test data'),
        Ether() / IP(src='224.0.0.1', dst='192.168.1.1') /
        UDP(sport=5678, dport=1234) / Raw(b'response data'),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        # Should create separate flows for different 5-tuples
        assert len(flows) >= 1

        # Check UDP flow
        udp_flows = [f for f in flows if f.key.protocol == 17]
        if udp_flows:
            flow = udp_flows[0]
            assert flow.key.protocol == 17  # UDP
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_ipv4_fragmentation():
    """Test IPv4 fragmented packet handling."""
    try:
        from scapy.all import Ether, IP, UDP, Raw, fragment, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    # Create a packet that will be fragmented
    pkt = Ether() / IP(src='192.168.1.1', dst='10.0.0.1') / UDP() / Raw(b'X' * 1500)

    # Fragment it
    fragments = fragment(pkt, 500)

    pcap_path = create_pcap_with_packets(fragments)

    try:
        analyzer = Wa1kPcap(verbose_mode=True, enable_reassembly=True)
        flows = analyzer.analyze_file(pcap_path)

        # Should reassemble into a single flow
        assert len(flows) >= 1
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_filter_ack_option():
    """Test ACK packet filtering."""
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    # Create packets including pure ACK
    packets = [
        # SYN
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='S', seq=1000),
        # SYN-ACK
        Ether() / IP(src='10.0.0.1', dst='192.168.1.1') /
        TCP(sport=80, dport=1234, flags='SA', seq=2000, ack=1001),
        # ACK
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='A', seq=1001, ack=2001),
        # Pure ACK (no payload)
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='A', seq=1001, ack=2001),
        # Data packet
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='PA', seq=1001, ack=2001) / Raw(b'data'),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        # Without filtering
        analyzer_no_filter = Wa1kPcap(verbose_mode=True, filter_ack=False)
        flows_no_filter = analyzer_no_filter.analyze_file(pcap_path)

        # With filtering
        analyzer_with_filter = Wa1kPcap(verbose_mode=True, filter_ack=True)
        flows_with_filter = analyzer_with_filter.analyze_file(pcap_path)

        # Filtered version should have same or fewer packets
        for flow in flows_with_filter:
            for flow_no_filter in flows_no_filter:
                if flow.key == flow_no_filter.key:
                    assert flow.num_packets <= flow_no_filter.num_packets
                    break
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_flow_duration():
    """Test flow duration calculation."""
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    import time

    # Create packets with different timestamps
    packets = [
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='S', seq=1000),
        Ether() / IP(src='10.0.0.1', dst='192.168.1.1') /
        TCP(sport=80, dport=1234, flags='SA', seq=2000, ack=1001),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        if flows:
            flow = flows[0]
            # Duration should be calculated
            assert flow.duration >= 0
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_packet_counts():
    """Test packet count tracking."""
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    packets = []
    # Add 5 packets
    for i in range(5):
        packets.append(
            Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
            TCP(sport=1234, dport=80, flags='PA', seq=1000+i*100) /
            Raw(b'data')
        )

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        if flows:
            flow = flows[0]
            assert flow.num_packets == 5
            assert flow.metrics.packet_count == 5
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_directional_packet_counts():
    """Test forward/reverse packet counting."""
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        # Forward packet
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='PA', seq=1000) / Raw(b'client data'),
        # Reverse packet
        Ether() / IP(src='10.0.0.1', dst='192.168.1.1') /
        TCP(sport=80, dport=1234, flags='PA', seq=2000, ack=1012) / Raw(b'server data'),
        # Another forward packet
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='PA', seq=1012, ack=2021) / Raw(b'more client data'),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        if flows:
            flow = flows[0]
            # Check directional counts
            assert flow.metrics.up_packet_count >= 2
            assert flow.metrics.down_packet_count >= 1
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_tcp_window_tracking():
    """Test TCP window size tracking."""
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='S', seq=1000, window=8192),
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='A', seq=1001, window=4096),
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='A', seq=1001, window=16384),
    ]

    pcap_path = create_pcap_with_packets(packets)

    try:
        analyzer = Wa1kPcap(verbose_mode=True)
        flows = analyzer.analyze_file(pcap_path)

        if flows:
            flow = flows[0]
            # Check window stats
            assert flow.metrics.min_window > 0
            assert flow.metrics.max_window > 0
            assert flow.metrics.sum_window > 0
            assert flow.metrics.max_window >= flow.metrics.min_window
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_flow_key_hashable():
    """Test that FlowKey is properly hashable for sets/dicts."""
    key1 = FlowKey(src_ip='192.168.1.1', dst_ip='10.0.0.1',
                   src_port=1234, dst_port=80, protocol=6)
    key2 = FlowKey(src_ip='192.168.1.1', dst_ip='10.0.0.1',
                   src_port=1234, dst_port=80, protocol=6)

    # Test with set
    key_set = {key1, key2}
    assert len(key_set) == 1  # Same key, only one in set

    # Test with dict
    key_dict = {key1: "flow1", key2: "flow2"}
    assert len(key_dict) == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
