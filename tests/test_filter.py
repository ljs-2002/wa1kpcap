"""
Tests for simplified BPF filter functionality.
"""

import pytest
from wa1kpcap import Wa1kPcap, PacketFilter, compile_filter, BPFCompiler
from wa1kpcap.core.filter import (
    ProtocolCondition,
    IPCondition,
    PortCondition,
    AppProtocolCondition,
    CompoundCondition
)


class TestBPFCompiler:
    """Test BPF compiler."""

    def test_compile_tcp(self):
        """Test compiling TCP filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("tcp")
        assert isinstance(cond, ProtocolCondition)
        assert cond.protocols == {6}  # TCP = 6

    def test_compile_udp(self):
        """Test compiling UDP filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("udp")
        assert isinstance(cond, ProtocolCondition)
        assert cond.protocols == {17}  # UDP = 17

    def test_compile_port(self):
        """Test compiling port filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("port 443")
        assert isinstance(cond, PortCondition)
        assert cond.any_ports == {443}

    def test_compile_host(self):
        """Test compiling host filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("host 192.168.1.1")
        assert isinstance(cond, IPCondition)
        assert cond.any_ips == {"192.168.1.1"}

    def test_compile_src_port(self):
        """Test compiling src port filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("src port 80")
        assert isinstance(cond, PortCondition)
        assert cond.src_ports == {80}

    def test_compile_dst_port(self):
        """Test compiling dst port filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("dst port 443")
        assert isinstance(cond, PortCondition)
        assert cond.dst_ports == {443}

    def test_compile_and(self):
        """Test compiling AND expression."""
        compiler = BPFCompiler()
        cond = compiler.compile("tcp and port 443")
        assert isinstance(cond, CompoundCondition)
        assert cond.operator == "and"
        assert len(cond.conditions) == 2

    def test_compile_or(self):
        """Test compiling OR expression."""
        compiler = BPFCompiler()
        cond = compiler.compile("tcp or udp")
        assert isinstance(cond, CompoundCondition)
        assert cond.operator == "or"
        assert len(cond.conditions) == 2

    def test_compile_not(self):
        """Test compiling NOT expression."""
        compiler = BPFCompiler()
        cond = compiler.compile("not tcp")
        assert isinstance(cond, ProtocolCondition)
        assert cond.negate == True

    def test_compile_grouped(self):
        """Test compiling grouped expression."""
        compiler = BPFCompiler()
        cond = compiler.compile("(tcp or udp) and port 443")
        assert isinstance(cond, CompoundCondition)
        assert cond.operator == "and"

    def test_compile_complex(self):
        """Test compiling complex expression."""
        compiler = BPFCompiler()
        cond = compiler.compile("host 192.168.1.1 and (tcp or udp)")
        assert isinstance(cond, CompoundCondition)

    def test_compile_app_protocol(self):
        """Test compiling application layer protocol filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("tls")
        assert isinstance(cond, AppProtocolCondition)
        assert cond.protocols == {'tls'}

    def test_compile_http(self):
        """Test compiling HTTP filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("http")
        assert isinstance(cond, AppProtocolCondition)
        assert cond.protocols == {'http'}

    def test_compile_dns(self):
        """Test compiling DNS filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("dns")
        assert isinstance(cond, AppProtocolCondition)
        assert cond.protocols == {'dns'}

    def test_compile_empty(self):
        """Test compiling empty filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("")
        assert isinstance(cond, CompoundCondition)
        assert len(cond.conditions) == 0

    def test_compile_none(self):
        """Test compiling None filter."""
        compiler = BPFCompiler()
        cond = compiler.compile(None)
        assert isinstance(cond, CompoundCondition)
        assert len(cond.conditions) == 0


class TestProtocolCondition:
    """Test protocol condition matching."""

    def test_tcp_matches(self):
        """Test TCP condition matching TCP packet."""
        cond = ProtocolCondition(protocols={6})
        # Ethernet(14) + IPv4(20, proto=6) + TCP(20)
        buf = bytes.fromhex(
            "aabbccddaabb"  # dst mac (6)
            "001122334455"  # src mac (6)
            "0800"          # IPv4 (2)
            "4500003c000040004006b1ea"  # IP hdr bytes 0-11
            "c0a801010a000001"          # src/dst IP
            "005001bb0000000000000000"  # TCP src=80 dst=443
            "5002000000000000"          # TCP flags+window
        )
        assert cond.matches(None, buf) == True

    def test_tcp_not_matches_udp(self):
        """Test TCP condition not matching UDP packet."""
        cond = ProtocolCondition(protocols={6})
        # Ethernet(14) + IPv4(20, proto=17) + UDP(8)
        buf = bytes.fromhex(
            "aabbccddaabb"
            "001122334455"
            "0800"
            "4500003c000040004011b1ea"  # proto=0x11 (UDP)
            "c0a801010a000001"
            "04d2003500080000"          # UDP src=1234 dst=53
        )
        assert cond.matches(None, buf) == False

    def test_not_tcp(self):
        """Test NOT TCP condition."""
        cond = ProtocolCondition(protocols={6}, negate=True)
        buf = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004006b1ea"
            "c0a801010a000001"
            "005001bb00000000000000005002000000000000"
        )
        assert cond.matches(None, buf) == False  # Is TCP, negate=True → False


class TestPortCondition:
    """Test port condition matching."""

    def test_port_443_matches(self):
        """Test port 443 condition."""
        cond = PortCondition(any_ports={443})
        # Ethernet(14) + IPv4(20, proto=6) + TCP(src=80, dst=443)
        buf = bytes.fromhex(
            "aabbccddaabb0011223344550800"          # Ethernet
            "4500003c000040004006b1ea"                # IP hdr (12 bytes)
            "c0a801010a000001"                        # src/dst IP
            "005001bb00000000000000005002000000000000" # TCP src=80 dst=443
        )
        assert cond.matches(None, buf) == True

    def test_src_port_80(self):
        """Test src port 80 condition."""
        cond = PortCondition(src_ports={80})
        # Ethernet(14) + IPv4(20, proto=6) + TCP(src=80, dst=443)
        buf = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004006b1ea"
            "c0a801010a000001"
            "005001bb"  # src port=80, dst port=443
        )
        assert cond.matches(None, buf) == True

    def test_dst_port_443(self):
        """Test dst port 443 condition."""
        cond = PortCondition(dst_ports={443})
        # Ethernet(14) + IPv4(20, proto=6) + TCP(src=80, dst=443)
        buf = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004006b1ea"
            "c0a801010a000001"
            "005001bb"  # src port=80, dst port=443
        )
        assert cond.matches(None, buf) == True


class TestIPCondition:
    """Test IP address condition matching."""

    def test_host_matches(self):
        """Test host condition matching."""
        cond = IPCondition(any_ips={"192.168.1.1"})
        # Ethernet(14) + IPv4(20) with src=192.168.1.1, dst=10.0.0.1
        buf = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004006b1ea"
            "c0a80101"  # 192.168.1.1 (src, offset 26)
            "0a000001"  # 10.0.0.1 (dst, offset 30)
        )
        assert cond.matches(None, buf) == True

    def test_host_not_matches(self):
        """Test host condition not matching."""
        cond = IPCondition(any_ips={"192.168.1.1"})
        # Packet with src=10.0.0.1, dst=10.0.0.2 (no 192.168.1.1)
        buf = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004006b1ea"
            "0a000001"  # 10.0.0.1
            "0a000002"  # 10.0.0.2
        )
        assert cond.matches(None, buf) == False


class TestPacketFilter:
    """Test PacketFilter class."""

    def test_no_filter(self):
        """Test filter with no filter string."""
        pf = PacketFilter(None)
        assert pf.fast_check(b"anything") == True
        assert pf.post_check(None) == True
        assert bool(pf) == False

    def test_empty_filter(self):
        """Test filter with empty filter string."""
        pf = PacketFilter("")
        assert pf.fast_check(b"anything") == True

    def test_tcp_port_443(self):
        """Test tcp and port 443 filter."""
        pf = PacketFilter("tcp and port 443")
        assert bool(pf) == True

        # TCP 443 packet: Ethernet(14) + IPv4(20, proto=6) + TCP(src=80, dst=443)
        buf = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004006b1ea"
            "c0a801010a000001"
            "005001bb00000000000000005002000000000000"
        )
        assert pf.fast_check(buf) == True

        # UDP 443 packet: proto=17 → should fail TCP check
        buf_udp = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004011b1ea"
            "c0a801010a000001"
            "005001bb00080000"
        )
        assert pf.fast_check(buf_udp) == False

    def test_app_protocol_filter(self):
        """Test application layer protocol filter."""
        from wa1kpcap.core.packet import ParsedPacket, TLSInfo

        pf = PacketFilter("tls")
        assert pf.has_app_layer == True
        # App layer filter should always pass fast_check
        assert pf.fast_check(b"anything") == True

        # Create mock packet with TLS
        pkt = ParsedPacket(timestamp=0.0)
        pkt.tls = TLSInfo(version="TLS 1.2", content_type=22, record_length=0)
        assert pf.post_check(pkt) == True

        # Packet without TLS
        pkt2 = ParsedPacket(timestamp=0.0)
        assert pf.post_check(pkt2) == False

    def test_not_icmp(self):
        """Test NOT ICMP filter."""
        pf = PacketFilter("not icmp")
        # ICMP packet: proto=1
        buf_icmp = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004001b1ea"
            "c0a801010a000001"
            "0800000000000000"
        )
        assert pf.fast_check(buf_icmp) == False

        # TCP packet: proto=6
        buf_tcp = bytes.fromhex(
            "aabbccddaabb0011223344550800"
            "4500003c000040004006b1ea"
            "c0a801010a000001"
            "005001bb00000000000000005002000000000000"
        )
        assert pf.fast_check(buf_tcp) == True


class TestCompileFilter:
    """Test compile_filter function."""

    def test_compile_filter(self):
        """Test compile_filter helper function."""
        pf = compile_filter("tcp and port 443")
        assert isinstance(pf, PacketFilter)
        assert bool(pf) == True

    def test_compile_filter_none(self):
        """Test compile_filter with None."""
        pf = compile_filter(None)
        assert isinstance(pf, PacketFilter)
        assert bool(pf) == False


class TestWa1kPcapBPFIntegration:
    """Test BPF filter integration with Wa1kPcap."""

    def test_analyzer_with_bpf_filter(self):
        """Test analyzer with BPF filter."""
        analyzer = Wa1kPcap(bpf_filter="tcp", verbose_mode=False)
        assert analyzer.bpf_filter == "tcp"
        assert analyzer._packet_filter is not None

    def test_analyze_with_tcp_filter(self):
        """Test analyzing with TCP filter."""
        analyzer = Wa1kPcap(bpf_filter="tcp", verbose_mode=False)
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        # All flows should be TCP
        for flow in flows:
            assert flow.key.protocol == 6, f"Expected TCP (6), got {flow.key.protocol}"

    def test_analyze_with_udp_filter(self):
        """Test analyzing with UDP filter."""
        analyzer = Wa1kPcap(bpf_filter="udp", verbose_mode=False)
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        # All flows should be UDP
        for flow in flows:
            assert flow.key.protocol == 17, f"Expected UDP (17), got {flow.key.protocol}"

    def test_analyze_with_port_filter(self):
        """Test analyzing with port filter."""
        analyzer = Wa1kPcap(bpf_filter="port 443", verbose_mode=False)
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        # All flows should have port 443
        for flow in flows:
            has_443 = (flow.key.src_port == 443 or flow.key.dst_port == 443)
            assert has_443, f"Expected port 443, got {flow.key.src_port}->{flow.key.dst_port}"

    def test_analyze_with_tls_filter(self):
        """Test analyzing with TLS filter (app layer)."""
        analyzer = Wa1kPcap(bpf_filter="tls", verbose_mode=False)
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        # All flows should have TLS
        for flow in flows:
            assert flow.tls is not None, f"Expected TLS, got {flow.key}"

    def test_analyze_with_not_filter(self):
        """Test analyzing with NOT filter."""
        analyzer = Wa1kPcap(bpf_filter="not udp", verbose_mode=False)
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        # No flows should be UDP
        for flow in flows:
            assert flow.key.protocol != 17, f"Expected non-UDP, got {flow.key.protocol}"

    def test_analyze_with_complex_filter(self):
        """Test analyzing with complex filter."""
        analyzer = Wa1kPcap(bpf_filter="port 443 or port 80", verbose_mode=False)
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        # All flows should have port 443 or 80
        for flow in flows:
            has_port = (flow.key.src_port in (443, 80) or
                       flow.key.dst_port in (443, 80))
            assert has_port, f"Expected port 443 or 80, got {flow.key.src_port}->{flow.key.dst_port}"

    def test_filter_reduces_flow_count(self):
        """Test that filter reduces flow count."""
        analyzer_all = Wa1kPcap(verbose_mode=False)
        flows_all = analyzer_all.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        analyzer_filtered = Wa1kPcap(bpf_filter="tcp and port 443", verbose_mode=False)
        flows_filtered = analyzer_filtered.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        assert len(flows_filtered) < len(flows_all)

    def test_filter_stats(self):
        """Test that filter stats are recorded."""
        analyzer = Wa1kPcap(bpf_filter="tcp", verbose_mode=False)
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        stats = analyzer.stats
        assert 'packets_filtered' in stats
        # Should have filtered some packets (non-TCP)
        assert stats['packets_filtered'] > 0

    def test_no_filter_allows_all(self):
        """Test that no filter allows all flows."""
        analyzer = Wa1kPcap(verbose_mode=False, default_filter=None)
        assert analyzer._packet_filter is None
        flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')
        assert len(flows) > 0

    def test_host_filter(self):
        """Test host filter."""
        # Find an IP that exists in the pcap
        analyzer_all = Wa1kPcap(verbose_mode=False)
        flows_all = analyzer_all.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

        if flows_all:
            target_ip = flows_all[0].key.src_ip

            analyzer = Wa1kPcap(bpf_filter=f"host {target_ip}", verbose_mode=False)
            flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

            # All flows should involve the target IP
            for flow in flows:
                assert (flow.key.src_ip == target_ip or
                       flow.key.dst_ip == target_ip), \
                    f"Expected {target_ip}, got {flow.key.src_ip}->{flow.key.dst_ip}"


class TestInvalidFilters:
    """Test invalid filter handling."""

    def test_invalid_syntax(self):
        """Test that invalid syntax raises error."""
        compiler = BPFCompiler()
        with pytest.raises(ValueError):
            compiler.compile("invalid syntax here")

    def test_unclosed_parenthesis(self):
        """Test unclosed parenthesis."""
        compiler = BPFCompiler()
        with pytest.raises(ValueError):
            compiler.compile("(tcp and port 443")

    def test_invalid_port(self):
        """Test invalid port specification."""
        compiler = BPFCompiler()
        with pytest.raises(ValueError):
            compiler.compile("port")


class TestProtocolCombinations:
    """Test various protocol combinations."""

    def test_ip_protocol(self):
        """Test ip protocol filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("ip")
        assert isinstance(cond, ProtocolCondition)
        assert cond.is_ip == True

    def test_ipv6_protocol(self):
        """Test ipv6 protocol filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("ipv6")
        assert isinstance(cond, ProtocolCondition)
        assert cond.is_ipv6 == True

    def test_arp_protocol(self):
        """Test arp protocol filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("arp")
        assert isinstance(cond, ProtocolCondition)
        assert cond.is_arp == True

    def test_icmp_protocol(self):
        """Test icmp protocol filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("icmp")
        assert isinstance(cond, ProtocolCondition)
        assert cond.protocols == {1}  # ICMP = 1

    def test_icmpv6_protocol(self):
        """Test icmpv6 protocol filter."""
        compiler = BPFCompiler()
        cond = compiler.compile("icmpv6")
        assert isinstance(cond, ProtocolCondition)
        assert cond.protocols == {58}  # ICMPv6 = 58
