"""Integration tests for C++ process_file pipeline.

Compares C++ pipeline output against the existing Python pipeline (Wa1kPcap)
to ensure identical flow counts, metrics, and sequence accumulators.
"""

import os
import pytest

native = pytest.importorskip("wa1kpcap._wa1kpcap_native")

process_file = native.process_file
ProcessConfig = native.ProcessConfig
NativeFlowManager = native.NativeFlowManager
NativeFlowManagerConfig = native.NativeFlowManagerConfig
NativeParser = native.NativeParser

TEST_DIR = os.path.join(os.path.dirname(__file__), '..', 'test')
PROTO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'wa1kpcap', 'native', 'protocols'))


def _pcap(name):
    return os.path.abspath(os.path.join(TEST_DIR, name))


@pytest.fixture
def parser():
    return NativeParser(PROTO_DIR)


class TestProcessFileSingle:
    """Test process_file with single.pcap."""

    def test_basic_flow_creation(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False  # Don't filter retrans for comparison
        stats = process_file(_pcap('single.pcap'), parser, None, config, mgr)

        assert stats.packets_processed > 0
        assert mgr.flow_count() > 0

    def test_stats_populated(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        stats = process_file(_pcap('single.pcap'), parser, None, config, mgr)

        assert stats.packets_processed > 0
        assert stats.flows_created > 0

    def test_flow_has_packets(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(_pcap('single.pcap'), parser, None, config, mgr)

        flows = mgr.get_all_flows()
        for flow in flows:
            assert flow.metrics.packet_count > 0
            assert len(flow.seq_packet_lengths) == flow.metrics.packet_count
            assert len(flow.seq_timestamps) == flow.metrics.packet_count

    def test_directional_metrics_sum(self, parser):
        """up + down packet counts should equal total."""
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(_pcap('single.pcap'), parser, None, config, mgr)

        for flow in mgr.get_all_flows():
            m = flow.metrics
            assert m.up_packet_count + m.down_packet_count == m.packet_count
            assert m.up_byte_count + m.down_byte_count == m.byte_count


class TestProcessFileMulti:
    """Test process_file with multi.pcap (multiple flows)."""

    def test_multiple_flows(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(_pcap('multi.pcap'), parser, None, config, mgr)

        assert mgr.total_flow_count() > 1

    def test_tcp_flags_counted(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(_pcap('multi.pcap'), parser, None, config, mgr)

        # At least some flows should have SYN packets
        total_syn = sum(f.metrics.syn_count for f in mgr.get_all_flows())
        assert total_syn > 0


class TestProcessFileRetransmission:
    """Test retransmission detection with dup.pcap."""

    def test_retrans_detected(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False  # Don't filter, just count
        process_file(_pcap('dup.pcap'), parser, None, config, mgr)

        total_retrans = sum(f.metrics.retrans_count for f in mgr.get_all_flows())
        assert total_retrans > 0

    def test_retrans_filtered(self, parser):
        """With filter_retrans=True, fewer packets should be in flows."""
        mgr_no_filter = NativeFlowManager()
        config_no = ProcessConfig()
        config_no.filter_retrans = False
        process_file(_pcap('dup.pcap'), parser, None, config_no, mgr_no_filter)

        mgr_filter = NativeFlowManager()
        config_yes = ProcessConfig()
        config_yes.filter_retrans = True
        stats = process_file(_pcap('dup.pcap'), parser, None, config_yes, mgr_filter)

        total_no = sum(f.metrics.packet_count for f in mgr_no_filter.get_all_flows())
        total_yes = sum(f.metrics.packet_count for f in mgr_filter.get_all_flows())
        assert total_yes <= total_no
        assert stats.packets_filtered > 0


class TestProcessFileQUIC:
    """Test QUIC flow state handling with quic.pcap."""

    def test_quic_flows_detected(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(_pcap('quic.pcap'), parser, None, config, mgr)

        quic_flows = [f for f in mgr.get_all_flows() if f.is_quic]
        assert len(quic_flows) > 0

    def test_quic_dcid_len_set(self, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(_pcap('quic.pcap'), parser, None, config, mgr)

        quic_flows = [f for f in mgr.get_all_flows() if f.is_quic]
        # At least one QUIC flow should have a DCID length
        has_dcid = any(f.quic_dcid_len > 0 for f in quic_flows)
        assert has_dcid


class TestProcessFileFilter:
    """Test ACK/RST filtering."""

    def test_ack_filter(self, parser):
        """With filter_ack=True, pure ACK packets should be filtered."""
        mgr_no = NativeFlowManager()
        config_no = ProcessConfig()
        config_no.filter_ack = False
        config_no.filter_retrans = False
        process_file(_pcap('single.pcap'), parser, None, config_no, mgr_no)

        mgr_yes = NativeFlowManager()
        config_yes = ProcessConfig()
        config_yes.filter_ack = True
        config_yes.filter_retrans = False
        stats = process_file(_pcap('single.pcap'), parser, None, config_yes, mgr_yes)

        total_no = sum(f.metrics.packet_count for f in mgr_no.get_all_flows())
        total_yes = sum(f.metrics.packet_count for f in mgr_yes.get_all_flows())
        # ACK filtering should remove some packets (or at least not add any)
        assert total_yes <= total_no


class TestProcessFileBPF:
    """Test BPF filter integration."""

    def test_bpf_tcp_only(self, parser):
        """BPF filter 'tcp' should only produce TCP flows."""
        filt = native.NativeFilter("tcp")
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(_pcap('multi.pcap'), parser, filt, config, mgr)

        for flow in mgr.get_all_flows():
            assert flow.key.protocol == 6  # TCP


class TestProcessFileCompareWithPython:
    """Compare C++ process_file output with Python Wa1kPcap pipeline."""

    def _run_python_pipeline(self, pcap_path):
        from wa1kpcap import Wa1kPcap
        analyzer = Wa1kPcap(
            verbose_mode=True,
            filter_retrans=False,
            default_filter=None,
            bpf_filter=None,
        )
        return analyzer.analyze_file(pcap_path)

    def _run_cpp_pipeline(self, pcap_path, parser):
        mgr = NativeFlowManager()
        config = ProcessConfig()
        config.filter_retrans = False
        process_file(pcap_path, parser, None, config, mgr)
        # Return mgr too to keep it alive (flows are references into it)
        return mgr, mgr.get_all_flows()

    def test_flow_count_matches(self, parser):
        """C++ and Python should produce the same number of flows."""
        pcap = _pcap('multi.pcap')
        py_flows = self._run_python_pipeline(pcap)
        mgr, cpp_flows = self._run_cpp_pipeline(pcap, parser)
        assert len(cpp_flows) == len(py_flows)

    def test_total_packets_match(self, parser):
        """Total packet count across all flows should match."""
        pcap = _pcap('multi.pcap')
        py_flows = self._run_python_pipeline(pcap)
        mgr, cpp_flows = self._run_cpp_pipeline(pcap, parser)

        py_total = sum(f.metrics.packet_count for f in py_flows)
        cpp_total = sum(f.metrics.packet_count for f in cpp_flows)
        assert cpp_total == py_total

    def test_total_bytes_match(self, parser):
        """Total byte count across all flows should match."""
        pcap = _pcap('multi.pcap')
        py_flows = self._run_python_pipeline(pcap)
        mgr, cpp_flows = self._run_cpp_pipeline(pcap, parser)

        py_total = sum(f.metrics.byte_count for f in py_flows)
        cpp_total = sum(f.metrics.byte_count for f in cpp_flows)
        assert cpp_total == py_total
