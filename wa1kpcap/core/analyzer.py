"""
Main PcapAnalyzer class - entry point for PCAP analysis.

Combines all components into a unified API.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any
import time
import warnings

import numpy as np

if TYPE_CHECKING:
    from wa1kpcap.core.reader import PcapReader
    from wa1kpcap.core.flow import FlowManager, Flow
    from wa1kpcap.core.packet import ParsedPacket

from wa1kpcap.core.flow import FlowManager, FlowManagerConfig
from wa1kpcap.core.reader import PcapReader


def _inject_tls_into_packets(packets: list, tls_info) -> None:
    """Post-materialization hook: inject reassembled TLS info into the first
    TCP data packet that doesn't already have TLS."""
    for pkt in packets:
        if pkt.tls is not None:
            return  # Already has TLS, no injection needed
    for pkt in packets:
        if pkt.tcp and getattr(pkt, '_raw_tcp_payload', b''):
            pkt.tls = tls_info
            return
from wa1kpcap.core.packet import ParsedPacket
from wa1kpcap.core.filter import PacketFilter
from wa1kpcap.features.extractor import FeatureExtractor
from wa1kpcap.protocols.registry import get_global_registry
from wa1kpcap.reassembly.ip_fragment import IPFragmentReassembler
from wa1kpcap.reassembly.tcp_stream import TCPStreamReassembler
from wa1kpcap.reassembly.tls_record import TLSRecordReassembler
from wa1kpcap.features.registry import BaseIncrementalFeature


def _merge_filters(default_filter: str | None, bpf_filter: str | None) -> str | None:
    """Combine default_filter and bpf_filter with AND logic."""
    df = (default_filter or "").strip()
    bf = (bpf_filter or "").strip()
    if df and bf:
        return f"({df}) and ({bf})"
    return df or bf or None


class Wa1kPcap:
    """
    Main entry point for PCAP analysis.

    Wa1kPcap provides a unified API for analyzing pcap/pcapng files and extracting
    flow-level features. It supports multiple PCAP formats, protocol parsing,
    feature extraction, and data export.

    Examples:
        Basic usage:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     print(f"Flow: {flow.key}, Packets: {flow.packet_count}")

        Extract packet length sequences:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     if flow.features:
            ...         # Get packet lengths (positive=up, negative=down)
            ...         lengths = flow.features.packet_lengths
            ...         print(f"Packet lengths: {lengths}")

        Extract statistical features:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     # Access pre-computed statistics
            ...     print(f"Mean packet length: {flow.pkt_mean:.1f}")
            ...     print(f"Up packet count: {flow.pkt_up_count}")
            ...     print(f"Down packet count: {flow.pkt_down_count}")
            ...     # Or access all stats
            ...     stats = flow.stats
            ...     print(f"IAT mean: {stats['iats']['mean']:.6f}")

        Extract TLS SNI:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     if flow.tls and flow.tls.sni:
            ...         print(f"TLS SNI: {flow.tls.sni}")

        With ACK filtering and no verbose mode:
            >>> analyzer = Wa1kPcap(filter_ack=True, verbose_mode=False)
            >>> flows = analyzer.analyze_file('traffic.pcap')

    Args:
        udp_timeout: UDP flow timeout in seconds. 0 or negative disables
            timeout (all packets with the same 5-tuple stay in one flow).
            Default: 0 (no timeout)
        tcp_cleanup_timeout: TCP closed flow cleanup timeout in seconds (default: 300.0)
        filter_ack: Filter pure ACK packets without payload (default: False)
        filter_rst: Filter RST packets (default: False)
        bpf_filter: Simplified BPF filter string (default: None)
            Supports: tcp, udp, icmp, icmpv6, arp, ip, ipv6, tls, http, dns
            IP filtering: host 192.168.1.1, src 192.168.1.1, dst 192.168.1.1
            Port filtering: port 443, src port 80, dst port 443
            Logical operators: and, or, not
            Grouping: (expr)
            Examples: "tcp and port 443", "host 192.168.1.1 or port 53", "not icmp"
        min_packets: Minimum packet count per flow. Flows with fewer packets are
            discarded (default: 1, i.e., keep all flows)
        verbose_mode: Store packet-level information (default: False)
        enabled_features: List of feature names to extract (default: all)
        save_raw_bytes: Save raw packet bytes (memory intensive, default: False)
        compute_statistics: Compute statistical features (default: True)
        enable_reassembly: Enable IP/TCP/TLS reassembly (default: True)
        protocols: List of protocols to parse (default: all supported)
        engine: Parsing engine - "native" (default, C++) or "dpkt" (requires pip install wa1kpcap[dpkt])

    Examples:
        Basic usage:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     print(f"Flow: {flow.key}, Packets: {flow.packet_count}")

        With BPF filter:
            >>> analyzer = Wa1kPcap(bpf_filter="tcp and port 443")
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> # Only TCP/443 flows will be analyzed

        With complex filter:
            >>> analyzer = Wa1kPcap(bpf_filter="host 192.168.1.1 and not icmp")
            >>> flows = analyzer.analyze_file('traffic.pcap')

        Extract packet length sequences:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     if flow.features:
            ...         # Get packet lengths (positive=up, negative=down)
            ...         lengths = flow.features.packet_lengths
            ...         print(f"Packet lengths: {lengths}")

        Extract statistical features:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     # Access pre-computed statistics
            ...     print(f"Mean packet length: {flow.pkt_mean:.1f}")
            ...     print(f"Up packet count: {flow.pkt_up_count}")
            ...     print(f"Down packet count: {flow.pkt_down_count}")
            ...     # Or access all stats
            ...     stats = flow.stats
            ...     print(f"IAT mean: {stats['iats']['mean']:.6f}")

        Extract TLS SNI:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     if flow.tls and flow.tls.sni:
            ...         print(f"TLS SNI: {flow.tls.sni}")

        With ACK filtering and no verbose mode:
            >>> analyzer = Wa1kPcap(filter_ack=True, verbose_mode=False)
            >>> flows = analyzer.analyze_file('traffic.pcap')
    """

    def __init__(
        self,
        # Flow management
        udp_timeout: float = 0,
        tcp_cleanup_timeout: float = 300.0,

        # Packet filtering
        filter_ack: bool = False,
        filter_rst: bool = False,
        filter_retrans: bool = True,
        bpf_filter: str | None = None,
        default_filter: str | None = "not arp and not icmp and not icmpv6 and not dhcp and not dhcpv6",

        # Flow filtering
        min_packets: int = 1,

        # Detailed mode
        verbose_mode: bool = False,

        # Feature extraction
        enabled_features: list[str] | None = None,
        save_raw_bytes: bool = False,
        compute_statistics: bool = True,

        # Protocol parsing
        enable_reassembly: bool = True,
        protocols: list[str] | None = None,
        app_layer_parsing: str = "full",

        # Engine selection: "native" (default, C++ engine) or "dpkt" (requires dpkt package)
        engine: str = "native",
    ):
        # dpkt fallback: if user requests dpkt but it's not installed, warn and use native
        if engine == "dpkt":
            warnings.warn(
                "The dpkt engine is deprecated and will be removed in a future version. "
                "Use engine='native' (default) for better performance.",
                DeprecationWarning,
                stacklevel=2,
            )
            try:
                import dpkt  # noqa: F401
            except ImportError:
                warnings.warn(
                    "dpkt is not installed. Falling back to native engine. "
                    "Install dpkt with: pip install wa1kpcap[dpkt]",
                    stacklevel=2,
                )
                engine = "native"

        self._engine = engine
        self.udp_timeout = udp_timeout
        self.tcp_cleanup_timeout = tcp_cleanup_timeout
        self.filter_ack = filter_ack
        self.filter_rst = filter_rst
        self.filter_retrans = filter_retrans
        self.min_packets = min_packets
        self.verbose_mode = verbose_mode
        self.enabled_features = enabled_features
        self.save_raw_bytes = save_raw_bytes
        self.compute_statistics = compute_statistics
        self.enable_reassembly = enable_reassembly
        self.protocols = protocols

        # app_layer_parsing: "full" (0), "port_only" (1), "none" (2)
        _app_layer_modes = {"full": 0, "port_only": 1, "none": 2}
        if app_layer_parsing not in _app_layer_modes:
            raise ValueError(
                f"Invalid app_layer_parsing={app_layer_parsing!r}, "
                f"must be one of: {', '.join(_app_layer_modes)}"
            )
        self.app_layer_parsing = app_layer_parsing
        self._app_layer_mode = _app_layer_modes[app_layer_parsing]

        # Merge default_filter and bpf_filter
        self.default_filter = default_filter
        self.bpf_filter = bpf_filter
        effective_filter = _merge_filters(default_filter, bpf_filter)

        # Initialize BPF filter
        self._packet_filter = PacketFilter(effective_filter) if effective_filter else None

        # Initialize components
        self._flow_manager = FlowManager(FlowManagerConfig(
            udp_timeout=udp_timeout,
            tcp_cleanup_timeout=tcp_cleanup_timeout,
            max_flows=100000
        ))

        self._feature_extractor = FeatureExtractor(compute_statistics=compute_statistics)

        # Reassembly
        if enable_reassembly:
            self._ip_reassembler = IPFragmentReassembler()
            self._tcp_reassembler = TCPStreamReassembler()
            self._tls_reassembler = TLSRecordReassembler()
        else:
            self._ip_reassembler = None
            self._tcp_reassembler = None
            self._tls_reassembler = None

        # Protocol registry
        self._protocol_registry = get_global_registry()

        # Custom features - registered by name
        self._custom_features: dict[str, BaseIncrementalFeature] = {}

        # Native engine (lazy init)
        self._native_engine = None
        if self._engine == "native":
            from wa1kpcap.native import NATIVE_AVAILABLE
            if not NATIVE_AVAILABLE:
                raise RuntimeError(
                    "Native C++ engine not available. "
                    "Install with: pip install -e '.[native]'"
                )
            from wa1kpcap.native.engine import NativeEngine
            self._native_engine = NativeEngine(
                bpf_filter=effective_filter,
                app_layer_mode=self._app_layer_mode,
            )

        # Statistics
        self._stats = {
            'files_processed': 0,
            'packets_processed': 0,
            'packets_filtered': 0,
            'flows_created': 0,
            'errors': []
        }

    def register_feature(self, name: str, processor: BaseIncrementalFeature) -> None:
        """Register a custom feature processor."""
        self._custom_features[name] = processor
        # Also register with flow manager for automatic registration on new flows
        self._flow_manager.register_custom_feature(name, processor)

    def analyze_file(self, pcap_path: str | Path) -> list[Flow]:
        """
        Analyze a single pcap/pcapng file.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            List of Flow objects
        """
        pcap_path = Path(pcap_path)

        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        if self._engine == "native":
            return self._process_native(pcap_path)

        with PcapReader(pcap_path) as reader:
            return self._process_reader(reader, str(pcap_path))

    def analyze_directory(
        self,
        directory: str | Path,
        pattern: str = "*.pcap"
    ) -> dict[str, list[Flow]]:
        """
        Analyze all PCAP files in a directory.

        Args:
            directory: Directory containing PCAP files
            pattern: Glob pattern for matching files

        Returns:
            Dict mapping filename to list of flows
        """
        directory = Path(directory)
        results = {}

        for pcap_file in directory.glob(pattern):
            # Also check for pcapng
            if not PcapReader.is_pcap_file(pcap_file):
                continue

            try:
                flows = self.analyze_file(pcap_file)
                results[pcap_file.name] = flows
            except Exception as e:
                self._stats['errors'].append(f"{pcap_file}: {e}")

        return results

    def _process_reader(self, reader: PcapReader, filename: str) -> list[Flow]:
        """Process packets from a PcapReader."""
        self._stats['files_processed'] += 1

        # Tell the BPF fast-check which link-layer type this file uses
        if self._packet_filter:
            self._packet_filter.set_link_type(reader.link_layer_type)

        for ts, buf in reader:
            try:
                # Fast BPF pre-check (before full parsing)
                if self._packet_filter and not self._packet_filter.fast_check(buf):
                    self._stats['packets_filtered'] += 1
                    continue

                self._process_packet(ts, buf, reader)
            except Exception as e:
                self._stats['errors'].append(f"{filename}: Packet processing error: {e}")

        # Get all flows
        flows = self._flow_manager.get_all_flows()

        # Aggregate packet-level protocol info to flow-level
        for flow in flows:
            self._aggregate_flow_info(flow)

        # Extract features
        for flow in flows:
            if self.verbose_mode:
                flow._verbose = True
                flow._save_raw = self.save_raw_bytes
            flow.features = self._feature_extractor.extract(flow)

        # Min packets filter
        if self.min_packets > 1:
            flows = [f for f in flows if f.packet_count >= self.min_packets]

        self._stats['flows_created'] += len(flows)

        # Clear for next file
        self._flow_manager.clear()

        return flows

    def _process_native(self, pcap_path: Path) -> list[Flow]:
        """Process packets using the native C++ engine.

        Uses C++ process_file for the full pipeline (read → parse → filter →
        flow management) when possible. Falls back to Python per-packet loop
        only when IP fragment reassembly or TLS stream reassembly is needed.
        """
        # Use C++ pipeline when no reassembly is needed
        # (reassembly requires Python-side state machines)
        if not self.enable_reassembly and not self._custom_features:
            return self._process_native_cpp(pcap_path)

        # Even with reassembly, use C++ pipeline — reassembly is rare
        # and we can handle it as a post-processing step later.
        # For now, use C++ pipeline for flow management + feature accumulation,
        # then do protocol aggregation in Python.
        return self._process_native_cpp(pcap_path)

    def _process_native_cpp(self, pcap_path: Path) -> list[Flow]:
        """Process packets using the fully fused C++ pipeline.

        C++ handles: pcap reading, protocol parsing, ACK/RST filtering,
        retransmission detection, TCP state, QUIC flow state, flow management,
        and sequence accumulation.

        Python handles: NativeFlow → Flow conversion, protocol aggregation,
        feature extraction.
        """
        from wa1kpcap.native import _wa1kpcap_native as _native

        self._stats['files_processed'] += 1

        # Configure C++ pipeline
        config = _native.ProcessConfig()
        config.filter_ack = self.filter_ack
        config.filter_rst = self.filter_rst
        config.filter_retrans = self.filter_retrans
        config.app_layer_mode = self._app_layer_mode
        config.save_raw_bytes = self.save_raw_bytes

        # Create C++ flow manager
        mgr_config = _native.NativeFlowManagerConfig()
        mgr_config.udp_timeout = self.udp_timeout
        mgr_config.tcp_cleanup_timeout = self.tcp_cleanup_timeout
        mgr_config.max_flows = 100000
        config.flow_config = mgr_config

        mgr = _native.NativeFlowManager(mgr_config)

        # Run fused C++ pipeline
        stats = _native.process_file(
            str(pcap_path),
            self._native_engine._parser,
            self._native_engine._filter,
            config,
            mgr,
        )

        self._stats['packets_processed'] += stats.packets_processed
        self._stats['packets_filtered'] += stats.packets_filtered

        # Convert NativeFlows → Python Flows
        native_flows = mgr.get_all_flows()
        flows = self._convert_native_flows(native_flows, mgr)

        # Batch C++ operations: aggregation + features (1 pybind11 call each)
        from wa1kpcap.core.flow import LazyPacketList
        from wa1kpcap.features.extractor import FlowFeatures
        from wa1kpcap.core.packet import TLSInfo, DNSInfo, QUICInfo
        parser = self._native_engine._parser
        verbose = self.verbose_mode
        save_raw = self.save_raw_bytes

        # Batch aggregate: one C++ call for all flows
        all_infos = mgr.aggregate_all(parser)
        # Batch features: one C++ call for all flows
        all_stats_dicts = mgr.compute_all_features_dicts()

        for py_flow, nf, info, stats_dict in zip(flows, native_flows, all_infos, all_stats_dicts):
            # Set flow layers from aggregated info
            if info.has_tls:
                ct = info.tls
                sni_val = ct.sni
                certs = list(ct.certificates) if ct.certificates else []
                py_flow.layers['tls_record'] = TLSInfo(
                    version=ct.version if ct.version else None,
                    content_type=ct.content_type if ct.content_type >= 0 else None,
                    handshake_type=ct.handshake_type if ct.handshake_type >= 0 else None,
                    record_length=ct.record_length,
                    sni=[sni_val] if sni_val else [],
                    cipher_suites=list(ct.cipher_suites) if ct.cipher_suites else [],
                    cipher_suite=ct.cipher_suite if ct.cipher_suite >= 0 else None,
                    alpn=list(ct.alpn) if ct.alpn else [],
                    signature_algorithms=list(ct.signature_algorithms) if ct.signature_algorithms else [],
                    supported_groups=list(ct.supported_groups) if ct.supported_groups else [],
                    certificates=certs,
                    certificate=certs[0] if certs else None,
                    _handshake_types=list(ct.handshake_types) if ct.handshake_types else [],
                )
            if info.has_dns:
                cd = info.dns
                py_flow.layers['dns'] = DNSInfo(
                    queries=list(cd.queries) if cd.queries else [],
                    response_code=cd.response_code,
                    question_count=cd.question_count,
                    answer_count=cd.answer_count,
                    authority_count=cd.authority_count,
                    additional_count=cd.additional_count,
                    flags=cd.flags,
                )
            if info.has_quic:
                cq = info.quic
                py_flow.layers['quic'] = QUICInfo(
                    is_long_header=cq.is_long_header,
                    packet_type=cq.packet_type,
                    version=cq.version,
                    dcid=bytes(cq.dcid) if cq.dcid else b'',
                    scid=bytes(cq.scid) if cq.scid else b'',
                    dcid_len=cq.dcid_len,
                    scid_len=cq.scid_len,
                    sni=cq.sni if cq.sni else None,
                    alpn=list(cq.alpn) if cq.alpn else None,
                    cipher_suites=list(cq.cipher_suites) if cq.cipher_suites else None,
                    version_str=cq.version_str if cq.version_str else '',
                    packet_type_str=cq.packet_type_str if cq.packet_type_str else '',
                )

            py_flow._ip_version = info.ip_version
            py_flow.ext_protocol = list(info.ext_protocol)

            # Lazy packet list
            lazy = LazyPacketList(nf.packets, mgr)
            if info.tls_reassembled and py_flow.tls is not None:
                py_flow._reassembled_tls = py_flow.tls
                lazy.add_post_hook(_inject_tls_into_packets, py_flow.tls)
            py_flow.packets = lazy

            # Features
            if verbose:
                py_flow._verbose = True
                py_flow._save_raw = save_raw
            features = FlowFeatures()
            features._statistics = stats_dict
            # Populate sequence arrays from C++ NativeFlow
            if nf.seq_timestamps:
                features.timestamps = np.array(nf.seq_timestamps)
            if nf.seq_packet_lengths:
                features.packet_lengths = np.array(nf.seq_packet_lengths)
            if nf.seq_ip_lengths:
                features.ip_lengths = np.array(nf.seq_ip_lengths)
            if nf.seq_trans_lengths:
                features.trans_lengths = np.array(nf.seq_trans_lengths)
            if nf.seq_app_lengths:
                features.app_lengths = np.array(nf.seq_app_lengths)
            if nf.seq_payload_bytes:
                features.payload_bytes = np.array(nf.seq_payload_bytes)
            if nf.seq_tcp_flags:
                features.tcp_flags = np.array(nf.seq_tcp_flags)
            if nf.seq_tcp_windows:
                features.tcp_window_sizes = np.array(nf.seq_tcp_windows)
            if len(features.timestamps) > 1:
                features.iats = np.diff(features.timestamps)
            py_flow.features = features

        # Custom feature post-processing: materialize packets and run update() per packet
        if self._custom_features:
            for py_flow in flows:
                py_flow._custom_features = dict(self._custom_features)
                py_flow._feature_initialized = False
                py_flow._initialize_features()
                for pkt in py_flow.packets:  # triggers lazy materialization
                    for name, processor in py_flow._custom_features.items():
                        try:
                            processor.update(py_flow, pkt)
                        except Exception:
                            pass

        # Custom protocol aggregation: if user registered non-builtin protocols
        # in ProtocolRegistry, aggregate extra_layers from packets into flow.layers.
        # Only materializes packets for flows that need it.
        from wa1kpcap.core.packet import ProtocolRegistry as _PR, _ProtocolInfoBase
        proto_registry = _PR.get_instance()
        # Snapshot default protocol keys on first call
        if not hasattr(proto_registry, '_default_keys'):
            proto_registry._default_keys = frozenset(proto_registry._registry.keys())
        user_protos = set(proto_registry._registry.keys()) - proto_registry._default_keys
        has_custom_protos = bool(user_protos)
        if has_custom_protos:
            _default_keys = proto_registry._default_keys
            for py_flow in flows:
                for pkt in py_flow.packets:  # triggers lazy materialization
                    if not hasattr(pkt, 'layers') or not pkt.layers:
                        continue
                    for name, info in pkt.layers.items():
                        if name in _default_keys:
                            continue
                        existing = py_flow.layers.get(name)
                        if existing is None:
                            if isinstance(info, _ProtocolInfoBase):
                                py_flow.layers[name] = info.copy()
                            else:
                                py_flow.layers[name] = info
                        elif isinstance(existing, _ProtocolInfoBase) and isinstance(info, _ProtocolInfoBase):
                            existing.merge(info)
                # Rebuild ext_protocol to include custom protocols
                py_flow.build_ext_protocol()

        # Post-parse app-layer filtering (e.g., bpf_filter="tls")
        if self._packet_filter and self._packet_filter.has_app_layer:
            flows = self._post_filter_flows(flows)

        # Min packets filter
        if self.min_packets > 1:
            flows = [f for f in flows if f.packet_count >= self.min_packets]

        self._stats['flows_created'] += len(flows)

        return flows

    def _convert_native_flows(self, native_flows, mgr) -> list[Flow]:
        """Convert list of NativeFlow pointers to Python Flow objects.

        Uses batch export_all_flow_data() to minimize pybind11 boundary crossings.
        """
        from wa1kpcap.core.flow import Flow, FlowKey, FlowMetrics

        all_data = mgr.export_all_flow_data()
        _from_native = Flow._from_native
        _FlowKey = FlowKey

        py_flows = []
        _append = py_flows.append
        for d in all_data:
            key = _FlowKey(
                src_ip=d[0], dst_ip=d[1],
                src_port=d[2], dst_port=d[3],
                protocol=d[4], vlan_id=d[5],
            )
            flow = _from_native(key, d[6], d[7])

            m = flow.metrics
            m.packet_count = d[8]
            m.byte_count = d[9]
            m.up_packet_count = d[10]
            m.up_byte_count = d[11]
            m.down_packet_count = d[12]
            m.down_byte_count = d[13]
            m.syn_count = d[14]
            m.fin_count = d[15]
            m.rst_count = d[16]
            m.ack_count = d[17]
            m.psh_count = d[18]
            m.urg_count = d[19]
            m.retrans_count = d[20]
            m.out_of_order_count = d[21]
            m.min_window = d[22]
            m.max_window = d[23]
            m.sum_window = d[24]

            flow._is_quic = d[25]
            flow._quic_dcid_len = d[26]

            _append(flow)

        return py_flows

    def _aggregate_native_flow_info(self, flow: Flow, nf) -> None:
        """Aggregate protocol info from C++ NativeParsedPackets to Python Flow layers.

        Iterates the C++ stored packets in the NativeFlow and converts
        protocol-layer info (TLS, DNS, QUIC, HTTP) to Python ProtocolInfo
        objects, merging them into the flow's layers dict.

        Uses inline first-wins logic to avoid creating intermediate objects
        after the first packet for each protocol.
        """
        from wa1kpcap.core.packet import TLSInfo, DNSInfo, QUICInfo

        layers = flow.layers
        tls_obj = None
        dns_obj = None
        quic_obj = None

        for cpkt in nf.packets:
            # TLS
            ct = cpkt.tls
            if ct is not None:
                if tls_obj is None:
                    sni_val = ct.sni
                    tls_obj = TLSInfo(
                        version=ct.version if ct.version else None,
                        content_type=ct.content_type if ct.content_type >= 0 else None,
                        handshake_type=ct.handshake_type if ct.handshake_type >= 0 else None,
                        record_length=ct.record_length,
                        sni=[sni_val] if sni_val and isinstance(sni_val, str) else [],
                        cipher_suites=list(ct.cipher_suites) if ct.cipher_suites else [],
                        cipher_suite=ct.cipher_suite if ct.cipher_suite >= 0 else None,
                        alpn=list(ct.alpn) if ct.alpn else [],
                        signature_algorithms=list(ct.signature_algorithms) if ct.signature_algorithms else [],
                        supported_groups=list(ct.supported_groups) if ct.supported_groups else [],
                    )
                    layers['tls_record'] = tls_obj
                else:
                    # Inline first-wins merge: only fill None/empty fields
                    if tls_obj.version is None and ct.version:
                        tls_obj.version = ct.version
                    if tls_obj.content_type is None and ct.content_type >= 0:
                        tls_obj.content_type = ct.content_type
                    if tls_obj.handshake_type is None and ct.handshake_type >= 0:
                        tls_obj.handshake_type = ct.handshake_type
                    if not tls_obj.sni and ct.sni:
                        tls_obj.sni = [ct.sni]
                    if not tls_obj.cipher_suites and ct.cipher_suites:
                        tls_obj.cipher_suites = list(ct.cipher_suites)
                    if tls_obj.cipher_suite is None and ct.cipher_suite >= 0:
                        tls_obj.cipher_suite = ct.cipher_suite
                    if not tls_obj.alpn and ct.alpn:
                        tls_obj.alpn = list(ct.alpn)

            # DNS
            cd = cpkt.dns
            if cd is not None:
                if dns_obj is None:
                    dns_obj = DNSInfo(
                        queries=list(cd.queries) if cd.queries else [],
                        response_code=cd.response_code,
                        question_count=cd.question_count,
                        answer_count=cd.answer_count,
                        authority_count=cd.authority_count,
                        additional_count=cd.additional_count,
                        flags=cd.flags,
                    )
                    layers['dns'] = dns_obj
                else:
                    if not dns_obj.queries and cd.queries:
                        dns_obj.queries = list(cd.queries)
                    if dns_obj.response_code is None and cd.response_code is not None:
                        dns_obj.response_code = cd.response_code

            # QUIC
            cq = cpkt.quic
            if cq is not None:
                if quic_obj is None:
                    quic_obj = QUICInfo(
                        is_long_header=cq.is_long_header,
                        packet_type=cq.packet_type,
                        version=cq.version,
                        dcid=bytes(cq.dcid) if cq.dcid else b'',
                        scid=bytes(cq.scid) if cq.scid else b'',
                        dcid_len=cq.dcid_len,
                        scid_len=cq.scid_len,
                        sni=cq.sni if cq.sni else None,
                        alpn=list(cq.alpn) if cq.alpn else None,
                        cipher_suites=list(cq.cipher_suites) if cq.cipher_suites else None,
                        version_str=cq.version_str if cq.version_str else '',
                        packet_type_str=cq.packet_type_str if cq.packet_type_str else '',
                    )
                    layers['quic'] = quic_obj
                else:
                    if quic_obj.sni is None and cq.sni:
                        quic_obj.sni = cq.sni
                    if quic_obj.alpn is None and cq.alpn:
                        quic_obj.alpn = list(cq.alpn)
                    if quic_obj.cipher_suites is None and cq.cipher_suites:
                        quic_obj.cipher_suites = list(cq.cipher_suites)
                    if not quic_obj.scid and cq.scid:
                        quic_obj.scid = bytes(cq.scid)
                        quic_obj.scid_len = cq.scid_len
                # Accumulate crypto_fragments across packets
                if cq.crypto_fragments:
                    quic_obj.crypto_fragments.extend(
                        (off, bytes(data)) for off, data in cq.crypto_fragments
                    )

            # HTTP is not a C++ built-in protocol — parsed in Python only
            # (via TLS reassembly or _parse_http). Skipped here.

        # QUIC: cross-packet CRYPTO frame reassembly
        if quic_obj is not None and quic_obj.sni is None:
            self._reassemble_quic_crypto(flow)

        # Build extended protocol stack
        flow.build_ext_protocol()

    def _native_tls_reassembly_pass(self, flow, nf) -> None:
        """Run TLS stream reassembly over C++ stored packets.

        Reads _raw_tcp_payload directly from NativeParsedPackets without
        materializing full Python ParsedPacket objects. Uses a lightweight
        shim packet for the reassembly callback.
        """
        if not nf.packets or flow.key.protocol != 6:
            return

        # Check if this is a TLS-relevant flow
        port = flow.key.dst_port
        sport = flow.key.src_port
        _TLS_PORTS = (443, 465, 993, 995, 5061)
        has_tls = port in _TLS_PORTS or sport in _TLS_PORTS or flow.tls is not None

        if not has_tls:
            # Check if any C++ packet detected TLS
            for cpkt in nf.packets:
                if cpkt.tls is not None:
                    has_tls = True
                    break
        if not has_tls:
            return

        # Clear flow-level TLS from single-packet C++ parse — reassembly will rebuild it
        flow.layers.pop('tls_record', None)

        # Create a lightweight shim for _handle_native_tls_reassembly
        from wa1kpcap.core.packet import ParsedPacket, TCPInfo
        shim = ParsedPacket.__new__(ParsedPacket)
        shim.layers = {}  # Required for property setters

        # Reusable TCPInfo — mutate fields instead of creating new objects
        shim_tcp = TCPInfo(sport=0, dport=0, seq=0, ack_num=0, flags=0, win=0, urgent=0, options=b'', _raw=b'')
        shim.tcp = shim_tcp

        src_ip = flow.key.src_ip
        src_port = flow.key.src_port

        for cpkt in nf.packets:
            tcp_data = cpkt._raw_tcp_payload
            if not tcp_data or cpkt.tcp is None:
                continue
            ct = cpkt.tcp
            shim_tcp.sport = ct.sport
            shim_tcp.dport = ct.dport
            shim_tcp.seq = ct.seq
            shim_tcp.ack_num = ct.ack_num
            shim_tcp.flags = ct.flags
            shim_tcp.win = ct.win
            shim.tls = None
            # Determine direction from flow key
            pkt_src_ip = cpkt.ip.src if cpkt.ip is not None else (cpkt.ip6.src if cpkt.ip6 is not None else '')
            pkt_src_port = ct.sport
            is_forward = (pkt_src_ip == src_ip and pkt_src_port == src_port)
            direction = 1 if is_forward else -1
            self._handle_native_tls_reassembly(tcp_data, shim, flow, direction)

        # Update flow-level TLS from reassembled shim
        if shim.tls is not None and flow.tls is None:
            flow.layers['tls_record'] = shim.tls

        # Store reassembled TLS for lazy packet injection
        if shim.tls is not None:
            flow._reassembled_tls = shim.tls

        # Rebuild ext_protocol since TLS info may have changed
        flow.build_ext_protocol()

    def _post_filter_flows(self, flows: list[Flow]) -> list[Flow]:
        """Filter flows based on app-layer protocol conditions.

        Used when bpf_filter contains app-layer filters like 'tls', 'dns', etc.
        These can't be evaluated at the raw-packet level in C++, so we filter
        at the flow level after protocol aggregation.
        """
        from wa1kpcap.core.filter import AppProtocolCondition, CompoundCondition

        condition = self._packet_filter.condition
        if condition is None:
            return flows

        def flow_matches(flow, cond) -> bool:
            if isinstance(cond, AppProtocolCondition):
                result = False
                if 'tls' in cond.protocols and flow.tls:
                    result = True
                if 'http' in cond.protocols and flow.http:
                    result = True
                if 'dns' in cond.protocols and flow.dns:
                    result = True
                if 'quic' in cond.protocols and flow.quic:
                    result = True
                return result != cond.negate
            elif isinstance(cond, CompoundCondition):
                if cond.operator == 'and':
                    return all(flow_matches(flow, c) for c in cond.conditions)
                elif cond.operator == 'or':
                    return any(flow_matches(flow, c) for c in cond.conditions)
                elif cond.operator == 'not' and cond.conditions:
                    return not flow_matches(flow, cond.conditions[0])
            # Non-app-layer conditions (port, ip, protocol) — already handled by C++ BPF
            return True

        return [f for f in flows if flow_matches(f, condition)]

    def _aggregate_flow_info(self, flow: Flow) -> None:
        """Aggregate packet-level protocol info to flow-level using generic merge."""
        from wa1kpcap.core.packet import ProtocolInfo, _ProtocolInfoBase, TLSInfo
        from wa1kpcap.protocols.application import TLSFlowState

        # 1. Extract TLS info from flow._tls_state (dpkt reassembly path)
        if flow._tls_state and isinstance(flow._tls_state, TLSFlowState):
            self._merge_tls_state_to_flow(flow, flow._tls_state)

        # 2. Generic merge: iterate all packets, merge each layer via ProtocolInfo.merge()
        for pkt in flow.packets:
            for layer_name, layer_info in pkt.layers.items():
                if not isinstance(layer_info, _ProtocolInfoBase):
                    continue
                existing = flow.layers.get(layer_name)
                if existing is None:
                    # First occurrence — clone with deep-copied mutables
                    flow.layers[layer_name] = layer_info.copy()
                else:
                    existing.merge(layer_info)

        # 3. Native engine: certificates from reassembly
        native_certs = getattr(flow, '_native_certs', None)
        if native_certs and flow.tls and not flow.tls.certificates:
            flow.tls.certificates = [bytes(c) for c in native_certs]
            flow.tls.certificate = flow.tls.certificates[0]

        # 4. QUIC: cross-packet CRYPTO frame reassembly and TLS ClientHello parsing
        if flow.quic and flow.quic.sni is None:
            self._reassemble_quic_crypto(flow)

        # 4b. QUIC: fill server SCID from first packet that has a non-empty scid
        if flow.quic and not flow.quic.scid:
            for pkt in flow.packets:
                q = pkt.quic
                if q and q.scid:
                    flow.quic.scid = q.scid
                    flow.quic.scid_len = q.scid_len
                    break

        # 5. Build extended protocol stack
        flow.build_ext_protocol()

    def _reassemble_quic_crypto(self, flow: Flow) -> None:
        """Reassemble CRYPTO fragments across packets and parse TLS ClientHello."""
        import struct

        # Use pre-accumulated crypto_fragments on flow.quic (from aggregation),
        # falling back to per-packet iteration for the old Python pipeline path.
        all_fragments = getattr(flow.quic, 'crypto_fragments', None) or []
        if not all_fragments:
            for pkt in flow.packets:
                q = pkt.quic
                if q is None:
                    continue
                frags = getattr(q, 'crypto_fragments', None)
                if frags:
                    all_fragments.extend(frags)

        if not all_fragments:
            return

        # Sort by offset and reassemble
        all_fragments.sort(key=lambda x: x[0])
        max_end = max(off + len(data) for off, data in all_fragments)
        if max_end > 65536:
            max_end = 65536
        reassembled = bytearray(max_end)
        for off, data in all_fragments:
            if off < max_end:
                end = min(off + len(data), max_end)
                reassembled[off:end] = data[:end - off]

        # Need at least TLS handshake header (4 bytes)
        if len(reassembled) < 4 or reassembled[0] != 1:
            return  # Not a ClientHello

        # Parse via native engine's TLS handshake parser
        try:
            from wa1kpcap.native import _wa1kpcap_native as _native
            if _native is None:
                return
            parser = self._native_engine._parser
            tls_pkt = parser.parse_from_protocol(bytes(reassembled), "tls_handshake")
            if tls_pkt.tls is not None:
                q = flow.quic
                if tls_pkt.tls.sni:
                    q.sni = tls_pkt.tls.sni
                if tls_pkt.tls.alpn:
                    q.alpn = tls_pkt.tls.alpn
                if tls_pkt.tls.cipher_suites:
                    q.cipher_suites = tls_pkt.tls.cipher_suites
        except Exception:
            pass

    def _merge_tls_state_to_flow(self, flow: Flow, tls_state) -> None:
        """Convert TLSFlowState (dpkt reassembly) into flow.tls via merge."""
        from wa1kpcap.core.packet import TLSInfo

        if not flow.tls:
            flow.tls = TLSInfo(version=tls_state.version, content_type=22, record_length=0)

        if not flow.tls.version and tls_state.version:
            flow.tls.version = tls_state.version
        if tls_state.sni:
            flow.tls.sni.extend(tls_state.sni)
        if tls_state.alpn:
            flow.tls.alpn.extend(tls_state.alpn)
        if tls_state.c_ciphersuites:
            flow.tls.cipher_suites.extend(tls_state.c_ciphersuites)
        if tls_state.s_ciphersuite and not flow.tls.cipher_suite:
            flow.tls.cipher_suite = tls_state.s_ciphersuite
        if tls_state.signature_algorithms:
            flow.tls.signature_algorithms.extend(tls_state.signature_algorithms)
        if tls_state.supported_groups:
            flow.tls.supported_groups.extend(tls_state.supported_groups)
        if tls_state.exts:
            for ext_type, ext_data_list in tls_state.exts.items():
                if ext_type not in flow.tls.exts:
                    flow.tls.exts[ext_type] = []
                for ext_data in ext_data_list:
                    ext_bytes = bytes(ext_data)
                    if ext_bytes not in flow.tls.exts[ext_type]:
                        flow.tls.exts[ext_type].append(ext_bytes)
            for ext_type, ext_data_list in tls_state.exts.items():
                for ext_data in ext_data_list:
                    ext_tuple = (ext_type, bytes(ext_data))
                    if ext_tuple not in flow.tls.extensions:
                        flow.tls.extensions.append(ext_tuple)
        if tls_state.certs and not flow.tls.certificates:
            flow.tls.certificates = [bytes(c) for c in tls_state.certs]
            flow.tls.certificate = flow.tls.certificates[0]

    def _process_packet(self, ts: float, buf: bytes, reader: PcapReader) -> None:
        """Process a single packet."""
        self._stats['packets_processed'] += 1

        # Parse packet (basic parsing, no transport layer yet for fragmented packets)
        pkt = self._parse_packet(ts, buf, reader)
        if not pkt:
            return

        # Handle IP fragmentation
        if self.enable_reassembly and pkt.ip and pkt.ip.is_fragment:
            # Use IP fragment reassembly
            # For ALL fragments (including offset=0), use reassembler
            reassembled = self._handle_ip_fragment(pkt)
            if reassembled is None:
                # Fragment not complete yet, don't add packet yet
                return
            # Reassembly complete - update this packet with reassembled data
            # This packet (the one that completed reassembly) will be added to flow
            # Clear the fragment flag so it's treated as a normal packet
            self._reparse_transport_layer(reassembled, pkt)
            # Mark as not a fragment anymore - update IPInfo to clear fragment flags
            if pkt.ip:
                pkt.ip.flags = 0  # Clear fragment flags
                pkt.ip.offset = 0  # Clear offset
                # pkt.ip.len should be updated to match pkt.ip_len (already updated in _reparse_transport_layer)
                pkt.ip.len = pkt.ip_len
            # Continue to add this packet to flow
        elif not self.enable_reassembly and pkt.ip and pkt.ip.offset > 0:
            # Non-initial fragment without reassembly - skip
            return

        # Apply filters
        if self._should_filter(pkt):
            self._stats['packets_filtered'] += 1
            return

        # Post-parse BPF filter check (for application layer protocols)
        if self._packet_filter and not self._packet_filter.post_check(pkt):
            self._stats['packets_filtered'] += 1
            return

        # Get or create flow
        flow = self._flow_manager.get_or_create_flow(pkt)
        if not flow:
            return

        # TCP retransmission detection
        if pkt.tcp:
            is_retrans = self._check_retransmission(pkt, flow)
            if is_retrans:
                flow.metrics.retrans_count += 1
                if self.filter_retrans:
                    self._stats['packets_filtered'] += 1
                    return

        # Update packet index
        pkt.packet_index = len(flow.packets)
        pkt.flow_index = self._stats['flows_created']

        # Handle TCP stream reassembly and application layer parsing
        if pkt.tcp and hasattr(pkt, '_raw_tcp_payload'):
            self._handle_tcp_reassembly(pkt, flow)

        # QUIC flow state: mark flow on Long Header, parse Short Header
        self._handle_quic_flow_state(pkt, flow)

        # Add packet to flow
        flow.add_packet(pkt)

    def _parse_packet(self, ts: float, buf: bytes, reader: PcapReader) -> ParsedPacket | None:
        """Parse a packet into ParsedPacket."""
        pkt = ParsedPacket(
            timestamp=ts,
            raw_data=buf,
            link_layer_type=reader.link_layer_type,
            caplen=len(buf),
            wirelen=len(buf)
        )

        # Parse protocol stack (single pass — dpkt auto-nests all layers)
        self._parse_protocols(buf, pkt, reader)

        return pkt

    def _parse_protocols(self, buf: bytes, pkt: ParsedPacket, reader: PcapReader) -> None:
        """Parse protocol layers.

        Uses dpkt's auto-nested parsing: dpkt.ethernet.Ethernet(buf) parses all
        layers at once. eth.data is already a dpkt.ip.IP object, ip.data is
        already a dpkt.tcp.TCP object, etc. We reuse these objects directly
        instead of serializing back to bytes and re-parsing.
        """
        import dpkt

        from wa1kpcap.core.packet import (
            EthernetInfo, IPInfo, IP6Info, TCPInfo, UDPInfo,
        )

        # ── Step 1: Link layer → obtain IP object ──
        link_type = reader.link_layer_name
        ip = None
        ip6 = None

        if link_type == "ethernet":
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                pkt.eth = EthernetInfo.from_dpkt(eth)
                net_obj = eth.data  # already parsed by dpkt
            except Exception:
                return

            if isinstance(net_obj, dpkt.ip.IP):
                ip = net_obj
            elif isinstance(net_obj, dpkt.ip6.IP6):
                ip6 = net_obj
            else:
                return

        elif link_type == "linux_sll":
            if len(buf) < 16:
                return
            proto = int.from_bytes(buf[14:16], 'big')
            sll_data = buf[16:]
            if not sll_data:
                return
            try:
                if proto == 0x0800:
                    ip = dpkt.ip.IP(sll_data)
                elif proto == 0x86DD:
                    ip6 = dpkt.ip6.IP6(sll_data)
                else:
                    return
            except Exception:
                return

        else:
            # raw_ip and other link types: treat buf as raw IP
            raw = buf if link_type == "raw_ip" else buf
            if len(raw) < 1:
                return
            v = (raw[0] >> 4) & 0x0F
            try:
                if v == 4:
                    ip = dpkt.ip.IP(raw)
                elif v == 6:
                    ip6 = dpkt.ip6.IP6(raw)
                else:
                    return
            except Exception:
                return

        # ── Step 2: Network layer ──
        ip_frag_offset = 0
        ip_is_fragment = False

        if ip is not None:
            pkt.ip = IPInfo.from_dpkt(ip)
            pkt.ip_len = ip.len

            # Fragment check using non-deprecated attributes
            ip_frag_offset = ip.offset
            ip_is_fragment = (ip_frag_offset > 0) or ip.mf

            transport = ip.data  # already parsed by dpkt
            proto = ip.p

        elif ip6 is not None:
            pkt.ip6 = IP6Info.from_dpkt(ip6)
            pkt.ip_len = 40 + ip6.plen

            transport = ip6.data  # already parsed by dpkt
            proto = ip6.nxt
        else:
            return

        # Skip transport parsing for non-initial IP fragments
        if ip_is_fragment and ip_frag_offset > 0:
            return

        # ── Step 3: Transport layer ──
        if isinstance(transport, dpkt.tcp.TCP):
            tcp = transport
            pkt.tcp = TCPInfo.from_dpkt(tcp)

            pkt.trans_len = len(tcp)           # header + options + payload
            pkt.app_len = len(tcp.data)        # payload only
            pkt._raw_tcp_payload = tcp.data    # already bytes

        elif isinstance(transport, dpkt.udp.UDP):
            udp = transport
            pkt.udp = UDPInfo.from_dpkt(udp)

            pkt.trans_len = len(udp)           # header + payload
            pkt.app_len = len(udp.data)        # payload only
            pkt._raw_tcp_payload = udp.data    # reuse field for app payload

            if udp.sport == 53 or udp.dport == 53:
                if self._app_layer_mode == 0:  # full only
                    self._parse_dns(udp.data, pkt)

        elif proto == 6 or proto == 17:
            # Fallback: transport is raw bytes (dpkt failed to parse)
            if not isinstance(transport, bytes) or not transport:
                return
            try:
                if proto == 6:
                    tcp = dpkt.tcp.TCP(transport)
                    pkt.tcp = TCPInfo.from_dpkt(tcp)
                    pkt.trans_len = len(tcp)
                    pkt.app_len = len(tcp.data)
                    pkt._raw_tcp_payload = tcp.data
                else:
                    udp = dpkt.udp.UDP(transport)
                    pkt.udp = UDPInfo.from_dpkt(udp)
                    pkt.trans_len = len(udp)
                    pkt.app_len = len(udp.data)
                    pkt._raw_tcp_payload = udp.data
                    if udp.sport == 53 or udp.dport == 53:
                        if self._app_layer_mode == 0:  # full only
                            self._parse_dns(udp.data, pkt)
            except Exception:
                pass

    def _parse_application(self, data: bytes, pkt: ParsedPacket) -> None:
        """Parse application layer protocols."""
        if not data or self._app_layer_mode >= 2:  # none: skip all
            return

        # Check for TLS (port 443, 465, 993, 995)
        if pkt.tcp:
            port = pkt.tcp.dport if pkt.tcp else 0
            sport = pkt.tcp.sport if pkt.tcp else 0

            # port_only (1) and above: skip TLS/HTTP (slow-path protocols)
            if self._app_layer_mode >= 1:
                return

            if port in (443, 465, 993, 995) or sport in (443, 465, 993, 995):
                self._parse_tls(data, pkt)

            # Check for HTTP
            if port in (80, 8080, 8000) or sport in (80, 8080, 8000):
                self._parse_http(data, pkt, sport < port)

    def _parse_tls(self, data: bytes, pkt: ParsedPacket) -> None:
        """Parse TLS record."""
        if len(data) < 5:
            return

        # TLS record header
        content_type = data[0]
        major = data[1]
        minor = data[2]

        if major != 3:  # SSL 3.0 / TLS 1.0-1.3
            return

        try:
            length = int.from_bytes(data[3:5], 'big')

            from wa1kpcap.core.packet import TLSInfo
            tls_info = TLSInfo(
                version=f"{major}.{minor}",
                content_type=content_type,
                record_length=length
            )

            # Parse handshake
            if content_type == 22 and len(data) >= 6:
                handshake_type = data[5]
                tls_info.handshake_type = handshake_type

                # Parse ClientHello for SNI
                if handshake_type == 1:
                    sni = self._extract_sni(data[6:6+length])
                    if sni:
                        tls_info.sni = sni
                # Parse ServerHello for cipher suite
                elif handshake_type == 2:
                    cipher_suite = self._extract_cipher_suite(data[6:6+length])
                    if cipher_suite:
                        tls_info.cipher_suite = cipher_suite

            pkt.tls = tls_info
        except Exception:
            pass

    def _extract_sni(self, data: bytes) -> str | None:
        """Extract SNI from ClientHello."""
        # Simplified SNI extraction
        try:
            # Look for SNI extension (type 0)
            idx = data.find(b'\x00\x00')
            if idx >= 0 and idx + 6 < len(data):
                ext_len = int.from_bytes(data[idx+4:idx+6], 'big')
                if idx + 6 + ext_len <= len(data):
                    sni_data = data[idx+6:idx+6+ext_len]
                    # Skip list length and entry type
                    if len(sni_data) >= 7:
                        sni_len = int.from_bytes(sni_data[3:5], 'big')
                        if 5 + sni_len <= len(sni_data):
                            return sni_data[5:5+sni_len].decode('ascii', errors='ignore')
        except Exception:
            pass
        return None

    def _extract_cipher_suite(self, data: bytes) -> int | None:
        """Extract cipher suite from ServerHello."""
        try:
            # ServerHello: version (2) + random (32) + session_id (1+len) + cipher_suite (2)
            if len(data) >= 36:
                # Skip version (2) + random (32) = 34
                session_id_len = data[34]
                if 35 + session_id_len + 2 <= len(data):
                    cipher_suite = int.from_bytes(data[35+session_id_len:37+session_id_len], 'big')
                    return cipher_suite
        except Exception:
            pass
        return None

    def _parse_http(self, data: bytes, pkt: ParsedPacket, is_client: bool) -> None:
        """Parse HTTP request or response."""
        try:
            text = data.decode('ascii', errors='ignore')
            lines = text.split('\r\n', 10)

            if not lines:
                return

            first_line = lines[0]

            from wa1kpcap.core.packet import HTTPInfo

            if is_client and ' ' in first_line:
                # Request
                parts = first_line.split()
                if len(parts) >= 2:
                    http_info = HTTPInfo(
                        method=parts[0],
                        path=parts[1]
                    )

                    # Parse headers
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            if key == 'host':
                                http_info.host = value
                            elif key == 'user-agent':
                                http_info.user_agent = value

                    pkt.http = http_info

            elif not is_client and first_line.startswith('HTTP/'):
                # Response
                parts = first_line.split()
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                        http_info = HTTPInfo(
                            status_code=status_code,
                            status_reason=' '.join(parts[2:]) if len(parts) > 2 else None
                        )
                        pkt.http = http_info
                    except ValueError:
                        pass
        except Exception:
            pass

    def _parse_dns(self, data: bytes, pkt: ParsedPacket) -> None:
        """Parse DNS message."""
        try:
            import dpkt
            dns = dpkt.dns.DNS(data)

            queries = [q.name for q in dns.qd] if dns.qd else []

            from wa1kpcap.core.packet import DNSInfo
            pkt.dns = DNSInfo(
                queries=queries,
                response_code=dns.rcode,
                question_count=len(dns.qd),
                answer_count=len(dns.an),
                authority_count=len(dns.ns),
                additional_count=len(dns.ar),
                flags=dns.op
            )
        except Exception:
            pass

    def _should_filter(self, pkt: ParsedPacket) -> bool:
        """Check if packet should be filtered out."""
        # Filter RST packets
        if self.filter_rst and pkt.tcp and pkt.tcp.rst:
            return True

        # Filter pure ACK packets
        if self.filter_ack and pkt.tcp:
            # Pure ACK has only ACK flag set, no TCP options, and no payload
            is_pure_ack = (pkt.tcp.flags == 0x10 and not pkt.tcp.options and pkt.app_len == 0)
            if is_pure_ack:
                return True

        return False

    def _check_retransmission(self, pkt: ParsedPacket, flow: Flow) -> bool:
        """Check if a TCP packet is a retransmission.

        Tracks the maximum (seq + payload_len) per direction. A packet is
        considered a retransmission if it carries payload and its entire
        sequence range has already been seen.

        Args:
            pkt: Parsed TCP packet
            flow: Flow the packet belongs to

        Returns:
            True if the packet is a retransmission
        """
        # SYN and FIN each consume 1 sequence number
        seq_len = pkt.app_len
        flags = pkt.tcp.flags
        if flags & 0x02:  # SYN
            seq_len += 1
        if flags & 0x01:  # FIN
            seq_len += 1
        if seq_len == 0:
            return False

        seq = pkt.tcp.seq
        seq_end = (seq + seq_len) & 0xFFFFFFFF

        direction = flow.key.direction(
            pkt.ip.src if pkt.ip else pkt.ip6.src if pkt.ip6 else "",
            pkt.tcp.sport
        )

        next_seq = flow._next_seq.get(direction)
        if next_seq is None:
            # First data packet in this direction
            flow._next_seq[direction] = seq_end
            return False

        # TCP Keep-Alive: seq == next_seq - 1, payload <= 1 byte, no SYN/FIN
        # These probe the connection and are not real retransmissions.
        if pkt.app_len <= 1 and not (flags & 0x03):  # no SYN/FIN
            if (seq - (next_seq - 1)) & 0xFFFFFFFF == 0:
                return False

        # Handle TCP sequence number wraparound (32-bit)
        # Use signed difference to handle wrap correctly
        diff = (seq_end - next_seq) & 0xFFFFFFFF
        if diff == 0:
            # Exact duplicate of last boundary — retransmission
            return True
        if diff < 0x80000000:
            # seq_end > next_seq (new data), advance tracker
            flow._next_seq[direction] = seq_end & 0xFFFFFFFF
            return False
        else:
            # seq_end < next_seq (already seen) — retransmission
            return True

    def _make_flow_key_for_reassembly(self, flow: Flow) -> str:
        """Create flow key string for reassembly."""
        return f"{flow.key.src_ip}:{flow.key.src_port}:{flow.key.dst_ip}:{flow.key.dst_port}:{flow.key.protocol}"

    def _is_packet_forward(self, pkt: ParsedPacket, flow: Flow) -> bool:
        """Determine if packet is in forward direction."""
        if pkt.ip:
            return (pkt.ip.src == flow.key.src_ip and
                    (pkt.tcp.sport if pkt.tcp else 0) == flow.key.src_port)
        elif pkt.ip6:
            return (pkt.ip6.src == flow.key.src_ip and
                    (pkt.tcp.sport if pkt.tcp else 0) == flow.key.src_port)
        return True

    def _handle_quic_flow_state(self, pkt, flow) -> None:
        """Track QUIC flow state and parse Short Header packets.

        When a QUIC Long Header (Initial) is seen, mark the flow as QUIC
        and record the DCID length. For subsequent UDP packets on the same
        flow that weren't identified as QUIC, try to parse as Short Header.
        """
        from wa1kpcap.core.packet import QUICInfo

        q = pkt.quic
        if q is not None and q.is_long_header:
            # Long Header seen — mark flow as QUIC
            flow._is_quic = True
            if q.dcid_len > 0:
                flow._quic_dcid_len = q.dcid_len
            return

        if q is not None:
            # Already parsed as QUIC (shouldn't happen for short header yet, but guard)
            return

        # Not identified as QUIC — check if this is a UDP packet on a QUIC flow
        if not flow._is_quic or not pkt.udp:
            return

        # Try to parse as QUIC Short Header (1-RTT)
        raw = pkt.raw_data
        if not raw:
            return

        # Compute UDP payload offset: link + IP + UDP(8)
        # Use the stored lengths from parsing
        udp_payload_offset = pkt.caplen - pkt.app_len
        if udp_payload_offset < 0 or pkt.app_len < 2:
            return

        buf = raw[udp_payload_offset:] if isinstance(raw, (bytes, memoryview)) else bytes(raw)[udp_payload_offset:]
        if len(buf) < 2:
            return

        first = buf[0]
        # Short Header: bit 7 = 0, Fixed Bit (bit 6) = 1
        if (first & 0x80) != 0 or (first & 0x40) == 0:
            return

        # Parse spin bit (bit 5)
        spin_bit = bool(first & 0x20)

        # Extract DCID using known length from flow state
        dcid_len = flow._quic_dcid_len
        if len(buf) < 1 + dcid_len:
            return
        dcid = bytes(buf[1:1 + dcid_len])

        pkt.quic = QUICInfo(
            is_long_header=False,
            spin_bit=spin_bit,
            dcid=dcid,
            dcid_len=dcid_len,
            packet_type_str="1-RTT",
        )

    def _handle_tcp_reassembly(self, pkt: ParsedPacket, flow: Flow) -> None:
        """Handle TCP stream reassembly and application layer parsing.

        Args:
            pkt: Parsed packet with TCP layer
            flow: Flow object (already created)
        """
        # app_layer_mode >= 2 (none): skip all post-transport parsing
        if self._app_layer_mode >= 2:
            return

        tcp_data = getattr(pkt, '_raw_tcp_payload', b'')
        if not tcp_data and not pkt.tcp:
            return

        # Native engine: handle TLS reassembly in Python, parse via C++ engine.
        if self._engine == "native":
            if tcp_data and pkt.tcp:
                # app_layer_mode >= 1 (port_only): skip TLS/HTTP (slow-path)
                if self._app_layer_mode >= 1:
                    return
                port = pkt.tcp.dport
                sport = pkt.tcp.sport
                is_tls_port = port in (443, 465, 993, 995, 5061) or sport in (443, 465, 993, 995, 5061)
                flow_has_tls = getattr(flow, '_native_tls_detected', False)

                if is_tls_port or flow_has_tls:
                    if pkt.tls is not None:
                        flow._native_tls_detected = True
                    # Clear TLS info from initial C++ parse — the reassembly
                    # code will re-parse with proper CCS state tracking.
                    pkt.tls = None
                    is_forward = self._is_packet_forward(pkt, flow)
                    direction = 1 if is_forward else -1
                    self._handle_native_tls_reassembly(tcp_data, pkt, flow, direction)
                elif pkt.tls is not None:
                    # Heuristic detected TLS on non-standard port — mark and re-parse
                    flow._native_tls_detected = True
                    pkt.tls = None
                    is_forward = self._is_packet_forward(pkt, flow)
                    direction = 1 if is_forward else -1
                    self._handle_native_tls_reassembly(tcp_data, pkt, flow, direction)
                # HTTP ports
                elif port in (80, 8080, 8000) or sport in (80, 8080, 8000):
                    self._parse_http(tcp_data, pkt, sport < port)
            return

        # Determine direction (1 = forward/C2S, -1 = reverse/S2C)
        is_forward = self._is_packet_forward(pkt, flow)
        direction = 1 if is_forward else -1

        # Parse application layer protocols using the new parse_tls approach
        # This handles TLS record reassembly internally via data buffering
        if tcp_data and self._app_layer_mode == 0:  # full only
            self._parse_application_with_buffering(tcp_data, pkt, flow, direction)

    def _handle_native_tls_reassembly(
        self, data: bytes, pkt: ParsedPacket, flow: Flow, direction: int
    ) -> None:
        """Buffer TCP payload, extract complete TLS records, parse via C++ engine.

        The C++ parse_tls_record now handles multi-record and multi-handshake
        splitting internally via parse_tls_stream. Python only needs to manage
        the incomplete-data buffer and CCS skip state.
        """
        buf = flow._tls_incomplete_data.get(direction, b"")
        full = buf + data

        # After ChangeCipherSpec, the next handshake record is the encrypted
        # Finished — skip it, then resume parsing (handles renegotiation).
        ccs_skip = getattr(flow, '_tls_ccs_skip', set())

        offset = 0
        while offset + 5 <= len(full):
            content_type = full[offset]
            if content_type not in (20, 21, 22, 23):  # Not a valid TLS record type
                break
            record_len = int.from_bytes(full[offset + 3:offset + 5], 'big')
            if record_len > 16384 + 256:  # Sanity check
                break
            if offset + 5 + record_len > len(full):
                break  # Incomplete record, wait for more data

            if content_type == 20:  # ChangeCipherSpec
                ccs_skip.add(direction)
                flow._tls_ccs_skip = ccs_skip
            elif content_type == 22:
                if direction in ccs_skip:
                    # Validate: real plaintext handshake vs encrypted Finished
                    body = full[offset + 5:offset + 5 + record_len]
                    is_valid_hs = (
                        len(body) >= 4
                        and int.from_bytes(body[1:4], 'big') == len(body) - 4
                    )
                    ccs_skip.discard(direction)
                    flow._tls_ccs_skip = ccs_skip
                    if is_valid_hs:
                        record = full[offset:offset + 5 + record_len]
                        self._parse_native_tls_chunk(record, pkt, flow)
                    # else: encrypted Finished — skip
                else:
                    record = full[offset:offset + 5 + record_len]
                    self._parse_native_tls_chunk(record, pkt, flow)
            elif content_type == 23:  # Application Data
                # Ensure pkt.tls is set so app-data-only flows are counted
                if pkt.tls is None:
                    from wa1kpcap.core.packet import TLSInfo
                    pkt.tls = TLSInfo(content_type=23)
            offset += 5 + record_len

        flow._tls_incomplete_data[direction] = full[offset:]

    def _parse_native_tls_chunk(
        self, record: bytes, pkt: ParsedPacket, flow: Flow
    ) -> None:
        """Parse a TLS chunk (one or more records) via C++ engine, merge into pkt.tls."""
        from wa1kpcap.core.packet import TLSInfo

        result = self._native_engine.parse_tls_record(record)
        if result is None:
            return

        tls = result.tls
        if tls is None:
            return

        # Track all handshake types seen in this flow
        ht_list = getattr(tls, 'handshake_types', None)
        hs_types = ht_list or ([tls.handshake_type] if tls.handshake_type >= 0 else [])

        # Extract raw certificates from Certificate handshake (type 11)
        if 11 in hs_types:
            self._extract_native_certs(record, flow)

        # Convert NativeTLSInfo to TLSInfo
        sni_val = tls.sni
        sni_list = [sni_val] if sni_val and isinstance(sni_val, str) else []
        parsed = TLSInfo(
            version=tls.version if tls.version else None,
            content_type=tls.content_type if tls.content_type >= 0 else None,
            handshake_type=tls.handshake_type if tls.handshake_type >= 0 else None,
            record_length=tls.record_length,
            sni=sni_list,
            cipher_suites=list(tls.cipher_suites) if tls.cipher_suites else [],
            cipher_suite=tls.cipher_suite if tls.cipher_suite >= 0 else None,
            alpn=list(tls.alpn) if tls.alpn else [],
            signature_algorithms=list(tls.signature_algorithms) if tls.signature_algorithms else [],
            supported_groups=list(tls.supported_groups) if tls.supported_groups else [],
            _handshake_types=list(hs_types),
        )

        # Merge into packet's TLS info
        if pkt.tls is None:
            pkt.tls = parsed
        else:
            pkt.tls.merge(parsed)

    def _extract_native_certs(self, record: bytes, flow: Flow) -> None:
        """Extract raw DER certificates from a TLS Certificate handshake record.

        TLS record format: [content_type(1)][version(2)][length(2)][body...]
        Handshake body:    [hs_type(1)][hs_length(3)][certs_length(3)][cert_list...]
        Each cert:         [cert_length(3)][DER bytes...]
        """
        if len(record) < 5:
            return
        body = record[5:]  # skip TLS record header
        # Walk handshake messages in the body
        off = 0
        while off + 4 <= len(body):
            hs_type = body[off]
            hs_len = int.from_bytes(body[off + 1:off + 4], 'big')
            if off + 4 + hs_len > len(body):
                break
            if hs_type == 11:  # Certificate
                hs_body = body[off + 4:off + 4 + hs_len]
                if len(hs_body) < 3:
                    break
                certs_len = int.from_bytes(hs_body[0:3], 'big')
                certs_data = hs_body[3:3 + certs_len]
                certs = []
                c_off = 0
                while c_off + 3 <= len(certs_data):
                    c_len = int.from_bytes(certs_data[c_off:c_off + 3], 'big')
                    if c_off + 3 + c_len > len(certs_data):
                        break
                    certs.append(certs_data[c_off + 3:c_off + 3 + c_len])
                    c_off += 3 + c_len
                if certs:
                    if not hasattr(flow, '_native_certs'):
                        flow._native_certs = []
                    flow._native_certs = certs
            off += 4 + hs_len

    def _parse_application_with_buffering(
        self, data: bytes, pkt: ParsedPacket, flow: Flow, direction: int
    ) -> None:
        """Parse application layer with per-flow data buffering.

        - Buffers incomplete TLS data between packets
        - Uses parse_tls which returns (TLSFlowState, bytes_parsed)
        - Stores unprocessed data for next packet

        Args:
            data: TCP payload data
            pkt: Parsed packet
            flow: Flow object
            direction: 1 for forward/C2S, -1 for reverse/S2C
        """
        if not data:
            return

        # Check for TLS by port
        if pkt.tcp:
            port = pkt.tcp.dport if pkt.tcp else 0
            sport = pkt.tcp.sport if pkt.tcp else 0

            # TLS ports
            if port in (443, 465, 993, 995, 5061) or sport in (443, 465, 993, 995, 5061):
                self._parse_tls_with_buffering(data, pkt, flow, direction)
            # HTTP ports
            elif port in (80, 8080, 8000) or sport in (80, 8080, 8000):
                self._parse_http(data, pkt, sport < port)

    def _parse_tls_with_buffering(
        self, data: bytes, pkt: ParsedPacket, flow: Flow, direction: int
    ) -> None:
        """Parse TLS with per-flow incomplete data buffering."""
        from wa1kpcap.protocols.application import parse_tls, TLSFlowState
        from wa1kpcap.core.packet import TLSInfo

        # Get or create TLS incomplete data buffer for this direction
        incomplete_data = flow._tls_incomplete_data.get(direction, b"")

        # Get or create TLS state for this flow
        tls_state = flow._tls_state
        if not isinstance(tls_state, TLSFlowState):
            tls_state = TLSFlowState()
            flow._tls_state = tls_state

        # Combine buffered data with new data
        full_data = incomplete_data + data

        # Parse TLS using tls_multi_factory approach
        parsed_tls, parsed_length = parse_tls(full_data, tls_state)

        # Store updated TLS state
        flow._tls_state = parsed_tls

        # Buffer unprocessed data for next packet
        if parsed_length < len(full_data):
            flow._tls_incomplete_data[direction] = full_data[parsed_length:]
        else:
            flow._tls_incomplete_data[direction] = b""

        # Create TLSInfo from parsed state for this packet
        tls_info = TLSInfo(
            version=parsed_tls.version,
            content_type=22,  # Handshake
            record_length=0
        )

        # Set handshake type if we have ClientHello/ServerHello
        if parsed_tls.c_ciphersuites:
            tls_info.handshake_type = 1  # ClientHello
            tls_info.cipher_suites = parsed_tls.c_ciphersuites

        if parsed_tls.s_ciphersuite:
            tls_info.handshake_type = 2  # ServerHello
            tls_info.cipher_suite = parsed_tls.s_ciphersuite.name if hasattr(parsed_tls.s_ciphersuite, 'name') else str(parsed_tls.s_ciphersuite)

        # Set SNI and ALPN (as lists)
        if parsed_tls.sni:
            tls_info.sni = list(parsed_tls.sni)
        if parsed_tls.alpn:
            tls_info.alpn = list(parsed_tls.alpn)

        # Set signature algorithms and supported groups
        if parsed_tls.signature_algorithms:
            tls_info.signature_algorithms = list(parsed_tls.signature_algorithms)
        if parsed_tls.supported_groups:
            tls_info.supported_groups = list(parsed_tls.supported_groups)

        # Set extensions (as dict)
        if parsed_tls.exts:
            for ext_type, ext_data_list in parsed_tls.exts.items():
                if ext_type not in tls_info.exts:
                    tls_info.exts[ext_type] = []
                for ext_data in ext_data_list:
                    ext_bytes = bytes(ext_data)
                    if ext_bytes not in tls_info.exts[ext_type]:
                        tls_info.exts[ext_type].append(ext_bytes)

            # Also populate legacy extensions list for backward compatibility
            for ext_type, ext_data_list in parsed_tls.exts.items():
                for ext_data in ext_data_list:
                    ext_tuple = (ext_type, bytes(ext_data))
                    if ext_tuple not in tls_info.extensions:
                        tls_info.extensions.append(ext_tuple)

        # Set raw DER certificate bytes if available
        if parsed_tls.certs:
            tls_info.certificates = [bytes(c) for c in parsed_tls.certs]
            tls_info.certificate = tls_info.certificates[0]

        # Attach to packet (may fail for NativeParsedPacket C++ struct)
        try:
            pkt.tls = tls_info
        except TypeError:
            pass  # flow._tls_state still has all the info

    def _handle_ip_fragment(self, pkt: ParsedPacket) -> bytes | None:
        """Handle IP fragment reassembly.

        Args:
            pkt: Packet with IP layer

        Returns:
            Reassembled payload if complete, None if more fragments needed
        """
        if not pkt.ip:
            return None

        ip = pkt.ip
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto
        ip_id = ip.id
        offset = ip.offset
        is_last = not ip.more_fragments

        # Get IP payload from raw_data
        # Find where IP layer starts in raw_data
        ip_start = 0
        if pkt.eth:
            ip_start = 14  # Ethernet header is 14 bytes
        elif pkt.link_layer_type == "linux_sll":
            ip_start = 16  # SLL header is 16 bytes
        # else raw_ip, ip_start = 0

        # IP header length is in the lower 4 bits of the first byte
        # But we need to get it from raw_data since IPInfo doesn't store hl
        ip_header_start = ip_start + 12  # Skip to the 12th byte (after src/dst IPs might vary)
        # Actually, let's use the raw dpkt object if available
        import dpkt

        # Parse IP header length from raw_data
        # First byte of IP header: version (4 bits) + IHL (4 bits)
        ip_first_byte = pkt.raw_data[ip_start]
        ip_header_len = (ip_first_byte & 0x0F) * 4  # IHL is in 32-bit words

        payload = pkt.raw_data[ip_start + ip_header_len:]

        # Add to reassembler
        reassembled, is_complete = self._ip_reassembler.add_fragment(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            ip_id=ip_id,
            offset=offset,
            data=payload,
            is_last=is_last
        )

        return reassembled if is_complete else None

    def _reparse_transport_layer(self, data: bytes, pkt: ParsedPacket) -> None:
        """Re-parse transport layer with reassembled data.

        Args:
            data: Reassembled transport layer payload
            pkt: Packet to update with transport layer info
        """
        if not pkt.ip:
            return

        protocol = pkt.ip.proto

        # Update packet length to reflect reassembled size
        # Calculate new total length: original headers + reassembled payload
        header_len = 0
        if pkt.eth:
            header_len = 14  # Ethernet header
        elif pkt.link_layer_type == "linux_sll":
            header_len = 16  # SLL header

        # Add IP header length (usually 20 bytes)
        ip_first_byte = pkt.raw_data[header_len]
        ip_header_len = (ip_first_byte & 0x0F) * 4
        header_len += ip_header_len

        # Update ip_len to reflect reassembled IP total length
        # ip_len = IP header length + transport payload length
        pkt.ip_len = ip_header_len + len(data)

        # Update wirelen to reflect reassembled packet
        original_wirelen = pkt.wirelen
        pkt.wirelen = header_len + len(data)
        pkt.caplen = max(pkt.caplen, pkt.wirelen)

        if protocol == 6:  # TCP
            try:
                import dpkt
                tcp = dpkt.tcp.TCP(data)
                from wa1kpcap.core.packet import TCPInfo
                pkt.tcp = TCPInfo.from_dpkt(tcp)

                pkt.trans_len = len(tcp)
                pkt.app_len = len(tcp.data)

                # Parse application layer protocols
                self._parse_application(tcp.data, pkt)
            except Exception:
                pass
        elif protocol == 17:  # UDP
            try:
                import dpkt
                udp = dpkt.udp.UDP(data)
                from wa1kpcap.core.packet import UDPInfo
                pkt.udp = UDPInfo.from_dpkt(udp)

                pkt.trans_len = len(udp)
                pkt.app_len = len(udp.data)

                # Parse DNS on UDP
                if (pkt.udp.sport == 53 or pkt.udp.dport == 53):
                    self._parse_dns(udp.data, pkt)
            except Exception:
                pass

    @property
    def stats(self) -> dict[str, Any]:
        """Get analysis statistics."""
        return self._stats.copy()

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats = {
            'files_processed': 0,
            'packets_processed': 0,
            'packets_filtered': 0,
            'flows_created': 0,
            'errors': []
        }


# Export main class
__all__ = ['Wa1kPcap']
