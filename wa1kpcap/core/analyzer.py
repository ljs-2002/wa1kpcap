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
    ):
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

        # Custom features - registered by name
        self._custom_features: dict[str, BaseIncrementalFeature] = {}

        # Native engine (required)
        from wa1kpcap.native import NATIVE_AVAILABLE
        if not NATIVE_AVAILABLE:
            raise RuntimeError(
                "Native C++ engine not available. "
                "Install with: pip install -e ."
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

        return self._process_native(pcap_path)

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
            # Skipped here.

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
