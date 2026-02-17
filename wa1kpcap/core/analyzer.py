"""
Main PcapAnalyzer class - entry point for PCAP analysis.

Combines all components into a unified API.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any
import time

if TYPE_CHECKING:
    from wa1kpcap.core.reader import PcapReader
    from wa1kpcap.core.flow import FlowManager, Flow
    from wa1kpcap.core.packet import ParsedPacket

from wa1kpcap.core.flow import FlowManager, FlowManagerConfig
from wa1kpcap.core.reader import PcapReader
from wa1kpcap.core.packet import ParsedPacket
from wa1kpcap.core.filter import PacketFilter
from wa1kpcap.features.extractor import FeatureExtractor
from wa1kpcap.protocols.registry import get_global_registry
from wa1kpcap.reassembly.ip_fragment import IPFragmentReassembler
from wa1kpcap.reassembly.tcp_stream import TCPStreamReassembler
from wa1kpcap.reassembly.tls_record import TLSRecordReassembler
from wa1kpcap.features.registry import BaseIncrementalFeature


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
        verbose_mode: Store packet-level information (default: False)
        enabled_features: List of feature names to extract (default: all)
        save_raw_bytes: Save raw packet bytes (memory intensive, default: False)
        compute_statistics: Compute statistical features (default: True)
        enable_reassembly: Enable IP/TCP/TLS reassembly (default: True)
        protocols: List of protocols to parse (default: all supported)

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

        # Detailed mode
        verbose_mode: bool = False,

        # Feature extraction
        enabled_features: list[str] | None = None,
        save_raw_bytes: bool = False,
        compute_statistics: bool = True,

        # Protocol parsing
        enable_reassembly: bool = True,
        protocols: list[str] | None = None,

        # Engine selection: "dpkt" (default) or "native" (C++ engine)
        engine: str = "dpkt",
    ):
        self._engine = engine
        self.udp_timeout = udp_timeout
        self.tcp_cleanup_timeout = tcp_cleanup_timeout
        self.filter_ack = filter_ack
        self.filter_rst = filter_rst
        self.filter_retrans = filter_retrans
        self.bpf_filter = bpf_filter
        self.verbose_mode = verbose_mode
        self.enabled_features = enabled_features
        self.save_raw_bytes = save_raw_bytes
        self.compute_statistics = compute_statistics
        self.enable_reassembly = enable_reassembly
        self.protocols = protocols

        # Initialize BPF filter
        self._packet_filter = PacketFilter(bpf_filter) if bpf_filter else None

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
            self._native_engine = NativeEngine(bpf_filter=bpf_filter)

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

        self._stats['flows_created'] += len(flows)

        # Clear for next file
        self._flow_manager.clear()

        return flows

    def _process_native(self, pcap_path: Path) -> list[Flow]:
        """Process packets using the native C++ engine.

        C++ handles pcap reading + protocol parsing (all layers).
        Python handles flow management, IP fragment reassembly,
        TCP retransmission detection, and feature extraction.
        """
        self._stats['files_processed'] += 1

        for pkt in self._native_engine.read_and_parse(pcap_path, self.save_raw_bytes):
            try:
                self._stats['packets_processed'] += 1

                # Handle IP fragmentation (reuse existing logic)
                if self.enable_reassembly and pkt.ip and pkt.ip.is_fragment:
                    reassembled = self._handle_ip_fragment(pkt)
                    if reassembled is None:
                        continue
                    self._reparse_transport_layer(reassembled, pkt)
                    if pkt.ip:
                        pkt.ip.flags = 0
                        pkt.ip.offset = 0
                        pkt.ip.len = pkt.ip_len
                elif not self.enable_reassembly and pkt.ip and pkt.ip.offset > 0:
                    continue

                # Apply ACK/RST filters
                if self._should_filter(pkt):
                    self._stats['packets_filtered'] += 1
                    continue

                # Get or create flow
                flow = self._flow_manager.get_or_create_flow(pkt)
                if not flow:
                    continue

                # TCP retransmission detection
                if pkt.tcp:
                    is_retrans = self._check_retransmission(pkt, flow)
                    if is_retrans:
                        flow.metrics.retrans_count += 1
                        if self.filter_retrans:
                            self._stats['packets_filtered'] += 1
                            continue

                # Update packet index
                pkt.packet_index = len(flow.packets)
                pkt.flow_index = self._stats['flows_created']

                # Handle TCP stream reassembly and application layer parsing
                if pkt.tcp and hasattr(pkt, '_raw_tcp_payload'):
                    self._handle_tcp_reassembly(pkt, flow)

                # Add packet to flow
                flow.add_packet(pkt)

            except Exception as e:
                self._stats['errors'].append(
                    f"{pcap_path}: Packet processing error: {e}")

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

        self._stats['flows_created'] += len(flows)

        # Clear for next file
        self._flow_manager.clear()

        return flows

    def _aggregate_flow_info(self, flow: Flow) -> None:
        """Aggregate packet-level protocol info to flow-level."""
        from wa1kpcap.core.packet import TLSInfo, HTTPInfo, DNSInfo
        from wa1kpcap.protocols.application import TLSFlowState, parse_cert_der

        # First, extract ALL TLS info from flow._tls_state if available
        if flow._tls_state and isinstance(flow._tls_state, TLSFlowState):
            tls_state = flow._tls_state

            # Create TLSInfo if not exists
            if not flow.tls:
                flow.tls = TLSInfo(version=tls_state.version, content_type=22, record_length=0)

            # Copy version
            if not flow.tls.version and tls_state.version:
                flow.tls.version = tls_state.version

            # Copy SNI (always list)
            if tls_state.sni:
                flow.tls.sni.extend(tls_state.sni)

            # Copy ALPN (always list)
            if tls_state.alpn:
                flow.tls.alpn.extend(tls_state.alpn)

            # Copy cipher suites
            if tls_state.c_ciphersuites:
                flow.tls.cipher_suites.extend(tls_state.c_ciphersuites)

            # Copy cipher suite
            if tls_state.s_ciphersuite and not flow.tls.cipher_suite:
                flow.tls.cipher_suite = tls_state.s_ciphersuite

            # Copy signature algorithms
            if tls_state.signature_algorithms:
                flow.tls.signature_algorithms.extend(tls_state.signature_algorithms)

            # Copy supported groups
            if tls_state.supported_groups:
                flow.tls.supported_groups.extend(tls_state.supported_groups)

            # Copy extensions (as dict {ext_type: [ext_data1, ext_data2, ...]})
            if tls_state.exts:
                for ext_type, ext_data_list in tls_state.exts.items():
                    if ext_type not in flow.tls.exts:
                        flow.tls.exts[ext_type] = []
                    for ext_data in ext_data_list:
                        ext_bytes = bytes(ext_data)
                        if ext_bytes not in flow.tls.exts[ext_type]:
                            flow.tls.exts[ext_type].append(ext_bytes)

                # Also populate legacy extensions list for backward compatibility
                for ext_type, ext_data_list in tls_state.exts.items():
                    for ext_data in ext_data_list:
                        ext_tuple = (ext_type, bytes(ext_data))
                        if ext_tuple not in flow.tls.extensions:
                            flow.tls.extensions.append(ext_tuple)

            # Parse and copy certificates
            if tls_state.certs and not flow.tls.certificates:
                cert_infos = []
                for cert_der in tls_state.certs:
                    cert_info = parse_cert_der(bytes(cert_der))
                    if cert_info:
                        cert_infos.append(cert_info)
                if cert_infos:
                    flow.tls.certificates = cert_infos
                    flow.tls.certificate = cert_infos[0]

        # Aggregate TLS info from packets (merge additional info not in _tls_state)
        for pkt in flow.packets:
            if pkt.tls:
                # Initialize flow.tls if not set
                if not flow.tls:
                    # For NativeTLSInfo (C++ struct), create a Python TLSInfo copy
                    try:
                        flow.tls = pkt.tls
                    except (TypeError, AttributeError):
                        flow.tls = TLSInfo(
                            version=getattr(pkt.tls, 'version', None),
                            content_type=getattr(pkt.tls, 'content_type', None),
                            record_length=getattr(pkt.tls, 'record_length', 0),
                        )
                # Otherwise, merge additional info
                else:
                    try:
                        # Merge versions
                        if pkt.tls.version and not flow.tls.version:
                            flow.tls.version = pkt.tls.version

                        # Merge SNI (both are lists for Python TLSInfo)
                        pkt_sni = getattr(pkt.tls, 'sni', None)
                        if pkt_sni:
                            # NativeTLSInfo.sni is a string; Python TLSInfo.sni is a list
                            sni_list = [pkt_sni] if isinstance(pkt_sni, str) else pkt_sni
                            for s in sni_list:
                                if s and s not in flow.tls.sni:
                                    flow.tls.sni.append(s)

                        # Merge ALPN (both are lists)
                        pkt_alpn = getattr(pkt.tls, 'alpn', None)
                        if pkt_alpn:
                            for a in pkt_alpn:
                                if a not in flow.tls.alpn:
                                    flow.tls.alpn.append(a)

                        # Merge cipher suite
                        pkt_cs = getattr(pkt.tls, 'cipher_suite', None)
                        if pkt_cs and not flow.tls.cipher_suite:
                            flow.tls.cipher_suite = pkt_cs

                        # Merge cipher suites
                        pkt_css = getattr(pkt.tls, 'cipher_suites', None)
                        if pkt_css:
                            for cs in pkt_css:
                                if cs not in flow.tls.cipher_suites:
                                    flow.tls.cipher_suites.append(cs)

                        # Merge signature algorithms
                        pkt_sa = getattr(pkt.tls, 'signature_algorithms', None)
                        if pkt_sa:
                            for alg in pkt_sa:
                                if alg not in flow.tls.signature_algorithms:
                                    flow.tls.signature_algorithms.append(alg)

                        # Merge supported groups
                        pkt_sg = getattr(pkt.tls, 'supported_groups', None)
                        if pkt_sg:
                            for sg in pkt_sg:
                                if sg not in flow.tls.supported_groups:
                                    flow.tls.supported_groups.append(sg)

                        # Merge certificate info
                        pkt_cert = getattr(pkt.tls, 'certificate', None)
                        if pkt_cert and not flow.tls.certificate:
                            flow.tls.certificate = pkt_cert

                        # Merge certificate chain
                        pkt_certs = getattr(pkt.tls, 'certificates', None)
                        if pkt_certs:
                            for cert in pkt_certs:
                                if cert not in flow.tls.certificates:
                                    flow.tls.certificates.append(cert)

                        # Merge exts
                        pkt_exts = getattr(pkt.tls, 'exts', None)
                        if pkt_exts:
                            for ext_type, ext_data_list in pkt_exts.items():
                                if ext_type not in flow.tls.exts:
                                    flow.tls.exts[ext_type] = []
                                for ext_data in ext_data_list:
                                    if ext_data not in flow.tls.exts[ext_type]:
                                        flow.tls.exts[ext_type].append(ext_data)

                        # Merge legacy extensions list
                        pkt_extensions = getattr(pkt.tls, 'extensions', None)
                        if pkt_extensions:
                            for ext in pkt_extensions:
                                if ext not in flow.tls.extensions:
                                    flow.tls.extensions.append(ext)
                    except (TypeError, AttributeError):
                        pass  # NativeTLSInfo may lack some attributes

        # Aggregate HTTP info
        for pkt in flow.packets:
            pkt_http = getattr(pkt, 'http', None)
            if pkt_http and not flow.http:
                flow.http = pkt_http
                if getattr(pkt_http, 'host', None) or getattr(pkt_http, 'user_agent', None):
                    break

        # Aggregate DNS info
        for pkt in flow.packets:
            pkt_dns = getattr(pkt, 'dns', None)
            if pkt_dns and not flow.dns:
                flow.dns = pkt_dns
                if getattr(pkt_dns, 'queries', None):
                    break

        # Build extended protocol stack
        flow.build_ext_protocol()

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
                        self._parse_dns(udp.data, pkt)
            except Exception:
                pass

    def _parse_application(self, data: bytes, pkt: ParsedPacket) -> None:
        """Parse application layer protocols."""
        if not data:
            return

        # Check for TLS (port 443, 465, 993, 995)
        if pkt.tcp:
            port = pkt.tcp.dport if pkt.tcp else 0
            sport = pkt.tcp.sport if pkt.tcp else 0

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

    def _handle_tcp_reassembly(self, pkt: ParsedPacket, flow: Flow) -> None:
        """Handle TCP stream reassembly and application layer parsing.

        Args:
            pkt: Parsed packet with TCP layer
            flow: Flow object (already created)
        """
        tcp_data = getattr(pkt, '_raw_tcp_payload', b'')
        if not tcp_data and not pkt.tcp:
            return

        # Native engine: handle TLS reassembly in Python, parse via C++ engine.
        if self._engine == "native":
            if tcp_data and pkt.tcp:
                port = pkt.tcp.dport
                sport = pkt.tcp.sport
                # TLS ports
                if port in (443, 465, 993, 995, 5061) or sport in (443, 465, 993, 995, 5061):
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
        if tcp_data:
            self._parse_application_with_buffering(tcp_data, pkt, flow, direction)

    def _handle_native_tls_reassembly(
        self, data: bytes, pkt: ParsedPacket, flow: Flow, direction: int
    ) -> None:
        """Buffer TCP payload, extract complete TLS records, parse via C++ engine."""
        buf = flow._tls_incomplete_data.get(direction, b"")
        full = buf + data

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

            # Complete TLS record — only parse handshake (content_type=22)
            if content_type == 22:
                record = full[offset:offset + 5 + record_len]
                self._parse_native_tls_record(record, pkt, flow)
            offset += 5 + record_len

        flow._tls_incomplete_data[direction] = full[offset:]

    def _parse_native_tls_record(
        self, record: bytes, pkt: ParsedPacket, flow: Flow
    ) -> None:
        """Parse a complete TLS record using C++ engine, update flow TLS state."""
        from wa1kpcap.core.packet import TLSInfo

        result = self._native_engine.parse_tls_record(record)
        if result is None:
            return

        tls = result.tls
        if tls is None:
            return

        # Merge into packet's TLS info (create if needed)
        if pkt.tls is None:
            pkt.tls = TLSInfo(
                version=tls.version if tls.version else None,
                content_type=tls.content_type if tls.content_type >= 0 else None,
                handshake_type=tls.handshake_type if tls.handshake_type >= 0 else None,
                record_length=tls.record_length,
            )

        info = pkt.tls

        # Merge SNI
        if tls.sni:
            if not info.sni:
                info.sni = []
            if tls.sni not in info.sni:
                info.sni.append(tls.sni)

        # Merge cipher_suites (ClientHello)
        if tls.cipher_suites and not info.cipher_suites:
            info.cipher_suites = list(tls.cipher_suites)
            info.handshake_type = 1

        # Merge cipher_suite (ServerHello)
        if tls.cipher_suite >= 0 and info.cipher_suite is None:
            info.cipher_suite = tls.cipher_suite
            info.handshake_type = 2

        # Merge ALPN
        if tls.alpn and not info.alpn:
            info.alpn = list(tls.alpn)

        # Merge signature_algorithms
        if tls.signature_algorithms and not info.signature_algorithms:
            info.signature_algorithms = list(tls.signature_algorithms)

        # Merge supported_groups
        if tls.supported_groups and not info.supported_groups:
            info.supported_groups = list(tls.supported_groups)

        # Merge version
        if tls.version and not info.version:
            info.version = tls.version

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
        from wa1kpcap.protocols.application import parse_tls, TLSFlowState, parse_cert_der
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

        # Set certificates if available
        if parsed_tls.certs:
            cert_infos = []
            for cert_der in parsed_tls.certs:
                cert_info = parse_cert_der(bytes(cert_der))
                if cert_info:
                    cert_infos.append(cert_info)
            if cert_infos:
                tls_info.certificates = cert_infos
                tls_info.certificate = cert_infos[0]

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
