"""
wa1kpcap - Python PCAP Analysis Library

A powerful PCAP analysis library providing flow-level feature extraction
and protocol field parsing using dpkt.

Example usage:
    from wa1kpcap import Wa1kPcap

    analyzer = Wa1kPcap(verbose_mode=True, filter_ack=True)
    flows = analyzer.analyze_file('traffic.pcap')

    for flow in flows:
        print(f"Flow: {flow.key}")
        print(f"  Packets: {flow.packet_count}")
        print(f"  Duration: {flow.duration:.3f}s")

        if flow.tls:
            print(f"  TLS SNI: {flow.tls.sni}")

        if flow.features:
            stats = flow.features._statistics
            print(f"  Mean packet length: {stats.get('packet_lengths', {}).get('mean', 0):.1f}")
"""

from wa1kpcap.core.analyzer import Wa1kPcap
from wa1kpcap.core.flow import Flow, FlowKey, FlowManager, TCPState
from wa1kpcap.core.packet import ParsedPacket, Layer, ProtocolInfo, ProtocolRegistry
from wa1kpcap.core.reader import PcapReader
from wa1kpcap.core.filter import PacketFilter, compile_filter, BPFCompiler
from wa1kpcap.protocols.base import BaseProtocolHandler, ProtocolContext, ParseResult
from wa1kpcap.protocols.registry import register_protocol, get_global_registry
from wa1kpcap.features.registry import (
    register_feature,
    FeatureType,
    BaseIncrementalFeature,
    get_global_registry as get_feature_registry
)
from wa1kpcap.features.extractor import FeatureExtractor, FlowFeatures
from wa1kpcap.exporters import (
    to_dataframe,
    to_dict,
    to_json,
    to_csv,
    FlowExporter
)

__version__ = "0.1.0"
__author__ = "wa1k"

__all__ = [
    # Main class
    'Wa1kPcap',

    # Core classes
    'Flow',
    'FlowKey',
    'FlowManager',
    'TCPState',
    'ParsedPacket',
    'Layer',
    'ProtocolInfo',
    'ProtocolRegistry',
    'PcapReader',

    # Filtering
    'PacketFilter',
    'compile_filter',
    'BPFCompiler',

    # Protocol handlers
    'BaseProtocolHandler',
    'ProtocolContext',
    'ParseResult',
    'register_protocol',
    'get_global_registry',

    # Feature extraction
    'FeatureExtractor',
    'FlowFeatures',
    'FeatureType',
    'register_feature',
    'BaseIncrementalFeature',
    'get_feature_registry',

    # Exporters
    'to_dataframe',
    'to_dict',
    'to_json',
    'to_csv',
    'FlowExporter',
]
