"""
wa1kpcap - Dual-engine PCAP analysis library.

Flow-level feature extraction and protocol field parsing using a native
C++ engine (default) or dpkt as fallback.

Example::

    from wa1kpcap import Wa1kPcap

    analyzer = Wa1kPcap()
    flows = analyzer.analyze_file('traffic.pcap')
    for flow in flows:
        print(f"{flow.key}  packets={flow.packet_count}")
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

__version__ = "0.1.4"
__author__ = "1in_js"

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
