"""
wa1kpcap - Efficient PCAP analysis library.

Flow-level feature extraction and protocol field parsing powered by a native
C++ engine for high performance.

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

try:
    from wa1kpcap.extract import (
        extract_all,
        extract,
        split_pcap,
        list_features,
        ExtractStats,
        FeatureSpec,
        read_jsonl,
        extract_cic,
        extract_cicext,
        extract_seq,
        extract_payload,
        extract_tls,
        extract_dns,
        extract_vpn,
        extract_im,
        extract_flow,
        extract_unified_seq,
    )
    from wa1kpcap.protocols import (
        tls_features,
        dns_features,
        smtp_features,
        dhcp_features,
        ftp_features,
        seq_features,
        payload_features,
        sequence_fields_union,
        wa1k_nvers_seq_mapping,
    )
    _HAS_NVERS = True
except ImportError:
    _HAS_NVERS = False

__version__ = "0.2.0"
__author__ = "1in_js"

__all__ = [
    'Wa1kPcap',
    'Flow', 'FlowKey', 'FlowManager', 'TCPState',
    'ParsedPacket', 'Layer', 'ProtocolInfo', 'ProtocolRegistry',
    'PcapReader',
    'PacketFilter', 'compile_filter', 'BPFCompiler',
    'FeatureExtractor', 'FlowFeatures', 'FeatureType',
    'register_feature', 'BaseIncrementalFeature', 'get_feature_registry',
    'to_dataframe', 'to_dict', 'to_json', 'to_csv', 'FlowExporter',
]

if _HAS_NVERS:
    __all__ += [
        'extract_all', 'extract', 'split_pcap', 'list_features',
        'ExtractStats', 'FeatureSpec', 'read_jsonl',
        'extract_cic', 'extract_cicext', 'extract_seq',
        'extract_payload', 'extract_tls', 'extract_dns',
        'extract_vpn', 'extract_im', 'extract_flow',
        'extract_unified_seq',
        'tls_features', 'dns_features', 'smtp_features',
        'dhcp_features', 'ftp_features', 'seq_features', 'payload_features',
        'sequence_fields_union', 'wa1k_nvers_seq_mapping',
    ]
