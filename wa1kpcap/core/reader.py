"""
PcapReader - PCAP file detection utilities.

Note: Actual pcap reading is done by the native C++ engine (NativePcapReader).
This module only provides file detection utilities.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Any


# DLT (Data Link Type) constants
DLT_NULL = 0           # BSD loopback
DLT_EN10MB = 1         # Ethernet
DLT_EN3MB = 2          # Experimental Ethernet
DLT_AX25 = 3
DLT_PRONET = 4
DLT_CHAOS = 5
DLT_IEEE802 = 6        # IEEE 802.5 Token Ring
DLT_ARCNET = 7
DLT_SLIP = 8
DLT_PPP = 9
DLT_FDDI = 10
DLT_PPP_HDLC = 50      # PPP in HDLC-like framing
DLT_PPP_ETHER = 51     # NetBSD PPP-over-Ethernet
DLT_ATM_RFC1483 = 100
DLT_RAW = 101          # Raw IP
DLT_C_HDLC = 104       # Cisco HDLC
DLT_IEEE802_11 = 105   # 802.11 wireless
DLT_FRELAY = 107
DLT_LOOP = 108         # OpenBSD loopback
DLT_LINUX_SLL = 113    # Linux cooked capture
DLT_LTALK = 114
DLT_PFLOG = 117        # OpenBSD pflog
DLT_PRISM_HEADER = 119
DLT_IP_OVER_FC = 122
DLT_SUNATM = 123       # Sun ATM
DLT_IEEE802_11_RADIO = 127  # 802.11 plus radiotap header
DLT_IEEE802_11_RADIO_AVS = 163
DLT_IPNET = 226        # Solaris ipnet
DLT_NETANALYZER = 240
DLT_NETANALYZER_TRANSPARENT = 241
DLT_IPOIB = 252        # IP-over-Infiniband
DLT_NFLOG = 239        # NFLOG


class LinkLayerType:
    """Link layer type support."""
    ETHERNET = "ethernet"
    LINUX_SLL = "linux_sll"
    RAW_IP = "raw_ip"
    NULL = "null"
    LOOP = "loop"
    NFLOG = "nflog"
    UNKNOWN = "unknown"


def get_link_layer_type(dlt: int) -> str:
    """Get link layer type name from DLT value."""
    mapping = {
        DLT_EN10MB: LinkLayerType.ETHERNET,
        DLT_LINUX_SLL: LinkLayerType.LINUX_SLL,
        DLT_RAW: LinkLayerType.RAW_IP,
        DLT_NULL: LinkLayerType.NULL,
        DLT_LOOP: LinkLayerType.LOOP,
        DLT_NFLOG: LinkLayerType.NFLOG,
    }
    return mapping.get(dlt, LinkLayerType.UNKNOWN)


class PcapReader:
    """
    PCAP file detection utilities.

    Note: Actual pcap reading is done by the native C++ engine (NativePcapReader).
    This class only provides file detection and link layer type utilities.
    """

    def __init__(self, pcap_path: str | Path):
        self.pcap_path = Path(pcap_path)

    @staticmethod
    def is_pcap_file(path: str | Path) -> bool:
        """Check if file is a valid PCAP or PCAPNG file."""
        path = Path(path)
        if not path.exists() or not path.is_file():
            return False

        try:
            with open(path, 'rb') as f:
                magic = f.read(4)

            # Check for standard pcap (little or big endian)
            if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                return True

            # Check for pcapng
            if magic == b'\x0a\x0d\x0d\x0a':
                return True

            return False
        except Exception:
            return False


# Export main class and utilities
__all__ = ['PcapReader', 'LinkLayerType', 'get_link_layer_type']
