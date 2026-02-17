"""
PcapReader - Multi link-layer type support.

Supports standard pcap, pcapng, and various link layer formats including
Ethernet, Linux SLL, Raw IP, NFLOG, etc.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Any
import struct
import sys

if TYPE_CHECKING:
    from wa1kpcap.core.packet import ParsedPacket


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
    PCAP file reader with multi-format support.

    Handles standard pcap and pcapng formats, with support for multiple
    link layer types.
    """

    def __init__(self, pcap_path: str | Path):
        self.pcap_path = Path(pcap_path)
        self._reader: Any | None = None
        self._file = None
        self._link_layer_type: int | None = None
        self._link_layer_name: str = LinkLayerType.UNKNOWN

    def open(self) -> None:
        """Open the PCAP file and initialize reader."""
        import dpkt

        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        f = open(self.pcap_path, 'rb')
        try:
            self._reader = dpkt.pcap.UniversalReader(f)
            self._file = f
            self._link_layer_type = self._reader.datalink()
        except ValueError as e:
            f.close()
            raise ValueError(f"Unknown PCAP format: {e}")

        self._link_layer_name = get_link_layer_type(self._link_layer_type)

    def close(self) -> None:
        """Close the PCAP file."""
        self._reader = None
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> PcapReader:
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    @property
    def link_layer_type(self) -> int:
        """Get the DLT link layer type."""
        if self._link_layer_type is None:
            raise RuntimeError("Reader not opened")
        return self._link_layer_type

    @property
    def link_layer_name(self) -> str:
        """Get the link layer type name."""
        return self._link_layer_name

    @property
    def datalink(self) -> int:
        """Alias for link_layer_type."""
        return self.link_layer_type

    def __iter__(self) -> Iterator[tuple[float, bytes]]:
        """Iterate over packets in the PCAP file."""
        if self._reader is None:
            raise RuntimeError("Reader not opened. Call open() first.")

        for ts, buf in self._reader:
            yield ts, buf

    def packets(self) -> Iterator[tuple[float, int, int, bytes]]:
        """
        Iterate over packets with extended metadata.

        Yields:
            (timestamp, caplen, wirelen, packet_data)
        """
        if self._reader is None:
            raise RuntimeError("Reader not opened. Call open() first.")

        if hasattr(self._reader, 'iter_packets'):
            # pcapng.Reader with extended metadata
            for ts, buf in self._reader:
                caplen = len(buf)
                wirelen = len(buf)
                yield ts, caplen, wirelen, buf
        else:
            # Standard pcap.Reader
            for ts, buf in self._reader:
                caplen = len(buf)
                wirelen = len(buf)
                yield ts, caplen, wirelen, buf

    @staticmethod
    def decode_ethernet_packet(buf: bytes) -> tuple[object | None, int]:
        """
        Decode Ethernet packet.

        Returns:
            (ethernet_obj, payload_offset)
        """
        import dpkt

        try:
            eth = dpkt.ethernet.Ethernet(buf)
            return eth, len(eth) - len(eth.data)
        except Exception:
            return None, 0

    @staticmethod
    def decode_linux_sll_packet(buf: bytes) -> tuple[object | None, int]:
        """
        Decode Linux cooked capture (SLL) packet.

        SLL header format:
        - Packet type (2 bytes)
        - ARPHRD type (2 bytes)
        - Link-layer address length (2 bytes)
        - Link-layer address (8 bytes)
        - Protocol type (2 bytes)

        Returns:
            (sll_obj, payload_offset)
        """
        # Linux SLL header is 16 bytes
        SLL_HDR_LEN = 16

        if len(buf) < SLL_HDR_LEN:
            return None, 0

        try:
            # Parse SLL header
            pkt_type = struct.unpack('>H', buf[0:2])[0]
            arphrd_type = struct.unpack('>H', buf[2:4])[0]
            addr_len = struct.unpack('>H', buf[4:6])[0]
            addr = buf[6:14]
            proto = struct.unpack('>H', buf[14:16])[0]

            # Create a simple wrapper for SLL
            class SLLPacket:
                def __init__(self, pkt_type, arphrd_type, addr_len, addr, proto, data):
                    self.pkt_type = pkt_type
                    self.arphrd_type = arphrd_type
                    self.addr_len = addr_len
                    self.addr = addr
                    self.proto = proto
                    self.data = data

            sll = SLLPacket(pkt_type, arphrd_type, addr_len, addr, proto, buf[SLL_HDR_LEN:])
            return sll, SLL_HDR_LEN
        except Exception:
            return None, 0

    @staticmethod
    def decode_raw_ip_packet(buf: bytes) -> tuple[object | None, int]:
        """
        Decode raw IP packet (no link layer).

        Returns:
            (ip_obj, payload_offset)
        """
        import dpkt

        try:
            # Try IPv4 first
            ip = dpkt.ip.IP(buf)
            return ip, 0
        except Exception:
            try:
                # Try IPv6
                ip6 = dpkt.ip6.IP6(buf)
                return ip6, 0
            except Exception:
                return None, 0

    @staticmethod
    def decode_null_packet(buf: bytes) -> tuple[object | None, int]:
        """
        Decode BSD loopback packet.

        NULL header format (4 bytes):
        - Address family (4 bytes, host byte order)

        Returns:
            (null_obj, payload_offset)
        """
        NULL_HDR_LEN = 4

        if len(buf) < NULL_HDR_LEN:
            return None, 0

        try:
            # Host byte order (native); fall back to swapped if value looks wrong
            af = struct.unpack('=I', buf[0:4])[0]
            if af > 255:
                af = struct.unpack('>I' if sys.byteorder == 'little' else '<I', buf[0:4])[0]

            class NullPacket:
                def __init__(self, af, data):
                    self.af = af
                    self.data = data

            null = NullPacket(af, buf[NULL_HDR_LEN:])
            return null, NULL_HDR_LEN
        except Exception:
            return None, 0

    @staticmethod
    def decode_nflog_packet(buf: bytes) -> tuple[object | None, int]:
        """
        Decode iptables NFLOG packet.

        NFLOG format:
        - Length (2 bytes)
        - Type (2 bytes)
        - TLV attributes for various metadata

        Returns:
            (nflog_obj, payload_offset)
        """
        try:
            # NFLOG uses TLV format
            offset = 0
            af = 2  # Default to AF_INET

            while offset + 4 <= len(buf):
                length = struct.unpack('>H', buf[offset:offset+2])[0]
                nful_attr_type = struct.unpack('>H', buf[offset+2:offset+4])[0]

                # NFLOG Address Family attribute (NFULA_IFINDEX_INDEV = 1)
                if nful_attr_type == 1:
                    pass

                offset += (length + 3) & ~3  # Align to 4 bytes

            class NFLOGPacket:
                def __init__(self, data):
                    self.data = data

            nflog = NFLOGPacket(buf)
            return nflog, 0  # Payload starts at offset (need proper parsing)
        except Exception:
            return None, 0

    def decode_packet(self, buf: bytes) -> tuple[object | None, int]:
        """
        Decode packet based on link layer type.

        Returns:
            (link_layer_obj, payload_offset)
        """
        if self._link_layer_name == LinkLayerType.ETHERNET:
            return self.decode_ethernet_packet(buf)
        elif self._link_layer_name == LinkLayerType.LINUX_SLL:
            return self.decode_linux_sll_packet(buf)
        elif self._link_layer_name == LinkLayerType.RAW_IP:
            return self.decode_raw_ip_packet(buf)
        elif self._link_layer_name == LinkLayerType.NULL or self._link_layer_name == LinkLayerType.LOOP:
            return self.decode_null_packet(buf)
        elif self._link_layer_name == LinkLayerType.NFLOG:
            return self.decode_nflog_packet(buf)
        else:
            # Try Ethernet as fallback
            return self.decode_ethernet_packet(buf)

    def read_packets(self, callback, limit: int | None = None) -> int:
        """
        Read packets and invoke callback for each.

        Args:
            callback: Function taking (timestamp, buf, link_layer_obj)
            limit: Maximum number of packets to read

        Returns:
            Number of packets read
        """
        count = 0
        for ts, buf in self:
            link_obj, _ = self.decode_packet(buf)
            callback(ts, buf, link_obj)
            count += 1
            if limit and count >= limit:
                break
        return count

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
