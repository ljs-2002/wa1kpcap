"""
Link layer protocol handlers (Ethernet, Linux SLL, Raw IP, NFLOG).
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from wa1kpcap.protocols.base import BaseProtocolHandler, ProtocolContext, ParseResult, Layer
from wa1kpcap.protocols.registry import register_protocol


@register_protocol('ethernet', Layer.DATA_LINK, priority=100)
class EthernetHandler(BaseProtocolHandler):
    """Ethernet link layer handler."""

    name = "ethernet"
    layer = Layer.DATA_LINK
    priority = 100

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse Ethernet frame."""
        import dpkt

        if len(payload) < 14:  # Min Ethernet header size
            return ParseResult(success=False)

        try:
            eth = dpkt.ethernet.Ethernet(payload)

            # Update packet with Ethernet info
            from wa1kpcap.core.packet import EthernetInfo
            context.packet.eth = EthernetInfo.from_dpkt(eth)

            # Determine next protocol from EtherType
            etype = eth.type
            next_proto = None

            # Common EtherTypes
            ETHERTYPE_IP = 0x0800
            ETHERTYPE_IP6 = 0x86DD
            ETHERTYPE_ARP = 0x0806
            ETHERTYPE_VLAN = 0x8100
            ETHERTYPE_MPLS = 0x8847

            if etype == ETHERTYPE_IP:
                next_proto = 'ipv4'
            elif etype == ETHERTYPE_IP6:
                next_proto = 'ipv6'
            elif etype == ETHERTYPE_ARP:
                next_proto = 'arp'

            return ParseResult(
                success=True,
                data=bytes(eth.data),
                next_protocol=next_proto
            )
        except Exception:
            return ParseResult(success=False)


@register_protocol('linux_sll', Layer.DATA_LINK, priority=100)
class LinuxSLLHandler(BaseProtocolHandler):
    """Linux cooked capture (SLL) link layer handler."""

    name = "linux_sll"
    layer = Layer.DATA_LINK
    priority = 100

    SLL_HDR_LEN = 16

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse Linux SLL packet."""
        if len(payload) < self.SLL_HDR_LEN:
            return ParseResult(success=False)

        try:
            # Parse SLL header
            pkt_type = struct.unpack('>H', payload[0:2])[0]
            arphrd_type = struct.unpack('>H', payload[2:4])[0]
            addr_len = struct.unpack('>H', payload[4:6])[0]
            addr = payload[6:14]
            proto = struct.unpack('>H', payload[14:16])[0]

            # Store info in packet metadata
            context.packet._raw_eth = type('SLLInfo', (), {
                'pkt_type': pkt_type,
                'arphrd_type': arphrd_type,
                'addr_len': addr_len,
                'addr': addr,
                'proto': proto
            })()

            # Determine next protocol
            next_proto = None
            if proto == 0x0800:
                next_proto = 'ipv4'
            elif proto == 0x86DD:
                next_proto = 'ipv6'

            return ParseResult(
                success=True,
                data=payload[self.SLL_HDR_LEN:],
                next_protocol=next_proto
            )
        except Exception:
            return ParseResult(success=False)


@register_protocol('raw_ip', Layer.DATA_LINK, priority=50)
class RawIPHandler(BaseProtocolHandler):
    """Raw IP handler (no link layer)."""

    name = "raw_ip"
    layer = Layer.DATA_LINK
    priority = 50

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse raw IP packet."""
        if len(payload) < 1:
            return ParseResult(success=False)

        # Check IP version from first nibble
        first_byte = payload[0]
        version = (first_byte >> 4) & 0x0F

        if version == 4:
            return ParseResult(
                success=True,
                data=payload,
                next_protocol='ipv4'
            )
        elif version == 6:
            return ParseResult(
                success=True,
                data=payload,
                next_protocol='ipv6'
            )

        return ParseResult(success=False)


@register_protocol('null', Layer.DATA_LINK, priority=50)
class NullHandler(BaseProtocolHandler):
    """BSD loopback handler."""

    name = "null"
    layer = Layer.DATA_LINK
    priority = 50

    NULL_HDR_LEN = 4

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse BSD null/loopback packet."""
        if len(payload) < self.NULL_HDR_LEN:
            return ParseResult(success=False)

        try:
            af = struct.unpack('>I', payload[0:4])[0]

            # Address family values
            AF_INET = 2
            AF_INET6 = 24  # OpenBSD, Darwin; NetBSD is 24

            next_proto = None
            if af == AF_INET:
                next_proto = 'ipv4'
            elif af == AF_INET6:
                next_proto = 'ipv6'

            return ParseResult(
                success=True,
                data=payload[self.NULL_HDR_LEN:],
                next_protocol=next_proto
            )
        except Exception:
            return ParseResult(success=False)


@register_protocol('nflog', Layer.DATA_LINK, priority=50)
class NFLOGHandler(BaseProtocolHandler):
    """iptables NFLOG handler."""

    name = "nflog"
    layer = Layer.DATA_LINK
    priority = 50

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse NFLOG packet."""
        # NFLOG TLV format - need to skip to payload
        offset = 0

        try:
            while offset + 4 <= len(payload):
                length = struct.unpack('>H', payload[offset:offset+2])[0]
                attr_type = struct.unpack('>H', payload[offset+2:offset+4])[0]

                # NFLOG_PAYLOAD_ATTR = 9
                if attr_type == 9:
                    # Found payload
                    payload_offset = offset + 4
                    return ParseResult(
                        success=True,
                        data=payload[payload_offset:payload_offset+length],
                        next_protocol='ipv4'
                    )

                # Move to next TLV (aligned to 4 bytes)
                offset += (length + 3) & ~3

            # If no explicit payload found, try parsing entire buffer as IP
            return ParseResult(
                success=True,
                data=payload,
                next_protocol='ipv4'
            )
        except Exception:
            return ParseResult(success=False)
