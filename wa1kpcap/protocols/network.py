"""
Network layer protocol handlers (IPv4, IPv6).
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from wa1kpcap.protocols.base import BaseProtocolHandler, ProtocolContext, ParseResult, Layer
from wa1kpcap.protocols.registry import register_protocol


@register_protocol('ipv4', Layer.NETWORK, priority=100)
class IPv4Handler(BaseProtocolHandler):
    """IPv4 network layer handler."""

    name = "ipv4"
    layer = Layer.NETWORK
    priority = 100

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse IPv4 packet."""
        import dpkt

        if len(payload) < 20:  # Min IPv4 header size
            return ParseResult(success=False)

        try:
            ip = dpkt.ip.IP(payload)

            # Update packet with IP info
            from wa1kpcap.core.packet import IPInfo
            context.packet.ip = IPInfo.from_dpkt(ip)

            # Determine next protocol from IP protocol field
            proto = ip.p
            next_proto = None

            # IP protocol numbers
            IP_PROTO_ICMP = 1
            IP_PROTO_TCP = 6
            IP_PROTO_UDP = 17
            IP_PROTO_ICMPV6 = 58
            IP_PROTO_SCTP = 132

            if proto == IP_PROTO_TCP:
                next_proto = 'tcp'
            elif proto == IP_PROTO_UDP:
                next_proto = 'udp'
            elif proto == IP_PROTO_ICMP:
                next_proto = 'icmp'
            elif proto == IP_PROTO_ICMPV6:
                next_proto = 'icmpv6'
            elif proto == IP_PROTO_SCTP:
                next_proto = 'sctp'

            return ParseResult(
                success=True,
                data=bytes(ip.data),
                next_protocol=next_proto
            )
        except Exception:
            return ParseResult(success=False)


@register_protocol('ipv6', Layer.NETWORK, priority=100)
class IPv6Handler(BaseProtocolHandler):
    """IPv6 network layer handler."""

    name = "ipv6"
    layer = Layer.NETWORK
    priority = 100

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse IPv6 packet."""
        import dpkt

        if len(payload) < 40:  # Min IPv6 header size
            return ParseResult(success=False)

        try:
            ip6 = dpkt.ip6.IP6(payload)

            # Update packet with IP info
            from wa1kpcap.core.packet import IP6Info
            context.packet.ip6 = IP6Info.from_dpkt(ip6)

            # Determine next protocol
            proto = ip6.nxt
            next_proto = None

            if proto == 6:  # TCP
                next_proto = 'tcp'
            elif proto == 17:  # UDP
                next_proto = 'udp'
            elif proto == 58:  # ICMPv6
                next_proto = 'icmpv6'
            elif proto == 132:  # SCTP
                next_proto = 'sctp'

            return ParseResult(
                success=True,
                data=bytes(ip6.data),
                next_protocol=next_proto
            )
        except Exception:
            return ParseResult(success=False)


@register_protocol('arp', Layer.NETWORK, priority=50)
class ARPHandler(BaseProtocolHandler):
    """ARP protocol handler."""

    name = "arp"
    layer = Layer.NETWORK
    priority = 50

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse ARP packet."""
        import dpkt

        try:
            arp = dpkt.arp.ARP(payload)
            return ParseResult(success=True, data=b"")
        except Exception:
            return ParseResult(success=False)


@register_protocol('icmp', Layer.NETWORK, priority=50)
class ICMPHandler(BaseProtocolHandler):
    """ICMP protocol handler."""

    name = "icmp"
    layer = Layer.NETWORK
    priority = 50

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse ICMP packet."""
        import dpkt

        if len(payload) < 8:
            return ParseResult(success=False)

        try:
            icmp = dpkt.icmp.ICMP(payload)

            # Update packet with ICMP info
            from wa1kpcap.core.packet import ICMPInfo
            context.packet.icmp = ICMPInfo.from_dpkt(icmp)

            return ParseResult(success=True, data=bytes(icmp.data))
        except Exception:
            return ParseResult(success=False)


@register_protocol('icmpv6', Layer.NETWORK, priority=50)
class ICMPv6Handler(BaseProtocolHandler):
    """ICMPv6 protocol handler."""

    name = "icmpv6"
    layer = Layer.NETWORK
    priority = 50

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse ICMPv6 packet."""
        import dpkt

        if len(payload) < 8:
            return ParseResult(success=False)

        try:
            icmp6 = dpkt.icmp6.ICMP6(payload)

            # Update packet with ICMP info (reuse ICMPInfo for v6)
            from wa1kpcap.core.packet import ICMPInfo
            context.packet.icmp = ICMPInfo(type=icmp6.type, code=icmp6.code, _raw=payload)

            return ParseResult(success=True, data=bytes(icmp6.data))
        except Exception:
            return ParseResult(success=False)
