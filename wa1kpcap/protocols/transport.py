"""
Transport layer protocol handlers (TCP, UDP).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wa1kpcap.protocols.base import BaseProtocolHandler, ProtocolContext, ParseResult, Layer
from wa1kpcap.protocols.registry import register_protocol


@register_protocol('tcp', Layer.TRANSPORT, priority=100)
class TCPHandler(BaseProtocolHandler):
    """TCP transport layer handler."""

    name = "tcp"
    layer = Layer.TRANSPORT
    priority = 100

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse TCP segment."""
        import dpkt

        if len(payload) < 20:  # Min TCP header size
            return ParseResult(success=False)

        try:
            tcp = dpkt.tcp.TCP(payload)

            # Update packet with TCP info
            from wa1kpcap.core.packet import TCPInfo
            context.packet.tcp = TCPInfo.from_dpkt(tcp)

            # Determine direction and update context
            if context.packet.ip:
                flow_key_parts = (
                    context.packet.ip.src,
                    context.packet.tcp.sport,
                    context.packet.ip.dst,
                    context.packet.tcp.dport
                )
            elif context.packet.ip6:
                flow_key_parts = (
                    context.packet.ip6.src,
                    context.packet.tcp.sport,
                    context.packet.ip6.dst,
                    context.packet.tcp.dport
                )
            else:
                flow_key_parts = None

            # Determine if this is client-to-server based on port comparison
            if flow_key_parts:
                src_port = flow_key_parts[1]
                dst_port = flow_key_parts[3]
                # Lower port is typically client
                if src_port < dst_port:
                    is_c2s = True
                elif src_port > dst_port:
                    is_c2s = False
                else:
                    # Same port (rare), use is_client_to_server from context
                    is_c2s = is_client_to_server

                context.is_client_to_server = is_c2s
                context.packet.is_client_to_server = is_c2s

            # Extract TCP options
            options = {}
            if tcp.opts:
                options = self._parse_tcp_options(tcp.opts)

            # Check for MSS
            mss = options.get(2)  # MSS option type

            return ParseResult(
                success=True,
                data=tcp.data,
                attributes={
                    'seq': tcp.seq,
                    'ack': tcp.ack_num if tcp.flags & 0x10 else 0,
                    'flags': tcp.flags,
                    'window': tcp.win,
                    'options': options,
                    'mss': mss,
                    'sack_permitted': 4 in options  # SACK permitted
                }
            )
        except Exception:
            return ParseResult(success=False)

    def _parse_tcp_options(self, opts: bytes) -> dict[int, int | bytes]:
        """Parse TCP options byte array."""
        options = {}
        offset = 0
        while offset < len(opts):
            opt_type = opts[offset]
            if opt_type == 0:  # End of options
                break
            if opt_type == 1:  # NOP
                offset += 1
                continue

            if offset + 1 < len(opts):
                opt_len = opts[offset + 1]
                if opt_len < 2:
                    break

                if offset + opt_len <= len(opts):
                    opt_value = opts[offset + 2:offset + opt_len]
                    # For single-byte values, store as int
                    if len(opt_value) == 1:
                        options[opt_type] = opt_value[0]
                    elif len(opt_value) == 2:
                        import struct
                        options[opt_type] = struct.unpack('>H', opt_value)[0]
                    else:
                        options[opt_type] = opt_value

                offset += opt_len
            else:
                offset += 1

        return options


@register_protocol('udp', Layer.TRANSPORT, priority=100)
class UDPHandler(BaseProtocolHandler):
    """UDP transport layer handler."""

    name = "udp"
    layer = Layer.TRANSPORT
    priority = 100

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse UDP datagram."""
        import dpkt

        if len(payload) < 8:  # UDP header is 8 bytes
            return ParseResult(success=False)

        try:
            udp = dpkt.udp.UDP(payload)

            # Update packet with UDP info
            from wa1kpcap.core.packet import UDPInfo
            context.packet.udp = UDPInfo.from_dpkt(udp)

            return ParseResult(
                success=True,
                data=udp.data
            )
        except Exception:
            return ParseResult(success=False)


@register_protocol('sctp', Layer.TRANSPORT, priority=50)
class SCTPHandler(BaseProtocolHandler):
    """SCTP transport layer handler."""

    name = "sctp"
    layer = Layer.TRANSPORT
    priority = 50

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse SCTP packet."""
        if len(payload) < 12:  # SCTP common header is 12 bytes
            return ParseResult(success=False)

        # SCTP parsing is complex, just mark as successful for now
        return ParseResult(
            success=True,
            data=payload[12:]
        )
