"""
Simplified BPF filter for packet filtering.

Provides fast pre-check filtering for link/network/transport layers and
post-parse filtering for application layer protocols.

Supports:
- Protocol filtering: tcp, udp, icmp, icmpv6, arp, ip, ipv6
- IP filtering: host 192.168.1.1, src 192.168.1.1, dst 192.168.1.1
- Port filtering: port 443, src port 80, dst port 443
- Logical operators: and, or, not
- Grouping: (expr)
"""

from __future__ import annotations

import struct
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable
from enum import Enum, IntFlag

if TYPE_CHECKING:
    from wa1kpcap.core.packet import ParsedPacket


class Protocol(IntFlag):
    """Protocol numbers for filtering."""
    IP = 0x0800          # IPv4 EtherType
    IPv6 = 0x86DD        # IPv6 EtherType
    ARP = 0x0806         # ARP EtherType
    TCP = 6              # IP protocol number
    UDP = 17             # IP protocol number
    ICMP = 1             # IP protocol number
    ICMPv6 = 58          # IPv6 next header


@dataclass
class FilterCondition:
    """Base class for filter conditions."""
    def matches(self, pkt: ParsedPacket | None, buf: bytes | None = None) -> bool:
        """Check if packet matches this condition."""
        raise NotImplementedError


@dataclass
class ProtocolCondition(FilterCondition):
    """Protocol filter condition."""
    protocols: set[int] = field(default_factory=set)
    is_ip: bool = False
    is_ipv6: bool = False
    is_arp: bool = False
    negate: bool = False

    def matches(self, pkt: ParsedPacket | None, buf: bytes | None = None) -> bool:
        if buf is not None and len(buf) >= 14:
            # Fast check from raw buffer (link layer)
            eth_type = struct.unpack('>H', buf[12:14])[0]
            result = False

            if self.is_ip and eth_type == 0x0800:
                result = True
            elif self.is_ipv6 and eth_type == 0x86DD:
                result = True
            elif self.is_arp and eth_type == 0x0806:
                result = True
            elif self.protocols:
                if eth_type == 0x0800 and len(buf) >= 24:
                    # IPv4
                    proto = buf[23]
                    result = proto in self.protocols
                elif eth_type == 0x86DD and len(buf) >= 54:
                    # IPv6
                    next_header = buf[20]
                    result = next_header in self.protocols

            return result != self.negate

        if pkt is not None:
            result = False
            if self.is_ip or self.is_ipv6 or self.is_arp:
                if self.is_ip and pkt.ip:
                    result = True
                elif self.is_ipv6 and pkt.ip6:
                    result = True
                elif self.is_arp and pkt.arp:
                    result = True
            elif self.protocols:
                if pkt.ip and pkt.ip.proto in self.protocols:
                    result = True
                elif pkt.ip6 and pkt.ip6.next_header in self.protocols:
                    result = True

            return result != self.negate

        return not self.negate


@dataclass
class IPCondition(FilterCondition):
    """IP address filter condition."""
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    any_ips: set[str] = field(default_factory=set)
    negate: bool = False

    def matches(self, pkt: ParsedPacket | None, buf: bytes | None = None) -> bool:
        if buf is not None and len(buf) >= 34:
            # Fast check from raw buffer
            eth_type = struct.unpack('>H', buf[12:14])[0]
            result = False

            if eth_type == 0x0800:  # IPv4
                ip_hdr_len = (buf[14] & 0x0F) * 4
                src_ip = bytes(buf[26:26+4])
                dst_ip = bytes(buf[30:30+4])

                if self.any_ips:
                    result = (src_ip in self._ip_bytes(self.any_ips) or
                             dst_ip in self._ip_bytes(self.any_ips))
                if self.src_ips:
                    result = result or (src_ip in self._ip_bytes(self.src_ips))
                if self.dst_ips:
                    result = result or (dst_ip in self._ip_bytes(self.dst_ips))

            return result != self.negate

        if pkt is not None:
            result = False
            src = pkt.ip.src if pkt.ip else (pkt.ip6.src if pkt.ip6 else "")
            dst = pkt.ip.dst if pkt.ip else (pkt.ip6.dst if pkt.ip6 else "")

            if self.any_ips:
                result = (src in self.any_ips or dst in self.any_ips)
            if self.src_ips:
                result = result or (src in self.src_ips)
            if self.dst_ips:
                result = result or (dst in self.dst_ips)

            return result != self.negate

        return not self.negate

    @staticmethod
    def _ip_bytes(ip_set: set[str]) -> set[bytes]:
        """Convert IP strings to bytes."""
        result = set()
        for ip in ip_set:
            try:
                parts = ip.split('.')
                if len(parts) == 4:
                    result.add(bytes(int(p) for p in parts))
            except (ValueError, AttributeError):
                pass
        return result


@dataclass
class PortCondition(FilterCondition):
    """Port filter condition."""
    src_ports: set[int] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    any_ports: set[int] = field(default_factory=set)
    negate: bool = False

    def matches(self, pkt: ParsedPacket | None, buf: bytes | None = None) -> bool:
        if buf is not None and len(buf) >= 38:
            # Fast check from raw buffer
            eth_type = struct.unpack('>H', buf[12:14])[0]
            result = False

            if eth_type == 0x0800:  # IPv4
                ip_hdr_len = (buf[14] & 0x0F) * 4
                transport_offset = 14 + ip_hdr_len

                if len(buf) >= transport_offset + 4:
                    src_port = struct.unpack('>H', buf[transport_offset:transport_offset+2])[0]
                    dst_port = struct.unpack('>H', buf[transport_offset+2:transport_offset+4])[0]

                    if self.any_ports:
                        result = (src_port in self.any_ports or dst_port in self.any_ports)
                    if self.src_ports:
                        result = result or (src_port in self.src_ports)
                    if self.dst_ports:
                        result = result or (dst_port in self.dst_ports)

            return result != self.negate

        if pkt is not None:
            result = False
            src = (pkt.tcp.sport if pkt.tcp else
                   pkt.udp.sport if pkt.udp else 0)
            dst = (pkt.tcp.dport if pkt.tcp else
                   pkt.udp.dport if pkt.udp else 0)

            if self.any_ports:
                result = (src in self.any_ports or dst in self.any_ports)
            if self.src_ports:
                result = result or (src in self.src_ports)
            if self.dst_ports:
                result = result or (dst in self.dst_ports)

            return result != self.negate

        return not self.negate


@dataclass
class AppProtocolCondition(FilterCondition):
    """Application layer protocol filter (post-parse only)."""
    protocols: set[str] = field(default_factory=set)
    negate: bool = False

    def matches(self, pkt: ParsedPacket | None, buf: bytes | None = None) -> bool:
        if buf is not None:
            # Cannot filter application layer from raw buffer
            # Return True to allow parsing
            return True

        if pkt is not None:
            result = False
            if 'tls' in self.protocols and pkt.tls:
                result = True
            if 'http' in self.protocols and pkt.http:
                result = True
            if 'dns' in self.protocols and pkt.dns:
                result = True
            if 'dhcp' in self.protocols and pkt.dhcp:
                result = True
            if 'dhcpv6' in self.protocols and pkt.dhcpv6:
                result = True
            if 'vlan' in self.protocols and pkt.vlan:
                result = True
            if 'gre' in self.protocols and pkt.gre:
                result = True
            if 'vxlan' in self.protocols and pkt.vxlan:
                result = True
            if 'mpls' in self.protocols and pkt.mpls:
                result = True

            return result != self.negate

        return not self.negate


@dataclass
class CompoundCondition(FilterCondition):
    """Compound filter condition with logical operators."""
    conditions: list[FilterCondition] = field(default_factory=list)
    operator: str = "and"  # "and", "or"
    negate: bool = False

    def matches(self, pkt: ParsedPacket | None, buf: bytes | None = None) -> bool:
        if self.operator == "and":
            result = all(c.matches(pkt, buf) for c in self.conditions)
        else:  # or
            result = any(c.matches(pkt, buf) for c in self.conditions)

        return result != self.negate


class BPFCompiler:
    """
    Compiler for simplified BPF filter syntax.

    Supports:
    - Protocols: tcp, udp, icmp, icmpv6, arp, ip, ipv6, tls, http, dns
    - IP: host X.X.X.X, src X.X.X.X, dst X.X.X.X
    - Ports: port N, src port N, dst port N
    - Logical: and, or, not
    - Grouping: (expr)

    Examples:
        >>> compiler = BPFCompiler()
        >>> cond = compiler.compile("tcp and port 443")
        >>> cond.matches(pkt, buf)
    """

    # Token patterns (order matters: longer keywords first, e.g. icmpv6 before icmp)
    TOKEN_PATTERNS = [
        (r'\(', 'LPAREN'),
        (r'\)', 'RPAREN'),
        (r'\band\b', 'AND'),
        (r'\bor\b', 'OR'),
        (r'\bnot\b', 'NOT'),
        (r'\bicmpv6\b', 'ICMPV6'),
        (r'\bdhcpv6\b', 'DHCPV6'),
        (r'\btcp\b', 'TCP'),
        (r'\budp\b', 'UDP'),
        (r'\bicmp\b', 'ICMP'),
        (r'\barp\b', 'ARP'),
        (r'\bipv6\b', 'IPV6'),
        (r'\bip\b', 'IP'),
        (r'\bhost\b', 'HOST'),
        (r'\bsrc\b', 'SRC'),
        (r'\bdst\b', 'DST'),
        (r'\bport\b', 'PORT'),
        (r'\btls\b', 'TLS'),
        (r'\bhttp\b', 'HTTP'),
        (r'\bdns\b', 'DNS'),
        (r'\bdhcp\b', 'DHCP'),
        (r'\bvxlan\b', 'VXLAN'),
        (r'\bvlan\b', 'VLAN'),
        (r'\bgre\b', 'GRE'),
        (r'\bmpls\b', 'MPLS'),
        (r'\d+\.\d+\.\d+\.\d+', 'IPV4_ADDR'),
        (r'\d+', 'NUMBER'),
        (r'\s+', 'WS'),
    ]

    def __init__(self):
        self._patterns = [(re.compile(p), name) for p, name in self.TOKEN_PATTERNS]
        self._tokens: list[tuple[str, str]] = []
        self._pos: int = 0

    def compile(self, filter_str: str) -> FilterCondition:
        """
        Compile a BPF filter string into a FilterCondition.

        Args:
            filter_str: BPF filter string (e.g., "tcp and port 443")

        Returns:
            FilterCondition object
        """
        if not filter_str or not filter_str.strip():
            return CompoundCondition(conditions=[], operator="or")

        self._tokens = self._tokenize(filter_str)
        self._pos = 0

        if not self._tokens:
            return CompoundCondition(conditions=[], operator="or")

        condition = self._parse_or()

        if self._pos < len(self._tokens):
            raise ValueError(
                f"Unexpected token at position {self._pos}: "
                f"{self._tokens[self._pos][1]}"
            )

        return condition

    # -- helpers --

    def _peek(self) -> str | None:
        """Peek at the current token type without consuming."""
        if self._pos < len(self._tokens):
            return self._tokens[self._pos][0]
        return None

    def _consume(self, expected: str | None = None) -> tuple[str, str]:
        """Consume and return the current token."""
        if self._pos >= len(self._tokens):
            raise ValueError(f"Unexpected end of filter, expected {expected}")
        tok = self._tokens[self._pos]
        if expected and tok[0] != expected:
            raise ValueError(f"Expected {expected}, got {tok[0]} ({tok[1]})")
        self._pos += 1
        return tok

    # -- tokenizer --

    def _tokenize(self, filter_str: str) -> list[tuple[str, str]]:
        """Tokenize the filter string."""
        tokens = []
        pos = 0
        text = filter_str.lower()

        while pos < len(text):
            matched = False
            for pattern, name in self._patterns:
                m = pattern.match(text, pos)
                if m:
                    if name != 'WS':
                        tokens.append((name, m.group()))
                    pos = m.end()
                    matched = True
                    break

            if not matched:
                raise ValueError(
                    f"Invalid filter syntax at position {pos}: "
                    f"{filter_str[pos:pos+10]}"
                )

        return tokens

    # -- recursive descent parser --
    # Grammar:
    #   or_expr  := and_expr ('or' and_expr)*
    #   and_expr := not_expr ('and' not_expr)*
    #   not_expr := 'not' not_expr | primary
    #   primary  := '(' or_expr ')' | atom
    #   atom     := protocol | ip_filter | port_filter | app_protocol

    def _parse_or(self) -> FilterCondition:
        """Parse OR expression."""
        left = self._parse_and()

        while self._peek() == 'OR':
            self._consume('OR')
            right = self._parse_and()
            left = CompoundCondition(conditions=[left, right], operator="or")

        return left

    def _parse_and(self) -> FilterCondition:
        """Parse AND expression."""
        left = self._parse_not()

        while self._peek() == 'AND':
            self._consume('AND')
            right = self._parse_not()
            left = CompoundCondition(conditions=[left, right], operator="and")

        return left

    def _parse_not(self) -> FilterCondition:
        """Parse NOT expression."""
        if self._peek() == 'NOT':
            self._consume('NOT')
            condition = self._parse_not()  # recursive for "not not x"
            condition.negate = not condition.negate
            return condition

        return self._parse_primary()

    def _parse_primary(self) -> FilterCondition:
        """Parse primary expression (parentheses or atom)."""
        if self._peek() == 'LPAREN':
            self._consume('LPAREN')
            condition = self._parse_or()
            self._consume('RPAREN')
            return condition

        return self._parse_atom()

    def _parse_atom(self) -> FilterCondition:
        """Parse an atomic condition."""
        tok_type = self._peek()

        if tok_type is None:
            raise ValueError("Unexpected end of filter expression")

        # Transport/network protocol keywords
        if tok_type == 'TCP':
            self._consume()
            return ProtocolCondition(protocols={Protocol.TCP})
        if tok_type == 'UDP':
            self._consume()
            return ProtocolCondition(protocols={Protocol.UDP})
        if tok_type == 'ICMP':
            self._consume()
            return ProtocolCondition(protocols={Protocol.ICMP})
        if tok_type == 'ICMPV6':
            self._consume()
            return ProtocolCondition(protocols={Protocol.ICMPv6})
        if tok_type == 'ARP':
            self._consume()
            return ProtocolCondition(is_arp=True)
        if tok_type == 'IP':
            self._consume()
            return ProtocolCondition(is_ip=True)
        if tok_type == 'IPV6':
            self._consume()
            return ProtocolCondition(is_ipv6=True)

        # Application layer protocols
        if tok_type == 'TLS':
            self._consume()
            return AppProtocolCondition(protocols={'tls'})
        if tok_type == 'HTTP':
            self._consume()
            return AppProtocolCondition(protocols={'http'})
        if tok_type == 'DNS':
            self._consume()
            return AppProtocolCondition(protocols={'dns'})
        if tok_type == 'DHCP':
            self._consume()
            return AppProtocolCondition(protocols={'dhcp'})
        if tok_type == 'DHCPV6':
            self._consume()
            return AppProtocolCondition(protocols={'dhcpv6'})
        if tok_type == 'VLAN':
            self._consume()
            return AppProtocolCondition(protocols={'vlan'})
        if tok_type == 'GRE':
            self._consume()
            return AppProtocolCondition(protocols={'gre'})
        if tok_type == 'VXLAN':
            self._consume()
            return AppProtocolCondition(protocols={'vxlan'})
        if tok_type == 'MPLS':
            self._consume()
            return AppProtocolCondition(protocols={'mpls'})

        # host <ip>
        if tok_type == 'HOST':
            self._consume()
            _, addr = self._consume('IPV4_ADDR')
            return IPCondition(any_ips={addr})

        # src <ip> | src port <n>
        if tok_type == 'SRC':
            self._consume()
            if self._peek() == 'PORT':
                self._consume('PORT')
                _, num = self._consume('NUMBER')
                return PortCondition(src_ports={int(num)})
            if self._peek() == 'IPV4_ADDR':
                _, addr = self._consume('IPV4_ADDR')
                return IPCondition(src_ips={addr})
            raise ValueError("Expected IP address or 'port' after 'src'")

        # dst <ip> | dst port <n>
        if tok_type == 'DST':
            self._consume()
            if self._peek() == 'PORT':
                self._consume('PORT')
                _, num = self._consume('NUMBER')
                return PortCondition(dst_ports={int(num)})
            if self._peek() == 'IPV4_ADDR':
                _, addr = self._consume('IPV4_ADDR')
                return IPCondition(dst_ips={addr})
            raise ValueError("Expected IP address or 'port' after 'dst'")

        # Standalone IP address (treat as host)
        if tok_type == 'IPV4_ADDR':
            _, addr = self._consume()
            return IPCondition(any_ips={addr})

        # port <n>
        if tok_type == 'PORT':
            self._consume()
            _, num = self._consume('NUMBER')
            return PortCondition(any_ports={int(num)})

        _, val = self._tokens[self._pos]
        raise ValueError(f"Unexpected token: {tok_type} ({val})")


class PacketFilter:
    """
    Fast packet filter with two-stage filtering.

    Compiles the condition tree into flat closure functions at init time,
    eliminating per-packet method dispatch, generator, and struct.unpack
    overhead.

    Stage 1: Pre-check from raw buffer (link/network/transport layers)
    Stage 2: Post-parse filtering (application layer)

    Examples:
        >>> filter = PacketFilter("tcp and port 443")
        >>> # Fast pre-check
        >>> if filter.fast_check(buf):
        ...     pkt = parse_packet(buf)
        ...     # Post-parse check
        ...     if filter.post_check(pkt):
        ...         process(pkt)
    """

    def __init__(self, filter_str: str | None = None):
        """
        Initialize the packet filter.

        Args:
            filter_str: BPF filter string (e.g., "tcp and port 443")
        """
        self.filter_str = filter_str
        self.condition: FilterCondition | None = None
        self.has_app_layer = False
        self._fast_fn: Callable[[bytes], bool] | None = None
        self._post_fn: Callable[[Any], bool] | None = None
        # Mutable container so compiled closures can read updated link type
        # Default: Ethernet (DLT_EN10MB = 1)
        self._link_type_ref: list[int] = [1]

        if filter_str:
            compiler = BPFCompiler()
            self.condition = compiler.compile(filter_str)
            self._analyze_condition(self.condition)
            self._fast_fn = _compile_fast_fn(self.condition, self.has_app_layer, self._link_type_ref)
            self._post_fn = _compile_post_fn(self.condition)

    def _analyze_condition(self, condition: FilterCondition) -> None:
        """Analyze condition to check for app layer filters."""
        if isinstance(condition, AppProtocolCondition):
            self.has_app_layer = True
        elif isinstance(condition, CompoundCondition):
            for c in condition.conditions:
                self._analyze_condition(c)

    def fast_check(self, buf: bytes) -> bool:
        """
        Fast pre-check from raw buffer.

        Uses a compiled closure for minimal per-packet overhead.

        Args:
            buf: Raw packet buffer (including link layer header)

        Returns:
            True if packet should be processed, False to skip
        """
        if self._fast_fn is None:
            return True
        return self._fast_fn(buf)

    def post_check(self, pkt: ParsedPacket) -> bool:
        """
        Post-parse filtering for application layer protocols.

        Uses a compiled closure for minimal per-packet overhead.

        Args:
            pkt: Parsed packet object

        Returns:
            True if packet passes the filter
        """
        if self._post_fn is None:
            return True
        return self._post_fn(pkt)

    def __bool__(self) -> bool:
        """Check if filter is active."""
        return self.condition is not None

    def set_link_type(self, link_type: int) -> None:
        """Set the link layer type for fast_check.

        Must be called before processing packets from a new file
        so the compiled closures use the correct header offsets.

        Args:
            link_type: DLT value (1=Ethernet, 113=Linux SLL, 101=Raw IP, etc.)
        """
        self._link_type_ref[0] = link_type


# ============================================================
# Closure compiler — flattens condition tree into plain functions
# ============================================================

def _ip_str_to_bytes(ip: str) -> bytes:
    """Convert dotted-quad IP string to 4-byte bytes (compile-time helper)."""
    parts = ip.split('.')
    return bytes(int(p) for p in parts)


def _compile_fast_fn(condition: FilterCondition, has_app_layer: bool, link_type_ref: list[int]) -> Callable[[bytes], bool] | None:
    """Compile condition tree into a single buf -> bool closure."""
    if has_app_layer:
        # App-layer filters can't be checked from raw buffer; always pass
        return None

    fn = _compile_fast_node(condition, link_type_ref)
    return fn


def _resolve_ethertype(buf: bytes, link_type_ref: list[int]):
    """Resolve EtherType and IP header start offset for various link layer types.

    Supports Ethernet, Linux SLL, Raw IP, BSD Loopback.
    Returns (eth_hi, eth_lo, ip_start) or None if buffer too short.
    """
    lt = link_type_ref[0]

    if lt == 113:
        # Linux SLL: 16-byte header, protocol type at offset 14-15
        if len(buf) < 16:
            return None
        e0, e1 = buf[14], buf[15]
        if e0 == 0x81 and e1 == 0x00:
            # VLAN inside SLL
            if len(buf) < 20:
                return None
            return buf[18], buf[19], 20
        return e0, e1, 16

    if lt == 101:
        # Raw IP: no link header, detect version from first nibble
        if len(buf) < 1:
            return None
        ver = (buf[0] >> 4) & 0x0F
        if ver == 4:
            return 0x08, 0x00, 0
        if ver == 6:
            return 0x86, 0xDD, 0
        return None

    if lt == 0 or lt == 108:
        # BSD Loopback / OpenBSD Loop: 4-byte AF header
        if len(buf) < 4:
            return None
        # AF_INET=2, AF_INET6=24(BSD)/10(Linux)/30(macOS)
        import struct, sys
        af = struct.unpack('=I', buf[0:4])[0]
        if af > 255:
            af = struct.unpack('>I' if sys.byteorder == 'little' else '<I', buf[0:4])[0]
        if af == 2:
            return 0x08, 0x00, 4
        if af in (10, 24, 28, 30):
            return 0x86, 0xDD, 4
        return None

    # Default: Ethernet (DLT_EN10MB = 1 and others)
    if len(buf) < 14:
        return None
    e0, e1 = buf[12], buf[13]
    if e0 == 0x81 and e1 == 0x00:
        # 802.1Q VLAN tag: real EtherType at offset 16, IP at 18
        if len(buf) < 18:
            return None
        return buf[16], buf[17], 18
    return e0, e1, 14


def _compile_fast_node(cond: FilterCondition, lt_ref: list[int]) -> Callable[[bytes], bool]:
    """Recursively compile a single condition node for fast (buf) check."""

    if isinstance(cond, ProtocolCondition):
        protos = frozenset(cond.protocols)
        is_ip = cond.is_ip
        is_ipv6 = cond.is_ipv6
        is_arp = cond.is_arp
        negate = cond.negate

        if is_ip:
            def _f(buf: bytes, _neg=negate, _lt=lt_ref) -> bool:
                r = _resolve_ethertype(buf, _lt)
                if r is None:
                    return _neg
                return (r[0] == 0x08 and r[1] == 0x00) != _neg
            return _f

        if is_ipv6:
            def _f(buf: bytes, _neg=negate, _lt=lt_ref) -> bool:
                r = _resolve_ethertype(buf, _lt)
                if r is None:
                    return _neg
                return (r[0] == 0x86 and r[1] == 0xDD) != _neg
            return _f

        if is_arp:
            def _f(buf: bytes, _neg=negate, _lt=lt_ref) -> bool:
                r = _resolve_ethertype(buf, _lt)
                if r is None:
                    return _neg
                return (r[0] == 0x08 and r[1] == 0x06) != _neg
            return _f

        # Transport protocol check (TCP/UDP/ICMP/ICMPv6)
        def _f(buf: bytes, _protos=protos, _neg=negate, _lt=lt_ref) -> bool:
            r = _resolve_ethertype(buf, _lt)
            if r is None:
                return _neg
            e0, e1, ip_off = r
            if e0 == 0x08 and e1 == 0x00:
                result = len(buf) >= ip_off + 10 and buf[ip_off + 9] in _protos
            elif e0 == 0x86 and e1 == 0xDD:
                result = len(buf) >= ip_off + 7 and buf[ip_off + 6] in _protos
            else:
                result = False
            return result != _neg
        return _f

    if isinstance(cond, IPCondition):
        # Pre-compute IP bytes at compile time
        any_set = frozenset(_ip_str_to_bytes(ip) for ip in cond.any_ips) if cond.any_ips else None
        src_set = frozenset(_ip_str_to_bytes(ip) for ip in cond.src_ips) if cond.src_ips else None
        dst_set = frozenset(_ip_str_to_bytes(ip) for ip in cond.dst_ips) if cond.dst_ips else None
        negate = cond.negate

        def _f(buf: bytes, _any=any_set, _src=src_set, _dst=dst_set, _neg=negate, _lt=lt_ref) -> bool:
            r = _resolve_ethertype(buf, _lt)
            if r is None:
                return _neg
            e0, e1, ip_off = r
            if e0 != 0x08 or e1 != 0x00:
                return _neg  # not IPv4
            if len(buf) < ip_off + 20:
                return _neg
            src = bytes(buf[ip_off + 12:ip_off + 16])
            dst = bytes(buf[ip_off + 16:ip_off + 20])
            result = False
            if _any:
                result = src in _any or dst in _any
            if _src:
                result = result or src in _src
            if _dst:
                result = result or dst in _dst
            return result != _neg
        return _f

    if isinstance(cond, PortCondition):
        any_ports = frozenset(cond.any_ports) if cond.any_ports else None
        src_ports = frozenset(cond.src_ports) if cond.src_ports else None
        dst_ports = frozenset(cond.dst_ports) if cond.dst_ports else None
        negate = cond.negate

        def _f(buf: bytes, _any=any_ports, _src=src_ports, _dst=dst_ports, _neg=negate, _lt=lt_ref) -> bool:
            r = _resolve_ethertype(buf, _lt)
            if r is None:
                return _neg
            e0, e1, ip_off = r
            if e0 != 0x08 or e1 != 0x00:
                return _neg
            ihl = (buf[ip_off] & 0x0F) * 4
            off = ip_off + ihl
            if len(buf) < off + 4:
                return _neg
            sp = (buf[off] << 8) | buf[off + 1]
            dp = (buf[off + 2] << 8) | buf[off + 3]
            result = False
            if _any:
                result = sp in _any or dp in _any
            if _src:
                result = result or sp in _src
            if _dst:
                result = result or dp in _dst
            return result != _neg
        return _f

    if isinstance(cond, AppProtocolCondition):
        # App layer can't be checked from raw buffer — always pass
        def _f(buf: bytes) -> bool:
            return True
        return _f

    if isinstance(cond, CompoundCondition):
        sub_fns = [_compile_fast_node(c, lt_ref) for c in cond.conditions]
        op = cond.operator
        negate = cond.negate

        if not sub_fns:
            # Empty compound — "or" with no children = False, "and" with no children = True
            val = (op == "and") != negate
            def _f(buf: bytes, _v=val) -> bool:
                return _v
            return _f

        if op == "and":
            if negate:
                def _f(buf: bytes, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if not fn(buf):
                            return True
                    return False
            else:
                def _f(buf: bytes, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if not fn(buf):
                            return False
                    return True
        else:  # or
            if negate:
                def _f(buf: bytes, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if fn(buf):
                            return False
                    return True
            else:
                def _f(buf: bytes, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if fn(buf):
                            return True
                    return False
        return _f

    # Fallback — use the original .matches method
    def _f(buf: bytes, _c=cond) -> bool:
        return _c.matches(None, buf)
    return _f


def _compile_post_fn(condition: FilterCondition) -> Callable[[Any], bool] | None:
    """Compile condition tree into a single pkt -> bool closure."""
    fn = _compile_post_node(condition)
    return fn


def _compile_post_node(cond: FilterCondition) -> Callable[[Any], bool]:
    """Recursively compile a single condition node for post (pkt) check."""

    if isinstance(cond, ProtocolCondition):
        protos = frozenset(cond.protocols)
        is_ip = cond.is_ip
        is_ipv6 = cond.is_ipv6
        is_arp = cond.is_arp
        negate = cond.negate

        def _f(pkt, _protos=protos, _ip=is_ip, _ip6=is_ipv6, _arp=is_arp, _neg=negate) -> bool:
            result = False
            if _ip or _ip6 or _arp:
                if _ip and pkt.ip:
                    result = True
                elif _ip6 and pkt.ip6:
                    result = True
                elif _arp and pkt.arp:
                    result = True
            elif _protos:
                if pkt.ip and pkt.ip.proto in _protos:
                    result = True
                elif pkt.ip6 and pkt.ip6.next_header in _protos:
                    result = True
            return result != _neg
        return _f

    if isinstance(cond, IPCondition):
        any_ips = frozenset(cond.any_ips) if cond.any_ips else None
        src_ips = frozenset(cond.src_ips) if cond.src_ips else None
        dst_ips = frozenset(cond.dst_ips) if cond.dst_ips else None
        negate = cond.negate

        def _f(pkt, _any=any_ips, _src=src_ips, _dst=dst_ips, _neg=negate) -> bool:
            s = pkt.ip.src if pkt.ip else (pkt.ip6.src if pkt.ip6 else "")
            d = pkt.ip.dst if pkt.ip else (pkt.ip6.dst if pkt.ip6 else "")
            result = False
            if _any:
                result = s in _any or d in _any
            if _src:
                result = result or s in _src
            if _dst:
                result = result or d in _dst
            return result != _neg
        return _f

    if isinstance(cond, PortCondition):
        any_ports = frozenset(cond.any_ports) if cond.any_ports else None
        src_ports = frozenset(cond.src_ports) if cond.src_ports else None
        dst_ports = frozenset(cond.dst_ports) if cond.dst_ports else None
        negate = cond.negate

        def _f(pkt, _any=any_ports, _src=src_ports, _dst=dst_ports, _neg=negate) -> bool:
            sp = pkt.tcp.sport if pkt.tcp else (pkt.udp.sport if pkt.udp else 0)
            dp = pkt.tcp.dport if pkt.tcp else (pkt.udp.dport if pkt.udp else 0)
            result = False
            if _any:
                result = sp in _any or dp in _any
            if _src:
                result = result or sp in _src
            if _dst:
                result = result or dp in _dst
            return result != _neg
        return _f

    if isinstance(cond, AppProtocolCondition):
        app_protos = frozenset(cond.protocols)
        negate = cond.negate

        def _f(pkt, _protos=app_protos, _neg=negate) -> bool:
            result = False
            if 'tls' in _protos and pkt.tls:
                result = True
            if 'http' in _protos and pkt.http:
                result = True
            if 'dns' in _protos and pkt.dns:
                result = True
            if 'dhcp' in _protos and pkt.dhcp:
                result = True
            if 'dhcpv6' in _protos and pkt.dhcpv6:
                result = True
            if 'vlan' in _protos and pkt.vlan:
                result = True
            if 'gre' in _protos and pkt.gre:
                result = True
            if 'vxlan' in _protos and pkt.vxlan:
                result = True
            if 'mpls' in _protos and pkt.mpls:
                result = True
            return result != _neg
        return _f

    if isinstance(cond, CompoundCondition):
        sub_fns = [_compile_post_node(c) for c in cond.conditions]
        op = cond.operator
        negate = cond.negate

        if not sub_fns:
            val = (op == "and") != negate
            def _f(pkt, _v=val) -> bool:
                return _v
            return _f

        if op == "and":
            if negate:
                def _f(pkt, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if not fn(pkt):
                            return True
                    return False
            else:
                def _f(pkt, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if not fn(pkt):
                            return False
                    return True
        else:
            if negate:
                def _f(pkt, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if fn(pkt):
                            return False
                    return True
            else:
                def _f(pkt, _fns=sub_fns) -> bool:
                    for fn in _fns:
                        if fn(pkt):
                            return True
                    return False
        return _f

    # Fallback
    def _f(pkt, _c=cond) -> bool:
        return _c.matches(pkt, None)
    return _f


def compile_filter(filter_str: str | None) -> PacketFilter:
    """
    Compile a BPF filter string into a PacketFilter.

    Args:
        filter_str: BPF filter string (e.g., "tcp and port 443")

    Returns:
        PacketFilter object

    Examples:
        >>> f = compile_filter("tcp and port 443")
        >>> f.fast_check(buf)
        True
        >>> f.post_check(pkt)
        True
    """
    return PacketFilter(filter_str)
