"""
Protocol field access wrapper module.

Provides convenient access to protocol fields at each layer through
typed dataclasses that wrap raw protocol data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    import dpkt


class Layer(Enum):
    """OSI-like layer enumeration.

    Attributes:
        PHYSICAL: Physical layer (Layer 1)
        DATA_LINK: Data link layer (Layer 2)
        NETWORK: Network layer (Layer 3)
        TRANSPORT: Transport layer (Layer 4)
        SESSION: Session layer (Layer 5)
        PRESENTATION: Presentation layer (Layer 6)
        APPLICATION: Application layer (Layer 7)
    """
    PHYSICAL = 1
    DATA_LINK = 2
    NETWORK = 3
    TRANSPORT = 4
    SESSION = 5
    PRESENTATION = 6
    APPLICATION = 7


@dataclass
class EthernetInfo:
    """Ethernet layer information.

    Attributes:
        src: Source MAC address in colon-separated hex format (e.g., "aa:bb:cc:dd:ee:ff")
        dst: Destination MAC address in colon-separated hex format
        type: EtherType field (e.g., 0x0800 for IPv4, 0x86DD for IPv6)
        _raw: Raw bytes of the Ethernet frame
    """
    src: str = ""
    dst: str = ""
    type: int = 0
    _raw: bytes = b""

    @classmethod
    def from_dpkt(cls, eth: dpkt.ethernet.Ethernet) -> EthernetInfo:
        """Create EthernetInfo from dpkt Ethernet object.

        Args:
            eth: dpkt.ethernet.Ethernet object

        Returns:
            EthernetInfo with parsed fields
        """
        return cls(
            src="{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*eth.src),
            dst="{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*eth.dst),
            type=eth.type,
        )


@dataclass
class IPInfo:
    """IPv4 layer information.

    Attributes:
        version: IP version (4 for IPv4)
        src: Source IP address in dotted decimal format
        dst: Destination IP address in dotted decimal format
        proto: IP protocol number (e.g., 6 for TCP, 17 for UDP, 1 for ICMP)
        ttl: Time-to-live value
        len: Total length of the IP packet
        id: Identification field for fragmentation
        flags: Fragment flags (DF, MF)
        offset: Fragment offset in 8-byte units
        _raw: Raw bytes of the IP packet
    """
    version: int = 0
    src: str = ""
    dst: str = ""
    proto: int = 0
    ttl: int = 0
    len: int = 0
    id: int = 0
    flags: int = 0
    offset: int = 0
    _raw: bytes = b""

    @property
    def is_fragment(self) -> bool:
        """Check if this packet is a fragment.

        Returns:
            True if MF flag is set or offset is non-zero
        """
        return self.flags & 0x1 != 0 or self.offset != 0

    @property
    def is_fragmented(self) -> bool:
        """Check if more fragments are expected.

        Returns:
            True if MF (More Fragments) flag is set
        """
        return self.flags & 0x1 != 0

    @property
    def more_fragments(self) -> bool:
        """Check if more fragments are expected.

        Returns:
            True if MF (More Fragments) flag is set
        """
        return (self.flags & 0x1) != 0

    @classmethod
    def from_dpkt(cls, ip: dpkt.ip.IP) -> IPInfo:
        """Create IPInfo from dpkt IP object.

        Args:
            ip: dpkt.ip.IP object

        Returns:
            IPInfo with parsed fields
        """
        import socket
        return cls(
            version=ip.v,
            src=socket.inet_ntop(socket.AF_INET, ip.src),
            dst=socket.inet_ntop(socket.AF_INET, ip.dst),
            proto=ip.p,
            ttl=ip.ttl,
            len=ip.len,
            id=ip.id,
            flags=(ip._flags_offset & 0xe000) >> 13,
            offset=ip._flags_offset & 0x1fff,
        )


@dataclass
class IP6Info:
    """IPv6 layer information.

    Attributes:
        version: IP version (6 for IPv6)
        src: Source IPv6 address
        dst: Destination IPv6 address
        next_header: Next header protocol number
        hop_limit: Hop limit (similar to TTL in IPv4)
        flow_label: Flow label for QoS
        len: Payload length
        _raw: Raw bytes of the IPv6 packet
    """
    version: int = 0
    src: str = ""
    dst: str = ""
    next_header: int = 0
    hop_limit: int = 0
    flow_label: int = 0
    len: int = 0
    _raw: bytes = b""

    @classmethod
    def from_dpkt(cls, ip6: dpkt.ip6.IP6) -> IP6Info:
        """Create IP6Info from dpkt IP6 object.

        Args:
            ip6: dpkt.ip6.IP6 object

        Returns:
            IP6Info with parsed fields
        """
        import socket
        return cls(
            version=ip6.v,
            src=socket.inet_ntop(socket.AF_INET6, ip6.src),
            dst=socket.inet_ntop(socket.AF_INET6, ip6.dst),
            next_header=ip6.nxt,
            hop_limit=ip6.hlim,
            flow_label=ip6.flow,
            len=ip6.plen,
        )


@dataclass
class TCPInfo:
    """TCP segment information.

    Attributes:
        sport: Source port number
        dport: Destination port number
        seq: Sequence number
        ack_num: Acknowledgment number
        flags: TCP flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
        win: Window size
        urgent: Urgent pointer
        options: TCP options data
        _raw: Raw bytes of the TCP segment
    """
    sport: int = 0
    dport: int = 0
    seq: int = 0
    ack_num: int = 0
    flags: int = 0
    win: int = 0
    urgent: int = 0
    options: bytes = b""
    _raw: bytes = b""

    @property
    def syn(self) -> bool:
        """Check if SYN flag is set.

        Returns:
            True if SYN flag is set
        """
        return bool(self.flags & 0x02)

    @property
    def fin(self) -> bool:
        """Check if FIN flag is set.

        Returns:
            True if FIN flag is set
        """
        return bool(self.flags & 0x01)

    @property
    def rst(self) -> bool:
        """Check if RST flag is set.

        Returns:
            True if RST flag is set
        """
        return bool(self.flags & 0x04)

    @property
    def psh(self) -> bool:
        """Check if PSH (push) flag is set.

        Returns:
            True if PSH flag is set
        """
        return bool(self.flags & 0x08)

    @property
    def ack(self) -> bool:
        """Check if ACK flag is set.

        Returns:
            True if ACK flag is set
        """
        return bool(self.flags & 0x10)

    @property
    def urg(self) -> bool:
        """Check if URG flag is set.

        Returns:
            True if URG flag is set
        """
        return bool(self.flags & 0x20)

    @property
    def ece(self) -> bool:
        """Check if ECE flag is set.

        Returns:
            True if ECE flag is set
        """
        return bool(self.flags & 0x40)

    @property
    def cwr(self) -> bool:
        """Check if CWR flag is set.

        Returns:
            True if CWR flag is set
        """
        return bool(self.flags & 0x80)

    @property
    def is_handshake(self) -> bool:
        """Check if this is a SYN packet (connection initiation).

        Returns:
            True if SYN is set but ACK is not
        """
        return self.syn and not self.ack

    @property
    def is_handshake_ack(self) -> bool:
        """Check if this is a SYN-ACK packet.

        Returns:
            True if both SYN and ACK are set
        """
        return self.syn and self.ack

    @classmethod
    def from_dpkt(cls, tcp: dpkt.tcp.TCP) -> TCPInfo:
        """Create TCPInfo from dpkt TCP object.

        Args:
            tcp: dpkt.tcp.TCP object

        Returns:
            TCPInfo with parsed fields
        """
        return cls(
            sport=tcp.sport,
            dport=tcp.dport,
            seq=tcp.seq,
            ack_num=tcp.ack if tcp.flags & 0x10 else 0,
            flags=tcp.flags,
            win=tcp.win,
            urgent=tcp.urp,
            options=tcp.opts,
        )


@dataclass
class UDPInfo:
    """UDP datagram information.

    Attributes:
        sport: Source port number
        dport: Destination port number
        len: Total length of UDP datagram (header + data)
        _raw: Raw bytes of the UDP datagram
    """
    sport: int = 0
    dport: int = 0
    len: int = 0
    _raw: bytes = b""

    @classmethod
    def from_dpkt(cls, udp: dpkt.udp.UDP) -> UDPInfo:
        """Create UDPInfo from dpkt UDP object.

        Args:
            udp: dpkt.udp.UDP object

        Returns:
            UDPInfo with parsed fields
        """
        return cls(
            sport=udp.sport,
            dport=udp.dport,
            len=udp.ulen,
        )


@dataclass
class ICMPInfo:
    """ICMP message information.

    Attributes:
        type: ICMP message type (e.g., 8 for echo request, 0 for echo reply)
        code: ICMP message code
        _raw: Raw bytes of the ICMP message
    """
    type: int = 0
    code: int = 0
    _raw: bytes = b""

    @classmethod
    def from_dpkt(cls, icmp: dpkt.icmp.ICMP) -> ICMPInfo:
        """Create ICMPInfo from dpkt ICMP object.

        Args:
            icmp: dpkt.icmp.ICMP object

        Returns:
            ICMPInfo with parsed fields
        """
        return cls(
            type=icmp.type,
            code=icmp.code,
        )


@dataclass
class CertificateInfo:
    """X.509 certificate information.

    Attributes:
        version: Certificate version (e.g., "v1", "v3")
        serial_number: Certificate serial number in hex format
        subject: Subject distinguished name
        issuer: Issuer distinguished name
        validity_not_before: Certificate validity start date (ISO format)
        validity_not_after: Certificate validity end date (ISO format)
        public_key_type: Type of public key (e.g., "RSAPublicKey")
        signature_algorithm: Signature algorithm name
        extensions: List of certificate extensions
        _raw: Raw DER-encoded certificate bytes
    """
    version: int | None = None
    serial_number: str | None = None
    subject: str | None = None
    issuer: str | None = None
    validity_not_before: str | None = None
    validity_not_after: str | None = None
    public_key_type: str | None = None
    signature_algorithm: str | None = None
    extensions: list[str] = field(default_factory=list)
    _raw: bytes = b""

    def __str__(self) -> str:
        """Return string representation of certificate.

        Returns:
            Formatted string with subject and issuer
        """
        return f"Certificate(subject={self.subject}, issuer={self.issuer})"


@dataclass
class TLSInfo:
    """TLS/SSL protocol information.

    Attributes:
        version: TLS version string (e.g., "TLS 1.2")
        content_type: TLS record content type (20-24)
        handshake_type: Handshake message type (for content_type=22)
        sni: Server Name Indication from ClientHello (list if multiple, str if single)
        cipher_suites: List of cipher suite IDs from ClientHello
        cipher_suite: Selected cipher suite from ServerHello (object with name attribute)
        alpn: Application-Layer Protocol Negotiation values (list if multiple)
        signature_algorithms: Signature algorithms from ClientHello
        supported_groups: Supported groups from ClientHello
        certificate: Parsed end-entity certificate
        certificates: All certificates from Certificate message
        exts: Extensions organized by type {ext_type: [ext_data1, ext_data2, ...]}
        extensions: Legacy list of (type, data) tuples for backward compatibility
        record_length: Length of the TLS record
        _raw: Raw bytes of the TLS record
    """
    version: str | None = None
    content_type: int | None = None
    handshake_type: int | None = None
    sni: list[str] = field(default_factory=list)
    cipher_suites: list[int] = field(default_factory=list)
    cipher_suite: object = None
    alpn: list[str] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    certificate: CertificateInfo | None = None
    certificates: list[CertificateInfo] = field(default_factory=list)
    exts: dict[int, list[bytes]] = field(default_factory=dict)
    extensions: list[tuple[int, bytes]] = field(default_factory=list)  # Legacy
    record_length: int = 0
    _raw: bytes = b""

    def get_extension(self, ext_type: int) -> list[bytes] | None:
        """Get all extension data for a given extension type.

        Args:
            ext_type: Extension type (e.g., 0 for server_name, 16 for ALPN)

        Returns:
            List of extension data bytes, or None if extension not found
        """
        return self.exts.get(ext_type)

    def get_extension_first(self, ext_type: int) -> bytes | None:
        """Get the first extension data for a given extension type.

        Args:
            ext_type: Extension type

        Returns:
            First extension data bytes, or None if extension not found
        """
        ext_list = self.exts.get(ext_type)
        return ext_list[0] if ext_list else None

    @property
    def content_type_name(self) -> str | None:
        """Get content type name.

        Returns:
            Human-readable content type name or None
        """
        names = {
            20: "change_cipher_spec",
            21: "alert",
            22: "handshake",
            23: "application_data",
            24: "heartbeat",
        }
        return names.get(self.content_type)

    @property
    def handshake_type_name(self) -> str | None:
        """Get handshake type name.

        Returns:
            Human-readable handshake type name or None
        """
        names = {
            0: "hello_request",
            1: "client_hello",
            2: "server_hello",
            11: "certificate",
            12: "server_key_exchange",
            13: "certificate_request",
            14: "server_hello_done",
            15: "certificate_verify",
            16: "client_key_exchange",
            20: "finished",
        }
        return names.get(self.handshake_type)

    @property
    def version_name(self) -> str | None:
        """Get TLS version name.

        Returns:
            Human-readable TLS version name or None
        """
        if self.version == "3.1":
            return "TLS 1.0"
        elif self.version == "3.2":
            return "TLS 1.1"
        elif self.version == "3.3":
            return "TLS 1.2"
        elif self.version == "3.4":
            return "TLS 1.3"
        return self.version


@dataclass
class HTTPInfo:
    """HTTP protocol information.

    Attributes:
        method: HTTP method for requests (e.g., "GET", "POST")
        host: Host header value
        path: Request path
        user_agent: User-Agent header value
        status_code: HTTP status code for responses
        status_reason: HTTP status reason phrase
        headers: Dictionary of all HTTP headers
        content_type: Content-Type header value
        content_length: Content-Length header value
        version: HTTP version string
        _raw: Raw bytes of the HTTP message
    """
    method: str | None = None
    host: str | None = None
    path: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    status_reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    content_length: int | None = None
    version: str | None = None
    _raw: bytes = b""

    @property
    def is_request(self) -> bool:
        """Check if this is an HTTP request.

        Returns:
            True if method is not None
        """
        return self.method is not None

    @property
    def is_response(self) -> bool:
        """Check if this is an HTTP response.

        Returns:
            True if status_code is not None
        """
        return self.status_code is not None


@dataclass
class DNSInfo:
    """DNS protocol information.

    Attributes:
        queries: List of query domain names
        answers: List of answer domain names
        response_code: DNS response code (0 = no error)
        question_count: Number of question records
        answer_count: Number of answer records
        authority_count: Number of authority records
        additional_count: Number of additional records
        flags: DNS flags field
        _raw: Raw bytes of the DNS message
    """
    queries: list[str] = field(default_factory=list)
    answers: list[str] = field(default_factory=list)
    response_code: int = 0
    question_count: int = 0
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0
    flags: int = 0
    _raw: bytes = b""

    @property
    def is_query(self) -> bool:
        """Check if this is a DNS query (QR bit = 0)."""
        return not bool(self.flags & 0x8000)

    @property
    def is_response(self) -> bool:
        """Check if this is a DNS response (QR bit = 1)."""
        return bool(self.flags & 0x8000)


@dataclass
class ParsedPacket:
    """Wrapper around a parsed packet with protocol layer accessors.

    Provides convenient access to protocol fields at each layer through
    typed Info objects. All layers are optional and populated as parsing
    progresses through the protocol stack.

    Attributes:
        timestamp: Packet timestamp in seconds since epoch
        raw_data: Raw packet bytes from PCAP
        link_layer_type: DLT (Data Link Type) value
        caplen: Captured length
        wirelen: Original wire length
        eth: Ethernet layer info (if present)
        ip: IPv4 layer info (if present)
        ip6: IPv6 layer info (if present)
        tcp: TCP layer info (if present)
        udp: UDP layer info (if present)
        icmp: ICMP layer info (if present)
        tls: TLS layer info (if present)
        http: HTTP layer info (if present)
        dns: DNS layer info (if present)
        is_client_to_server: Direction flag (True = C2S, False = S2C)
        packet_index: Packet index within flow
        flow_index: Flow index in capture
        _raw_eth: Raw link layer object
        _raw_ip: Raw network layer object
        _raw_transport: Raw transport layer object
        _raw_app: Raw application layer object
    """
    timestamp: float = 0.0
    raw_data: bytes = b""
    link_layer_type: int = 0
    caplen: int = 0
    wirelen: int = 0  # Total packet length (Ethernet + IP + TCP/UDP + payload)
    ip_len: int = 0   # IP total length (IP header + transport + payload)
    trans_len: int = 0  # Transport payload length (TCP/UDP header + payload)
    app_len: int = 0   # App payload length (excludes TCP/UDP header)

    # Protocol layer fields - populated as packets are parsed
    eth: EthernetInfo | None = None
    ip: IPInfo | None = None
    ip6: IP6Info | None = None
    tcp: TCPInfo | None = None
    udp: UDPInfo | None = None
    icmp: ICMPInfo | None = None
    tls: TLSInfo | None = None
    http: HTTPInfo | None = None
    dns: DNSInfo | None = None

    # Direction tracking
    is_client_to_server: bool = True
    packet_index: int = -1
    flow_index: int = -1

    # Raw protocol objects for advanced access
    _raw_eth: object | None = None
    _raw_ip: object | None = None
    _raw_transport: object | None = None
    _raw_app: object | None = None

    # Raw TCP payload (for reassembly)
    _raw_tcp_payload: bytes = b""

    @property
    def payload(self) -> bytes:
        """Get the payload bytes at the highest decoded layer.

        Returns:
            Payload bytes or empty bytes if no payload
        """
        if self._raw_app:
            return getattr(self._raw_app, 'data', b'')
        return self._raw_tcp_payload

    @property
    def has_payload(self) -> bool:
        """Check if packet has payload data.

        Returns:
            True if payload length > 0
        """
        return len(self.payload) > 0

    def to_dict(self) -> dict:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all non-null protocol fields
        """
        result = {
            'timestamp': self.timestamp,
            'caplen': self.caplen,
            'wirelen': self.wirelen,
            'is_client_to_server': self.is_client_to_server,
        }
        if self.eth:
            result['eth'] = {
                'src': self.eth.src,
                'dst': self.eth.dst,
                'type': self.eth.type,
            }
        if self.ip:
            result['ip'] = {
                'src': self.ip.src,
                'dst': self.ip.dst,
                'proto': self.ip.proto,
                'ttl': self.ip.ttl,
            }
        if self.tcp:
            result['tcp'] = {
                'sport': self.tcp.sport,
                'dport': self.tcp.dport,
                'flags': self.tcp.flags,
                'seq': self.tcp.seq,
                'ack': self.tcp.ack_num,
                'win': self.tcp.win,
            }
        if self.udp:
            result['udp'] = {
                'sport': self.udp.sport,
                'dport': self.udp.dport,
                'len': self.udp.len,
            }
        if self.tls:
            result['tls'] = {
                'version': self.tls.version,
                'content_type': self.tls.content_type,
                'handshake_type': self.tls.handshake_type,
            }
            if self.tls.sni:
                result['tls']['sni'] = self.tls.sni
            if self.tls.certificate:
                result['tls']['cert_subject'] = self.tls.certificate.subject
                result['tls']['cert_issuer'] = self.tls.certificate.issuer
        if self.http:
            result['http'] = {
                'method': self.http.method,
                'host': self.http.host,
                'status_code': self.http.status_code,
            }
        if self.dns:
            result['dns'] = {
                'queries': self.dns.queries,
                'response_code': self.dns.response_code,
            }
        return result
