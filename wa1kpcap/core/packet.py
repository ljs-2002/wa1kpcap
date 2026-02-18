"""
Protocol field access wrapper module.

Provides convenient access to protocol fields at each layer through
typed dataclasses that wrap raw protocol data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    import dpkt


class _ProtocolInfoBase:
    """Abstract base for all protocol info objects. No slots defined here."""
    __slots__ = ()


class ProtocolInfo(_ProtocolInfoBase):
    """Base class for protocol info objects.

    Custom protocols use _fields dict. Built-in subclasses use __slots__ directly.
    """
    __slots__ = ('_fields',)

    def __init__(self, fields: dict | None = None, **kwargs):
        self._fields = fields or {}
        self._fields.update(kwargs)

    def get(self, key: str, default=None):
        return self._fields.get(key, default)

    def copy(self) -> 'ProtocolInfo':
        """Create a shallow clone with deep-copied mutable values (lists, dicts)."""
        copied = {}
        for k, v in self._fields.items():
            if isinstance(v, list):
                copied[k] = list(v)
            elif isinstance(v, dict):
                copied[k] = dict(v)
            else:
                copied[k] = v
        return type(self)(fields=copied)

    def merge(self, other: 'ProtocolInfo') -> None:
        """Merge another instance into this one. Override in subclasses."""
        for k, v in other._fields.items():
            if k not in self._fields or self._fields[k] is None:
                self._fields[k] = v


class _SlottedInfoBase(_ProtocolInfoBase):
    """Base for __slots__-based built-in Info classes.

    Subclasses must define _SLOT_NAMES (tuple of field names).
    Inherits from _ProtocolInfoBase so isinstance(_ProtocolInfoBase) passes.
    """
    __slots__ = ()

    def get(self, key: str, default=None):
        try:
            return getattr(self, key)
        except AttributeError:
            return default

    @property
    def _fields(self) -> dict:
        return {k: getattr(self, k) for k in self._SLOT_NAMES}

    def copy(self):
        obj = object.__new__(type(self))
        for k in self._SLOT_NAMES:
            v = getattr(self, k)
            if isinstance(v, list):
                v = list(v)
            elif isinstance(v, dict):
                v = dict(v)
            setattr(obj, k, v)
        return obj

    def merge(self, other) -> None:
        for k in self._SLOT_NAMES:
            cur = getattr(self, k)
            if cur is None:
                v = getattr(other, k, None)
                if v is not None:
                    setattr(self, k, v)


class ProtocolRegistry:
    """Maps protocol names to ProtocolInfo subclasses."""
    _instance = None

    def __init__(self):
        self._registry: dict[str, type[ProtocolInfo]] = {}

    @classmethod
    def get_instance(cls) -> 'ProtocolRegistry':
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, name: str, info_class: type[ProtocolInfo]):
        self._registry[name] = info_class

    def get(self, name: str) -> type[ProtocolInfo] | None:
        return self._registry.get(name)

    def create(self, name: str, fields: dict) -> ProtocolInfo | None:
        cls = self._registry.get(name)
        if cls is None:
            return ProtocolInfo(fields)  # generic fallback
        return cls(fields=fields)


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


class EthernetInfo(_SlottedInfoBase):
    """Ethernet layer information."""
    __slots__ = ('src', 'dst', 'type', '_raw')
    _SLOT_NAMES = ('src', 'dst', 'type', '_raw')
    _SLOT_DEFAULTS = ('', '', 0, b'')

    def __init__(self, src="", dst="", type=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.src = fields.get('src', "")
            self.dst = fields.get('dst', "")
            self.type = fields.get('type', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.src = src
            self.dst = dst
            self.type = type
            self._raw = _raw

    @classmethod
    def from_dpkt(cls, eth: dpkt.ethernet.Ethernet) -> EthernetInfo:
        return cls(
            src="{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*eth.src),
            dst="{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*eth.dst),
            type=eth.type,
        )


class IPInfo(_SlottedInfoBase):
    """IPv4 layer information."""
    __slots__ = ('version', 'src', 'dst', 'proto', 'ttl', 'len', 'id', 'flags', 'offset', '_raw')
    _SLOT_NAMES = ('version', 'src', 'dst', 'proto', 'ttl', 'len', 'id', 'flags', 'offset', '_raw')
    _SLOT_DEFAULTS = (0, '', '', 0, 0, 0, 0, 0, 0, b'')

    def __init__(self, version=0, src="", dst="", proto=0, ttl=0, len=0,
                 id=0, flags=0, offset=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.version = fields.get('version', 0)
            self.src = fields.get('src', "")
            self.dst = fields.get('dst', "")
            self.proto = fields.get('proto', 0)
            self.ttl = fields.get('ttl', 0)
            self.len = fields.get('len', 0)
            self.id = fields.get('id', 0)
            self.flags = fields.get('flags', 0)
            self.offset = fields.get('offset', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.version = version
            self.src = src
            self.dst = dst
            self.proto = proto
            self.ttl = ttl
            self.len = len
            self.id = id
            self.flags = flags
            self.offset = offset
            self._raw = _raw

    @property
    def is_fragment(self) -> bool:
        return self.flags & 0x1 != 0 or self.offset != 0

    @property
    def is_fragmented(self) -> bool:
        return self.flags & 0x1 != 0

    @property
    def more_fragments(self) -> bool:
        return (self.flags & 0x1) != 0

    @classmethod
    def from_dpkt(cls, ip: dpkt.ip.IP) -> IPInfo:
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


class IP6Info(_SlottedInfoBase):
    """IPv6 layer information."""
    __slots__ = ('version', 'src', 'dst', 'next_header', 'hop_limit', 'flow_label', 'len', '_raw')
    _SLOT_NAMES = ('version', 'src', 'dst', 'next_header', 'hop_limit', 'flow_label', 'len', '_raw')
    _SLOT_DEFAULTS = (0, '', '', 0, 0, 0, 0, b'')

    def __init__(self, version=0, src="", dst="", next_header=0, hop_limit=0,
                 flow_label=0, len=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.version = fields.get('version', 0)
            self.src = fields.get('src', "")
            self.dst = fields.get('dst', "")
            self.next_header = fields.get('next_header', 0)
            self.hop_limit = fields.get('hop_limit', 0)
            self.flow_label = fields.get('flow_label', 0)
            self.len = fields.get('len', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.version = version
            self.src = src
            self.dst = dst
            self.next_header = next_header
            self.hop_limit = hop_limit
            self.flow_label = flow_label
            self.len = len
            self._raw = _raw

    @classmethod
    def from_dpkt(cls, ip6: dpkt.ip6.IP6) -> IP6Info:
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


class TCPInfo(_SlottedInfoBase):
    """TCP segment information."""
    __slots__ = ('sport', 'dport', 'seq', 'ack_num', 'flags', 'win', 'urgent', 'options', '_raw')
    _SLOT_NAMES = ('sport', 'dport', 'seq', 'ack_num', 'flags', 'win', 'urgent', 'options', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, 0, 0, 0, 0, b'', b'')

    def __init__(self, sport=0, dport=0, seq=0, ack_num=0, flags=0,
                 win=0, urgent=0, options=b"", _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.sport = fields.get('sport', 0)
            self.dport = fields.get('dport', 0)
            self.seq = fields.get('seq', 0)
            self.ack_num = fields.get('ack_num', 0)
            self.flags = fields.get('flags', 0)
            self.win = fields.get('win', 0)
            self.urgent = fields.get('urgent', 0)
            self.options = fields.get('options', b"")
            self._raw = fields.get('_raw', b"")
        else:
            self.sport = sport
            self.dport = dport
            self.seq = seq
            self.ack_num = ack_num
            self.flags = flags
            self.win = win
            self.urgent = urgent
            self.options = options
            self._raw = _raw

    @property
    def syn(self) -> bool: return bool(self.flags & 0x02)
    @property
    def fin(self) -> bool: return bool(self.flags & 0x01)
    @property
    def rst(self) -> bool: return bool(self.flags & 0x04)
    @property
    def psh(self) -> bool: return bool(self.flags & 0x08)
    @property
    def ack(self) -> bool: return bool(self.flags & 0x10)
    @property
    def urg(self) -> bool: return bool(self.flags & 0x20)
    @property
    def ece(self) -> bool: return bool(self.flags & 0x40)
    @property
    def cwr(self) -> bool: return bool(self.flags & 0x80)

    @property
    def is_handshake(self) -> bool: return self.syn and not self.ack
    @property
    def is_handshake_ack(self) -> bool: return self.syn and self.ack

    @classmethod
    def from_dpkt(cls, tcp: dpkt.tcp.TCP) -> TCPInfo:
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


class UDPInfo(_SlottedInfoBase):
    """UDP datagram information."""
    __slots__ = ('sport', 'dport', 'len', '_raw')
    _SLOT_NAMES = ('sport', 'dport', 'len', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, b'')

    def __init__(self, sport=0, dport=0, len=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.sport = fields.get('sport', 0)
            self.dport = fields.get('dport', 0)
            self.len = fields.get('len', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.sport = sport
            self.dport = dport
            self.len = len
            self._raw = _raw

    @classmethod
    def from_dpkt(cls, udp: dpkt.udp.UDP) -> UDPInfo:
        return cls(
            sport=udp.sport,
            dport=udp.dport,
            len=udp.ulen,
        )


class ICMPInfo(_SlottedInfoBase):
    """ICMP message information."""
    __slots__ = ('type', 'code', '_raw')
    _SLOT_NAMES = ('type', 'code', '_raw')
    _SLOT_DEFAULTS = (0, 0, b'')

    def __init__(self, type=0, code=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.type = fields.get('type', 0)
            self.code = fields.get('code', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.type = type
            self.code = code
            self._raw = _raw

    @classmethod
    def from_dpkt(cls, icmp: dpkt.icmp.ICMP) -> ICMPInfo:
        return cls(type=icmp.type, code=icmp.code)


class ARPInfo(_SlottedInfoBase):
    """ARP message information."""
    __slots__ = ('hw_type', 'proto_type', 'opcode', 'sender_mac', 'sender_ip', 'target_mac', 'target_ip', '_raw')
    _SLOT_NAMES = ('hw_type', 'proto_type', 'opcode', 'sender_mac', 'sender_ip', 'target_mac', 'target_ip', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, '', '', '', '', b'')

    def __init__(self, hw_type=0, proto_type=0, opcode=0,
                 sender_mac="", sender_ip="", target_mac="", target_ip="",
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.hw_type = fields.get('hw_type', 0)
            self.proto_type = fields.get('proto_type', 0)
            self.opcode = fields.get('opcode', 0)
            self.sender_mac = fields.get('sender_mac', "")
            self.sender_ip = fields.get('sender_ip', "")
            self.target_mac = fields.get('target_mac', "")
            self.target_ip = fields.get('target_ip', "")
            self._raw = fields.get('_raw', b"")
        else:
            self.hw_type = hw_type
            self.proto_type = proto_type
            self.opcode = opcode
            self.sender_mac = sender_mac
            self.sender_ip = sender_ip
            self.target_mac = target_mac
            self.target_ip = target_ip
            self._raw = _raw


class ICMP6Info(_SlottedInfoBase):
    """ICMPv6 message information."""
    __slots__ = ('type', 'code', 'checksum', '_raw')
    _SLOT_NAMES = ('type', 'code', 'checksum', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, b'')

    def __init__(self, type=0, code=0, checksum=0, _raw=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            self.type = fields.get('type', 0)
            self.code = fields.get('code', 0)
            self.checksum = fields.get('checksum', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.type = type
            self.code = code
            self.checksum = checksum
            self._raw = _raw


class TLSInfo(_SlottedInfoBase):
    """TLS/SSL protocol information."""
    __slots__ = ('version', 'content_type', 'handshake_type', 'sni', 'cipher_suites',
                 'cipher_suite', 'alpn', 'signature_algorithms', 'supported_groups',
                 'certificate', 'certificates', 'exts', 'extensions',
                 'record_length', '_raw', '_handshake_types')
    _SLOT_NAMES = ('version', 'content_type', 'handshake_type', 'sni', 'cipher_suites',
                   'cipher_suite', 'alpn', 'signature_algorithms', 'supported_groups',
                   'certificate', 'certificates', 'exts', 'extensions',
                   'record_length', '_raw', '_handshake_types')

    def __init__(self, version=None, content_type=None, handshake_type=None,
                 sni=None, cipher_suites=None, cipher_suite=None,
                 alpn=None, signature_algorithms=None, supported_groups=None,
                 certificate=None, certificates=None, exts=None,
                 extensions=None, record_length=0, _raw=b"",
                 _handshake_types=None,
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            self.version = fields.get('version')
            self.content_type = fields.get('content_type')
            self.handshake_type = fields.get('handshake_type')
            self.sni = fields.get('sni') or []
            self.cipher_suites = fields.get('cipher_suites') or []
            self.cipher_suite = fields.get('cipher_suite')
            self.alpn = fields.get('alpn') or []
            self.signature_algorithms = fields.get('signature_algorithms') or []
            self.supported_groups = fields.get('supported_groups') or []
            self.certificate = fields.get('certificate')
            self.certificates = fields.get('certificates') or []
            self.exts = fields.get('exts') or {}
            self.extensions = fields.get('extensions') or []
            self.record_length = fields.get('record_length', 0)
            self._raw = fields.get('_raw', b"")
            self._handshake_types = fields.get('_handshake_types') or []
        else:
            self.version = version
            self.content_type = content_type
            self.handshake_type = handshake_type
            self.sni = sni if sni is not None else []
            self.cipher_suites = cipher_suites if cipher_suites is not None else []
            self.cipher_suite = cipher_suite
            self.alpn = alpn if alpn is not None else []
            self.signature_algorithms = signature_algorithms if signature_algorithms is not None else []
            self.supported_groups = supported_groups if supported_groups is not None else []
            self.certificate = certificate
            self.certificates = certificates if certificates is not None else []
            self.exts = exts if exts is not None else {}
            self.extensions = extensions if extensions is not None else []
            self.record_length = record_length
            self._raw = _raw
            self._handshake_types = _handshake_types if _handshake_types is not None else []

    def get_extension(self, ext_type: int) -> list[bytes] | None:
        return self.exts.get(ext_type)

    def get_extension_first(self, ext_type: int) -> bytes | None:
        ext_list = self.exts.get(ext_type)
        return ext_list[0] if ext_list else None

    @property
    def content_type_name(self) -> str | None:
        names = {20: "change_cipher_spec", 21: "alert", 22: "handshake",
                 23: "application_data", 24: "heartbeat"}
        return names.get(self.content_type)

    @property
    def handshake_type_name(self) -> str | None:
        names = {0: "hello_request", 1: "client_hello", 2: "server_hello",
                 11: "certificate", 12: "server_key_exchange",
                 13: "certificate_request", 14: "server_hello_done",
                 15: "certificate_verify", 16: "client_key_exchange", 20: "finished"}
        return names.get(self.handshake_type)

    @property
    def version_name(self) -> str | None:
        if self.version == "3.1": return "TLS 1.0"
        elif self.version == "3.2": return "TLS 1.1"
        elif self.version == "3.3": return "TLS 1.2"
        elif self.version == "3.4": return "TLS 1.3"
        return self.version

    def merge(self, other: 'TLSInfo') -> None:
        """Merge another TLSInfo into this one (for flow aggregation)."""
        if other.version and not self.version:
            self.version = other.version
        for s in (other.sni or []):
            if s and s not in self.sni:
                self.sni.append(s)
        for a in (other.alpn or []):
            if a and a not in self.alpn:
                self.alpn.append(a)
        if other.cipher_suites and not self.cipher_suites:
            self.cipher_suites = list(other.cipher_suites)
        if other.cipher_suite and not self.cipher_suite:
            self.cipher_suite = other.cipher_suite
        if other.signature_algorithms and not self.signature_algorithms:
            self.signature_algorithms = list(other.signature_algorithms)
        if other.supported_groups and not self.supported_groups:
            self.supported_groups = list(other.supported_groups)
        if other.certificate and not self.certificate:
            self.certificate = other.certificate
        if other.certificates and not self.certificates:
            self.certificates = list(other.certificates)
        # Merge extensions
        for ext_type, ext_data_list in (other.exts or {}).items():
            if ext_type not in self.exts:
                self.exts[ext_type] = list(ext_data_list)
            else:
                for d in ext_data_list:
                    if d not in self.exts[ext_type]:
                        self.exts[ext_type].append(d)


class HTTPInfo(_SlottedInfoBase):
    """HTTP protocol information."""
    __slots__ = ('method', 'host', 'path', 'user_agent', 'status_code',
                 'status_reason', 'headers', 'content_type', 'content_length',
                 'version', '_raw')
    _SLOT_NAMES = ('method', 'host', 'path', 'user_agent', 'status_code',
                   'status_reason', 'headers', 'content_type', 'content_length',
                   'version', '_raw')

    def __init__(self, method=None, host=None, path=None, user_agent=None,
                 status_code=None, status_reason=None, headers=None,
                 content_type=None, content_length=None, version=None,
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.method = fields.get('method')
            self.host = fields.get('host')
            self.path = fields.get('path')
            self.user_agent = fields.get('user_agent')
            self.status_code = fields.get('status_code')
            self.status_reason = fields.get('status_reason')
            self.headers = fields.get('headers') or {}
            self.content_type = fields.get('content_type')
            self.content_length = fields.get('content_length')
            self.version = fields.get('version')
            self._raw = fields.get('_raw', b"")
        else:
            self.method = method
            self.host = host
            self.path = path
            self.user_agent = user_agent
            self.status_code = status_code
            self.status_reason = status_reason
            self.headers = headers if headers is not None else {}
            self.content_type = content_type
            self.content_length = content_length
            self.version = version
            self._raw = _raw

    @property
    def is_request(self) -> bool: return self.method is not None
    @property
    def is_response(self) -> bool: return self.status_code is not None

    def merge(self, other: 'HTTPInfo') -> None:
        """Merge another HTTPInfo (first-wins for scalars, merge dicts)."""
        for k in self._SLOT_NAMES:
            cur = getattr(self, k)
            v = getattr(other, k, None)
            if cur is None and v is not None:
                setattr(self, k, v)
            elif isinstance(cur, dict) and isinstance(v, dict):
                for hk, hv in v.items():
                    if hk not in cur:
                        cur[hk] = hv


class DNSInfo(_SlottedInfoBase):
    """DNS protocol information."""
    __slots__ = ('queries', 'answers', 'response_code', 'question_count',
                 'answer_count', 'authority_count', 'additional_count', 'flags', '_raw')
    _SLOT_NAMES = ('queries', 'answers', 'response_code', 'question_count',
                   'answer_count', 'authority_count', 'additional_count', 'flags', '_raw')

    def __init__(self, queries=None, answers=None, response_code=0,
                 question_count=0, answer_count=0, authority_count=0,
                 additional_count=0, flags=0, _raw=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            self.queries = fields.get('queries') or []
            self.answers = fields.get('answers') or []
            self.response_code = fields.get('response_code', 0)
            self.question_count = fields.get('question_count', 0)
            self.answer_count = fields.get('answer_count', 0)
            self.authority_count = fields.get('authority_count', 0)
            self.additional_count = fields.get('additional_count', 0)
            self.flags = fields.get('flags', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.queries = queries if queries is not None else []
            self.answers = answers if answers is not None else []
            self.response_code = response_code
            self.question_count = question_count
            self.answer_count = answer_count
            self.authority_count = authority_count
            self.additional_count = additional_count
            self.flags = flags
            self._raw = _raw

    @property
    def is_query(self) -> bool: return not bool(self.flags & 0x8000)
    @property
    def is_response(self) -> bool: return bool(self.flags & 0x8000)

    def merge(self, other: 'DNSInfo') -> None:
        """Merge another DNSInfo (first-wins for scalars, extend lists)."""
        for k in self._SLOT_NAMES:
            cur = getattr(self, k)
            v = getattr(other, k, None)
            if cur is None and v is not None:
                setattr(self, k, v)
            elif isinstance(cur, list) and isinstance(v, list):
                for item in v:
                    if item not in cur:
                        cur.append(item)
            elif (cur is None or cur == 0) and v:
                setattr(self, k, v)


# Map from short property names to layer registry names
_PROTO_KEY_TO_LAYER = {
    'eth': 'ethernet', 'ip': 'ipv4', 'ip6': 'ipv6',
    'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp',
    'tls': 'tls_record', 'http': 'http', 'dns': 'dns',
    'arp': 'arp', 'icmp6': 'icmpv6',
}


class ParsedPacket:
    """Wrapper around a parsed packet with protocol layer accessors.

    Provides convenient access to protocol fields at each layer through
    typed Info objects. All layers are optional and populated as parsing
    progresses through the protocol stack.
    """
    __slots__ = (
        'timestamp', 'raw_data', 'link_layer_type', 'caplen', 'wirelen',
        'ip_len', 'trans_len', 'app_len',
        'layers',
        'is_client_to_server', 'packet_index', 'flow_index',
        '_raw_eth', '_raw_ip', '_raw_transport', '_raw_app',
        '_raw_tcp_payload', '_flow_key_cache',
    )

    def __init__(self, timestamp=0.0, raw_data=b"", link_layer_type=0,
                 caplen=0, wirelen=0, ip_len=0, trans_len=0, app_len=0,
                 eth=None, ip=None, ip6=None, tcp=None, udp=None,
                 icmp=None, tls=None, http=None, dns=None,
                 is_client_to_server=True, packet_index=-1, flow_index=-1,
                 _raw_eth=None, _raw_ip=None, _raw_transport=None, _raw_app=None,
                 _raw_tcp_payload=b"", _flow_key_cache=None, extra_layers=None,
                 arp=None, icmp6=None):
        self.timestamp = timestamp
        self.raw_data = raw_data
        self.link_layer_type = link_layer_type
        self.caplen = caplen
        self.wirelen = wirelen
        self.ip_len = ip_len
        self.trans_len = trans_len
        self.app_len = app_len
        self.is_client_to_server = is_client_to_server
        self.packet_index = packet_index
        self.flow_index = flow_index
        self._raw_eth = _raw_eth
        self._raw_ip = _raw_ip
        self._raw_transport = _raw_transport
        self._raw_app = _raw_app
        self._raw_tcp_payload = _raw_tcp_payload
        self._flow_key_cache = _flow_key_cache

        # Build layers dict from protocol args
        self.layers = {}
        for key, val in (('eth', eth), ('ip', ip), ('ip6', ip6),
                         ('tcp', tcp), ('udp', udp), ('icmp', icmp),
                         ('tls', tls), ('http', http), ('dns', dns),
                         ('arp', arp), ('icmp6', icmp6)):
            if val is not None:
                self.layers[_PROTO_KEY_TO_LAYER[key]] = val

        # Populate extra layers from C++ extra_layers (unknown protocols)
        if extra_layers:
            registry = ProtocolRegistry.get_instance()
            for name, fields_dict in extra_layers.items():
                if name not in self.layers:
                    cls = registry.get(name)
                    if cls is not None:
                        self.layers[name] = cls(fields=fields_dict)
                    else:
                        self.layers[name] = ProtocolInfo(fields=fields_dict)

    # Protocol properties — source of truth is self.layers
    @property
    def eth(self) -> EthernetInfo | None:
        return self.layers.get('ethernet')
    @eth.setter
    def eth(self, v):
        if v is not None: self.layers['ethernet'] = v
        else: self.layers.pop('ethernet', None)

    @property
    def ip(self) -> IPInfo | None:
        return self.layers.get('ipv4')
    @ip.setter
    def ip(self, v):
        if v is not None: self.layers['ipv4'] = v
        else: self.layers.pop('ipv4', None)

    @property
    def ip6(self) -> IP6Info | None:
        return self.layers.get('ipv6')
    @ip6.setter
    def ip6(self, v):
        if v is not None: self.layers['ipv6'] = v
        else: self.layers.pop('ipv6', None)

    @property
    def tcp(self) -> TCPInfo | None:
        return self.layers.get('tcp')
    @tcp.setter
    def tcp(self, v):
        if v is not None: self.layers['tcp'] = v
        else: self.layers.pop('tcp', None)

    @property
    def udp(self) -> UDPInfo | None:
        return self.layers.get('udp')
    @udp.setter
    def udp(self, v):
        if v is not None: self.layers['udp'] = v
        else: self.layers.pop('udp', None)

    @property
    def icmp(self) -> ICMPInfo | None:
        return self.layers.get('icmp')
    @icmp.setter
    def icmp(self, v):
        if v is not None: self.layers['icmp'] = v
        else: self.layers.pop('icmp', None)

    @property
    def tls(self) -> TLSInfo | None:
        return self.layers.get('tls_record')
    @tls.setter
    def tls(self, v):
        if v is not None: self.layers['tls_record'] = v
        else: self.layers.pop('tls_record', None)

    @property
    def http(self) -> HTTPInfo | None:
        return self.layers.get('http')
    @http.setter
    def http(self, v):
        if v is not None: self.layers['http'] = v
        else: self.layers.pop('http', None)

    @property
    def dns(self) -> DNSInfo | None:
        return self.layers.get('dns')
    @dns.setter
    def dns(self, v):
        if v is not None: self.layers['dns'] = v
        else: self.layers.pop('dns', None)

    @property
    def arp(self) -> ARPInfo | None:
        return self.layers.get('arp')
    @arp.setter
    def arp(self, v):
        if v is not None: self.layers['arp'] = v
        else: self.layers.pop('arp', None)

    @property
    def icmp6(self) -> ICMP6Info | None:
        return self.layers.get('icmpv6')
    @icmp6.setter
    def icmp6(self, v):
        if v is not None: self.layers['icmpv6'] = v
        else: self.layers.pop('icmpv6', None)

    def get_layer(self, name: str) -> ProtocolInfo | None:
        """Get a protocol layer by registry name."""
        return self.layers.get(name)

    @property
    def protocol_stack(self) -> list[str]:
        """Ordered list of protocol names present in this packet."""
        return list(self.layers.keys())

    @property
    def payload(self) -> bytes:
        if self._raw_app:
            return getattr(self._raw_app, 'data', b'')
        return self._raw_tcp_payload

    @property
    def has_payload(self) -> bool:
        return len(self.payload) > 0

    def to_dict(self) -> dict:
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


# Register built-in protocols
_registry = ProtocolRegistry.get_instance()
_registry.register('ethernet', EthernetInfo)
_registry.register('ipv4', IPInfo)
_registry.register('ipv6', IP6Info)
_registry.register('tcp', TCPInfo)
_registry.register('udp', UDPInfo)
_registry.register('icmp', ICMPInfo)
_registry.register('tls_record', TLSInfo)
_registry.register('dns', DNSInfo)
_registry.register('http', HTTPInfo)
