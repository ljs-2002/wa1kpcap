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
        self._yaml_paths: dict[str, str] = {}
        self._routing: dict[str, dict[str, dict[int, str]]] = {}

    @classmethod
    def get_instance(cls) -> 'ProtocolRegistry':
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, name: str, info_class: type[ProtocolInfo],
                 yaml_path: str | None = None,
                 routing: dict[str, dict[int, str]] | None = None):
        self._registry[name] = info_class
        if yaml_path is not None:
            self._yaml_paths[name] = yaml_path
        if routing is not None:
            self._routing[name] = routing

    def get(self, name: str) -> type[ProtocolInfo] | None:
        return self._registry.get(name)

    def get_yaml_paths(self) -> dict[str, str]:
        return dict(self._yaml_paths)

    def get_routing(self) -> dict[str, dict[str, dict[int, str]]]:
        return dict(self._routing)

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


class VLANInfo(_SlottedInfoBase):
    """802.1Q VLAN tag information."""
    __slots__ = ('vlan_id', 'priority', 'dei', 'ether_type', '_raw')
    _SLOT_NAMES = ('vlan_id', 'priority', 'dei', 'ether_type', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, 0, b'')

    def __init__(self, vlan_id=0, priority=0, dei=0, ether_type=0,
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.vlan_id = fields.get('vlan_id', 0)
            self.priority = fields.get('priority', 0)
            self.dei = fields.get('dei', 0)
            self.ether_type = fields.get('ether_type', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.vlan_id = vlan_id
            self.priority = priority
            self.dei = dei
            self.ether_type = ether_type
            self._raw = _raw


class SLLInfo(_SlottedInfoBase):
    """Linux cooked capture (SLL) information."""
    __slots__ = ('packet_type', 'arphrd_type', 'addr', 'protocol', '_raw')
    _SLOT_NAMES = ('packet_type', 'arphrd_type', 'addr', 'protocol', '_raw')
    _SLOT_DEFAULTS = (0, 0, '', 0, b'')

    def __init__(self, packet_type=0, arphrd_type=0, addr="", protocol=0,
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.packet_type = fields.get('packet_type', 0)
            self.arphrd_type = fields.get('arphrd_type', 0)
            self.addr = fields.get('addr', "")
            self.protocol = fields.get('protocol', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.packet_type = packet_type
            self.arphrd_type = arphrd_type
            self.addr = addr
            self.protocol = protocol
            self._raw = _raw


class SLL2Info(_SlottedInfoBase):
    """Linux cooked capture v2 (SLL2) information."""
    __slots__ = ('protocol_type', 'interface_index', 'arphrd_type', 'packet_type', 'addr', '_raw')
    _SLOT_NAMES = ('protocol_type', 'interface_index', 'arphrd_type', 'packet_type', 'addr', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, 0, '', b'')

    def __init__(self, protocol_type=0, interface_index=0, arphrd_type=0,
                 packet_type=0, addr="", _raw=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            self.protocol_type = fields.get('protocol_type', 0)
            self.interface_index = fields.get('interface_index', 0)
            self.arphrd_type = fields.get('arphrd_type', 0)
            self.packet_type = fields.get('packet_type', 0)
            self.addr = fields.get('addr', "")
            self._raw = fields.get('_raw', b"")
        else:
            self.protocol_type = protocol_type
            self.interface_index = interface_index
            self.arphrd_type = arphrd_type
            self.packet_type = packet_type
            self.addr = addr
            self._raw = _raw


class GREInfo(_SlottedInfoBase):
    """GRE (Generic Routing Encapsulation) information."""
    __slots__ = ('flags', 'protocol_type', 'checksum', 'key', 'sequence', '_raw')
    _SLOT_NAMES = ('flags', 'protocol_type', 'checksum', 'key', 'sequence', '_raw')
    _SLOT_DEFAULTS = (0, 0, None, None, None, b'')

    def __init__(self, flags=0, protocol_type=0, checksum=None, key=None,
                 sequence=None, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.flags = fields.get('flags', 0)
            self.protocol_type = fields.get('protocol_type', 0)
            self.checksum = fields.get('checksum')
            self.key = fields.get('key')
            self.sequence = fields.get('sequence')
            self._raw = fields.get('_raw', b"")
        else:
            self.flags = flags
            self.protocol_type = protocol_type
            self.checksum = checksum
            self.key = key
            self.sequence = sequence
            self._raw = _raw

    @property
    def has_checksum(self) -> bool:
        return self.checksum is not None

    @property
    def has_key(self) -> bool:
        return self.key is not None

    @property
    def has_sequence(self) -> bool:
        return self.sequence is not None


class VXLANInfo(_SlottedInfoBase):
    """VXLAN (Virtual Extensible LAN) information."""
    __slots__ = ('flags', 'vni', '_raw')
    _SLOT_NAMES = ('flags', 'vni', '_raw')
    _SLOT_DEFAULTS = (0, 0, b'')

    def __init__(self, flags=0, vni=0, _raw=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            self.flags = fields.get('flags', 0)
            self.vni = fields.get('vni', 0)
            self._raw = fields.get('_raw', b"")
        else:
            self.flags = flags
            self.vni = vni
            self._raw = _raw


class MPLSInfo(_SlottedInfoBase):
    """MPLS (Multi-Protocol Label Switching) information."""
    __slots__ = ('label', 'tc', 'ttl', 'stack_depth', 'bottom_of_stack', '_raw')
    _SLOT_NAMES = ('label', 'tc', 'ttl', 'stack_depth', 'bottom_of_stack', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, 0, False, b'')

    def __init__(self, label=0, tc=0, ttl=0, stack_depth=0,
                 bottom_of_stack=False, _raw=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            self.label = fields.get('label', 0)
            self.tc = fields.get('tc', 0)
            self.ttl = fields.get('ttl', 0)
            self.stack_depth = fields.get('stack_depth', 0)
            self.bottom_of_stack = fields.get('bottom_of_stack', False)
            self._raw = fields.get('_raw', b"")
        else:
            self.label = label
            self.tc = tc
            self.ttl = ttl
            self.stack_depth = stack_depth
            self.bottom_of_stack = bottom_of_stack
            self._raw = _raw


class DHCPInfo(_SlottedInfoBase):
    """DHCP (Dynamic Host Configuration Protocol) information."""
    __slots__ = ('op', 'htype', 'xid', 'ciaddr', 'yiaddr', 'siaddr',
                 'giaddr', 'chaddr', 'options_raw', '_raw')
    _SLOT_NAMES = ('op', 'htype', 'xid', 'ciaddr', 'yiaddr', 'siaddr',
                   'giaddr', 'chaddr', 'options_raw', '_raw')
    _SLOT_DEFAULTS = (0, 0, 0, '', '', '', '', '', b'', b'')

    def __init__(self, op=0, htype=0, xid=0, ciaddr='', yiaddr='',
                 siaddr='', giaddr='', chaddr='', options_raw=b'',
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.op = fields.get('op', 0)
            self.htype = fields.get('htype', 0)
            self.xid = fields.get('xid', 0)
            self.ciaddr = fields.get('ciaddr', '')
            self.yiaddr = fields.get('yiaddr', '')
            self.siaddr = fields.get('siaddr', '')
            self.giaddr = fields.get('giaddr', '')
            self.chaddr = fields.get('chaddr', '')
            self.options_raw = fields.get('options_raw', b'')
            self._raw = fields.get('_raw', b"")
        else:
            self.op = op
            self.htype = htype
            self.xid = xid
            self.ciaddr = ciaddr
            self.yiaddr = yiaddr
            self.siaddr = siaddr
            self.giaddr = giaddr
            self.chaddr = chaddr
            self.options_raw = options_raw
            self._raw = _raw


class DHCPv6Info(_SlottedInfoBase):
    """DHCPv6 (Dynamic Host Configuration Protocol for IPv6) information."""
    __slots__ = ('msg_type', 'transaction_id', 'options_raw', '_raw')
    _SLOT_NAMES = ('msg_type', 'transaction_id', 'options_raw', '_raw')
    _SLOT_DEFAULTS = (0, 0, b'', b'')

    def __init__(self, msg_type=0, transaction_id=0, options_raw=b'',
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.msg_type = fields.get('msg_type', 0)
            self.transaction_id = fields.get('transaction_id', 0)
            self.options_raw = fields.get('options_raw', b'')
            self._raw = fields.get('_raw', b"")
        else:
            self.msg_type = msg_type
            self.transaction_id = transaction_id
            self.options_raw = options_raw
            self._raw = _raw


class QUICInfo(_SlottedInfoBase):
    """QUIC (RFC 9000/9001) protocol information.

    Stores parsed fields from QUIC Long Header and Short Header packets.
    For Initial packets, may also contain decrypted Client Hello fields
    (SNI, ALPN, cipher_suites) if decryption succeeded.

    Attributes:
        is_long_header: True for Long Header packets, False for Short Header.
        packet_type: Packet type (0=Initial, 1=0-RTT, 2=Handshake, 3=Retry).
        version: QUIC version as integer (e.g. 0x00000001 for v1).
        dcid: Destination Connection ID (raw bytes).
        scid: Source Connection ID (raw bytes).
        dcid_len: Length of DCID in bytes.
        scid_len: Length of SCID in bytes.
        token: Token from Initial packets (raw bytes).
        token_len: Length of token in bytes.
        spin_bit: Spin bit value (Short Header only).
        sni: Server Name Indication (from decrypted Initial).
        alpn: Application-Layer Protocol Negotiation list (from decrypted Initial).
        cipher_suites: Cipher suites offered (from decrypted Initial).
        version_str: Human-readable version string (e.g. "QUICv1").
        packet_type_str: Human-readable packet type (e.g. "Initial", "1-RTT").
    """
    __slots__ = ('is_long_header', 'packet_type', 'version', 'dcid', 'scid',
                 'dcid_len', 'scid_len', 'token', 'token_len',
                 'spin_bit', 'sni', 'alpn', 'cipher_suites',
                 'version_str', 'packet_type_str', '_raw', 'crypto_fragments')
    _SLOT_NAMES = ('is_long_header', 'packet_type', 'version', 'dcid', 'scid',
                   'dcid_len', 'scid_len', 'token', 'token_len',
                   'spin_bit', 'sni', 'alpn', 'cipher_suites',
                   'version_str', 'packet_type_str', '_raw')
    _SLOT_DEFAULTS = (True, 0, 0, b'', b'', 0, 0, b'', 0,
                      False, None, None, None, '', '', b'')

    def __init__(self, is_long_header=True, packet_type=0, version=0,
                 dcid=b'', scid=b'', dcid_len=0, scid_len=0,
                 token=b'', token_len=0, spin_bit=False,
                 sni=None, alpn=None, cipher_suites=None,
                 version_str='', packet_type_str='',
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            self.is_long_header = fields.get('is_long_header', True)
            self.packet_type = fields.get('packet_type', 0)
            self.version = fields.get('version', 0)
            self.dcid = fields.get('dcid', b'')
            self.scid = fields.get('scid', b'')
            self.dcid_len = fields.get('dcid_len', 0)
            self.scid_len = fields.get('scid_len', 0)
            self.token = fields.get('token', b'')
            self.token_len = fields.get('token_len', 0)
            self.spin_bit = fields.get('spin_bit', False)
            self.sni = fields.get('sni')
            self.alpn = fields.get('alpn')
            self.cipher_suites = fields.get('cipher_suites')
            self.version_str = fields.get('version_str', '')
            self.packet_type_str = fields.get('packet_type_str', '')
            self._raw = fields.get('_raw', b"")
            self.crypto_fragments = []
        else:
            self.is_long_header = is_long_header
            self.packet_type = packet_type
            self.version = version
            self.dcid = dcid
            self.scid = scid
            self.dcid_len = dcid_len
            self.scid_len = scid_len
            self.token = token
            self.token_len = token_len
            self.spin_bit = spin_bit
            self.sni = sni
            self.alpn = alpn
            self.cipher_suites = cipher_suites
            self.version_str = version_str
            self.packet_type_str = packet_type_str
            self._raw = _raw
            self.crypto_fragments = []

    # Per-packet fields that should not be aggregated to flow level
    _MERGE_SKIP = frozenset(('is_long_header', 'packet_type', 'packet_type_str',
                             'token', 'token_len', 'spin_bit'))

    def merge(self, other) -> None:
        for k in self._SLOT_NAMES:
            if k in self._MERGE_SKIP:
                continue
            cur = getattr(self, k)
            if cur is None:
                v = getattr(other, k, None)
                if v is not None:
                    setattr(self, k, v)

    def copy(self):
        obj = super().copy()
        # Reset per-packet fields to None so they don't appear at flow level
        obj.is_long_header = None
        obj.packet_type = None
        obj.packet_type_str = None
        obj.token = None
        obj.token_len = None
        obj.spin_bit = None
        return obj


# Map from short property names to layer registry names
_PROTO_KEY_TO_LAYER = {
    'eth': 'ethernet', 'ip': 'ipv4', 'ip6': 'ipv6',
    'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp',
    'tls': 'tls_record', 'http': 'http', 'dns': 'dns',
    'arp': 'arp', 'icmp6': 'icmpv6',
    'vlan': 'vlan', 'sll': 'linux_sll', 'sll2': 'linux_sll2',
    'gre': 'gre', 'vxlan': 'vxlan', 'mpls': 'mpls', 'dhcp': 'dhcp', 'dhcpv6': 'dhcpv6',
    'quic': 'quic',
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
                 arp=None, icmp6=None,
                 vlan=None, sll=None, sll2=None, gre=None, vxlan=None, mpls=None,
                 dhcp=None, dhcpv6=None, quic=None):
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
                         ('arp', arp), ('icmp6', icmp6),
                         ('vlan', vlan), ('sll', sll), ('sll2', sll2),
                         ('gre', gre), ('vxlan', vxlan), ('mpls', mpls),
                         ('dhcp', dhcp), ('dhcpv6', dhcpv6), ('quic', quic)):
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

    @property
    def vlan(self) -> VLANInfo | None:
        return self.layers.get('vlan')
    @vlan.setter
    def vlan(self, v):
        if v is not None: self.layers['vlan'] = v
        else: self.layers.pop('vlan', None)

    @property
    def sll(self) -> SLLInfo | None:
        return self.layers.get('linux_sll')
    @sll.setter
    def sll(self, v):
        if v is not None: self.layers['linux_sll'] = v
        else: self.layers.pop('linux_sll', None)

    @property
    def sll2(self) -> SLL2Info | None:
        return self.layers.get('linux_sll2')
    @sll2.setter
    def sll2(self, v):
        if v is not None: self.layers['linux_sll2'] = v
        else: self.layers.pop('linux_sll2', None)

    @property
    def gre(self) -> GREInfo | None:
        return self.layers.get('gre')
    @gre.setter
    def gre(self, v):
        if v is not None: self.layers['gre'] = v
        else: self.layers.pop('gre', None)

    @property
    def vxlan(self) -> VXLANInfo | None:
        return self.layers.get('vxlan')
    @vxlan.setter
    def vxlan(self, v):
        if v is not None: self.layers['vxlan'] = v
        else: self.layers.pop('vxlan', None)

    @property
    def mpls(self) -> MPLSInfo | None:
        return self.layers.get('mpls')
    @mpls.setter
    def mpls(self, v):
        if v is not None: self.layers['mpls'] = v
        else: self.layers.pop('mpls', None)

    @property
    def dhcp(self) -> DHCPInfo | None:
        return self.layers.get('dhcp')
    @dhcp.setter
    def dhcp(self, v):
        if v is not None: self.layers['dhcp'] = v
        else: self.layers.pop('dhcp', None)

    @property
    def dhcpv6(self) -> DHCPv6Info | None:
        return self.layers.get('dhcpv6')
    @dhcpv6.setter
    def dhcpv6(self, v):
        if v is not None: self.layers['dhcpv6'] = v
        else: self.layers.pop('dhcpv6', None)

    @property
    def quic(self) -> QUICInfo | None:
        return self.layers.get('quic')
    @quic.setter
    def quic(self, v):
        if v is not None: self.layers['quic'] = v
        else: self.layers.pop('quic', None)

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
                from wa1kpcap.protocols.application import parse_cert_der
                parsed = parse_cert_der(self.tls.certificate)
                if parsed:
                    result['tls']['cert_subject'] = parsed.get('subject')
                    result['tls']['cert_issuer'] = parsed.get('issuer')
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
_registry.register('vlan', VLANInfo)
_registry.register('linux_sll', SLLInfo)
_registry.register('linux_sll2', SLL2Info)
_registry.register('gre', GREInfo)
_registry.register('vxlan', VXLANInfo)
_registry.register('mpls', MPLSInfo)
_registry.register('dhcp', DHCPInfo)
_registry.register('dhcpv6', DHCPv6Info)
