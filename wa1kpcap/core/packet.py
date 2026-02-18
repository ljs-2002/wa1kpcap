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


class ProtocolInfo:
    """Base class for protocol info objects.

    Stores parsed fields in _fields dict. Subclasses add typed properties.
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


class EthernetInfo(ProtocolInfo):
    """Ethernet layer information."""
    __slots__ = ()

    def __init__(self, src="", dst="", type=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={'src': src, 'dst': dst, 'type': type, '_raw': _raw})

    @property
    def src(self) -> str: return self._fields.get('src', "")
    @src.setter
    def src(self, v): self._fields['src'] = v

    @property
    def dst(self) -> str: return self._fields.get('dst', "")
    @dst.setter
    def dst(self, v): self._fields['dst'] = v

    @property
    def type(self) -> int: return self._fields.get('type', 0)
    @type.setter
    def type(self, v): self._fields['type'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

    @classmethod
    def from_dpkt(cls, eth: dpkt.ethernet.Ethernet) -> EthernetInfo:
        return cls(
            src="{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*eth.src),
            dst="{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*eth.dst),
            type=eth.type,
        )


class IPInfo(ProtocolInfo):
    """IPv4 layer information."""
    __slots__ = ()

    def __init__(self, version=0, src="", dst="", proto=0, ttl=0, len=0,
                 id=0, flags=0, offset=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'version': version, 'src': src, 'dst': dst, 'proto': proto,
                'ttl': ttl, 'len': len, 'id': id, 'flags': flags,
                'offset': offset, '_raw': _raw,
            })

    @property
    def version(self) -> int: return self._fields.get('version', 0)
    @version.setter
    def version(self, v): self._fields['version'] = v

    @property
    def src(self) -> str: return self._fields.get('src', "")
    @src.setter
    def src(self, v): self._fields['src'] = v

    @property
    def dst(self) -> str: return self._fields.get('dst', "")
    @dst.setter
    def dst(self, v): self._fields['dst'] = v

    @property
    def proto(self) -> int: return self._fields.get('proto', 0)
    @proto.setter
    def proto(self, v): self._fields['proto'] = v

    @property
    def ttl(self) -> int: return self._fields.get('ttl', 0)
    @ttl.setter
    def ttl(self, v): self._fields['ttl'] = v

    @property
    def len(self) -> int: return self._fields.get('len', 0)
    @len.setter
    def len(self, v): self._fields['len'] = v

    @property
    def id(self) -> int: return self._fields.get('id', 0)
    @id.setter
    def id(self, v): self._fields['id'] = v

    @property
    def flags(self) -> int: return self._fields.get('flags', 0)
    @flags.setter
    def flags(self, v): self._fields['flags'] = v

    @property
    def offset(self) -> int: return self._fields.get('offset', 0)
    @offset.setter
    def offset(self, v): self._fields['offset'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

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


class IP6Info(ProtocolInfo):
    """IPv6 layer information."""
    __slots__ = ()

    def __init__(self, version=0, src="", dst="", next_header=0, hop_limit=0,
                 flow_label=0, len=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'version': version, 'src': src, 'dst': dst,
                'next_header': next_header, 'hop_limit': hop_limit,
                'flow_label': flow_label, 'len': len, '_raw': _raw,
            })

    @property
    def version(self) -> int: return self._fields.get('version', 0)
    @version.setter
    def version(self, v): self._fields['version'] = v

    @property
    def src(self) -> str: return self._fields.get('src', "")
    @src.setter
    def src(self, v): self._fields['src'] = v

    @property
    def dst(self) -> str: return self._fields.get('dst', "")
    @dst.setter
    def dst(self, v): self._fields['dst'] = v

    @property
    def next_header(self) -> int: return self._fields.get('next_header', 0)
    @next_header.setter
    def next_header(self, v): self._fields['next_header'] = v

    @property
    def hop_limit(self) -> int: return self._fields.get('hop_limit', 0)
    @hop_limit.setter
    def hop_limit(self, v): self._fields['hop_limit'] = v

    @property
    def flow_label(self) -> int: return self._fields.get('flow_label', 0)
    @flow_label.setter
    def flow_label(self, v): self._fields['flow_label'] = v

    @property
    def len(self) -> int: return self._fields.get('len', 0)
    @len.setter
    def len(self, v): self._fields['len'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

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


class TCPInfo(ProtocolInfo):
    """TCP segment information."""
    __slots__ = ()

    def __init__(self, sport=0, dport=0, seq=0, ack_num=0, flags=0,
                 win=0, urgent=0, options=b"", _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'sport': sport, 'dport': dport, 'seq': seq,
                'ack_num': ack_num, 'flags': flags, 'win': win,
                'urgent': urgent, 'options': options, '_raw': _raw,
            })

    @property
    def sport(self) -> int: return self._fields.get('sport', 0)
    @sport.setter
    def sport(self, v): self._fields['sport'] = v

    @property
    def dport(self) -> int: return self._fields.get('dport', 0)
    @dport.setter
    def dport(self, v): self._fields['dport'] = v

    @property
    def seq(self) -> int: return self._fields.get('seq', 0)
    @seq.setter
    def seq(self, v): self._fields['seq'] = v

    @property
    def ack_num(self) -> int: return self._fields.get('ack_num', 0)
    @ack_num.setter
    def ack_num(self, v): self._fields['ack_num'] = v

    @property
    def flags(self) -> int: return self._fields.get('flags', 0)
    @flags.setter
    def flags(self, v): self._fields['flags'] = v

    @property
    def win(self) -> int: return self._fields.get('win', 0)
    @win.setter
    def win(self, v): self._fields['win'] = v

    @property
    def urgent(self) -> int: return self._fields.get('urgent', 0)
    @urgent.setter
    def urgent(self, v): self._fields['urgent'] = v

    @property
    def options(self) -> bytes: return self._fields.get('options', b"")
    @options.setter
    def options(self, v): self._fields['options'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

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


class UDPInfo(ProtocolInfo):
    """UDP datagram information."""
    __slots__ = ()

    def __init__(self, sport=0, dport=0, len=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={'sport': sport, 'dport': dport, 'len': len, '_raw': _raw})

    @property
    def sport(self) -> int: return self._fields.get('sport', 0)
    @sport.setter
    def sport(self, v): self._fields['sport'] = v

    @property
    def dport(self) -> int: return self._fields.get('dport', 0)
    @dport.setter
    def dport(self, v): self._fields['dport'] = v

    @property
    def len(self) -> int: return self._fields.get('len', 0)
    @len.setter
    def len(self, v): self._fields['len'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

    @classmethod
    def from_dpkt(cls, udp: dpkt.udp.UDP) -> UDPInfo:
        return cls(
            sport=udp.sport,
            dport=udp.dport,
            len=udp.ulen,
        )


class ICMPInfo(ProtocolInfo):
    """ICMP message information."""
    __slots__ = ()

    def __init__(self, type=0, code=0, _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={'type': type, 'code': code, '_raw': _raw})

    @property
    def type(self) -> int: return self._fields.get('type', 0)
    @type.setter
    def type(self, v): self._fields['type'] = v

    @property
    def code(self) -> int: return self._fields.get('code', 0)
    @code.setter
    def code(self, v): self._fields['code'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

    @classmethod
    def from_dpkt(cls, icmp: dpkt.icmp.ICMP) -> ICMPInfo:
        return cls(type=icmp.type, code=icmp.code)


class ARPInfo(ProtocolInfo):
    """ARP message information."""
    __slots__ = ()

    def __init__(self, hw_type=0, proto_type=0, opcode=0,
                 sender_mac="", sender_ip="", target_mac="", target_ip="",
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'hw_type': hw_type, 'proto_type': proto_type, 'opcode': opcode,
                'sender_mac': sender_mac, 'sender_ip': sender_ip,
                'target_mac': target_mac, 'target_ip': target_ip, '_raw': _raw,
            })

    @property
    def hw_type(self) -> int: return self._fields.get('hw_type', 0)
    @hw_type.setter
    def hw_type(self, v): self._fields['hw_type'] = v

    @property
    def proto_type(self) -> int: return self._fields.get('proto_type', 0)
    @proto_type.setter
    def proto_type(self, v): self._fields['proto_type'] = v

    @property
    def opcode(self) -> int: return self._fields.get('opcode', 0)
    @opcode.setter
    def opcode(self, v): self._fields['opcode'] = v

    @property
    def sender_mac(self) -> str: return self._fields.get('sender_mac', "")
    @sender_mac.setter
    def sender_mac(self, v): self._fields['sender_mac'] = v

    @property
    def sender_ip(self) -> str: return self._fields.get('sender_ip', "")
    @sender_ip.setter
    def sender_ip(self, v): self._fields['sender_ip'] = v

    @property
    def target_mac(self) -> str: return self._fields.get('target_mac', "")
    @target_mac.setter
    def target_mac(self, v): self._fields['target_mac'] = v

    @property
    def target_ip(self) -> str: return self._fields.get('target_ip', "")
    @target_ip.setter
    def target_ip(self, v): self._fields['target_ip'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v


class ICMP6Info(ProtocolInfo):
    """ICMPv6 message information."""
    __slots__ = ()

    def __init__(self, type=0, code=0, checksum=0, _raw=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'type': type, 'code': code, 'checksum': checksum, '_raw': _raw,
            })

    @property
    def type(self) -> int: return self._fields.get('type', 0)
    @type.setter
    def type(self, v): self._fields['type'] = v

    @property
    def code(self) -> int: return self._fields.get('code', 0)
    @code.setter
    def code(self, v): self._fields['code'] = v

    @property
    def checksum(self) -> int: return self._fields.get('checksum', 0)
    @checksum.setter
    def checksum(self, v): self._fields['checksum'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v


class TLSInfo(ProtocolInfo):
    """TLS/SSL protocol information."""
    __slots__ = ()

    def __init__(self, version=None, content_type=None, handshake_type=None,
                 sni=None, cipher_suites=None, cipher_suite=None,
                 alpn=None, signature_algorithms=None, supported_groups=None,
                 certificate=None, certificates=None, exts=None,
                 extensions=None, record_length=0, _raw=b"",
                 _handshake_types=None,
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'version': version, 'content_type': content_type,
                'handshake_type': handshake_type,
                'sni': sni if sni is not None else [],
                'cipher_suites': cipher_suites if cipher_suites is not None else [],
                'cipher_suite': cipher_suite,
                'alpn': alpn if alpn is not None else [],
                'signature_algorithms': signature_algorithms if signature_algorithms is not None else [],
                'supported_groups': supported_groups if supported_groups is not None else [],
                'certificate': certificate,
                'certificates': certificates if certificates is not None else [],
                'exts': exts if exts is not None else {},
                'extensions': extensions if extensions is not None else [],
                'record_length': record_length, '_raw': _raw,
                '_handshake_types': _handshake_types if _handshake_types is not None else [],
            })

    @property
    def version(self): return self._fields.get('version')
    @version.setter
    def version(self, v): self._fields['version'] = v

    @property
    def content_type(self): return self._fields.get('content_type')
    @content_type.setter
    def content_type(self, v): self._fields['content_type'] = v

    @property
    def handshake_type(self): return self._fields.get('handshake_type')
    @handshake_type.setter
    def handshake_type(self, v): self._fields['handshake_type'] = v

    @property
    def sni(self) -> list[str]: return self._fields.get('sni', [])
    @sni.setter
    def sni(self, v): self._fields['sni'] = v

    @property
    def cipher_suites(self) -> list[int]: return self._fields.get('cipher_suites', [])
    @cipher_suites.setter
    def cipher_suites(self, v): self._fields['cipher_suites'] = v

    @property
    def cipher_suite(self): return self._fields.get('cipher_suite')
    @cipher_suite.setter
    def cipher_suite(self, v): self._fields['cipher_suite'] = v

    @property
    def alpn(self) -> list[str]: return self._fields.get('alpn', [])
    @alpn.setter
    def alpn(self, v): self._fields['alpn'] = v

    @property
    def signature_algorithms(self) -> list[int]: return self._fields.get('signature_algorithms', [])
    @signature_algorithms.setter
    def signature_algorithms(self, v): self._fields['signature_algorithms'] = v

    @property
    def supported_groups(self) -> list[int]: return self._fields.get('supported_groups', [])
    @supported_groups.setter
    def supported_groups(self, v): self._fields['supported_groups'] = v

    @property
    def certificate(self): return self._fields.get('certificate')
    @certificate.setter
    def certificate(self, v): self._fields['certificate'] = v

    @property
    def certificates(self) -> list[bytes]: return self._fields.get('certificates', [])
    @certificates.setter
    def certificates(self, v): self._fields['certificates'] = v

    @property
    def exts(self) -> dict[int, list[bytes]]: return self._fields.get('exts', {})
    @exts.setter
    def exts(self, v): self._fields['exts'] = v

    @property
    def extensions(self) -> list[tuple[int, bytes]]: return self._fields.get('extensions', [])
    @extensions.setter
    def extensions(self, v): self._fields['extensions'] = v

    @property
    def record_length(self) -> int: return self._fields.get('record_length', 0)
    @record_length.setter
    def record_length(self, v): self._fields['record_length'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

    @property
    def _handshake_types(self) -> list[int]: return self._fields.get('_handshake_types', [])
    @_handshake_types.setter
    def _handshake_types(self, v): self._fields['_handshake_types'] = v

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


class HTTPInfo(ProtocolInfo):
    """HTTP protocol information."""
    __slots__ = ()

    def __init__(self, method=None, host=None, path=None, user_agent=None,
                 status_code=None, status_reason=None, headers=None,
                 content_type=None, content_length=None, version=None,
                 _raw=b"", fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'method': method, 'host': host, 'path': path,
                'user_agent': user_agent, 'status_code': status_code,
                'status_reason': status_reason,
                'headers': headers if headers is not None else {},
                'content_type': content_type, 'content_length': content_length,
                'version': version, '_raw': _raw,
            })

    @property
    def method(self): return self._fields.get('method')
    @method.setter
    def method(self, v): self._fields['method'] = v

    @property
    def host(self): return self._fields.get('host')
    @host.setter
    def host(self, v): self._fields['host'] = v

    @property
    def path(self): return self._fields.get('path')
    @path.setter
    def path(self, v): self._fields['path'] = v

    @property
    def user_agent(self): return self._fields.get('user_agent')
    @user_agent.setter
    def user_agent(self, v): self._fields['user_agent'] = v

    @property
    def status_code(self): return self._fields.get('status_code')
    @status_code.setter
    def status_code(self, v): self._fields['status_code'] = v

    @property
    def status_reason(self): return self._fields.get('status_reason')
    @status_reason.setter
    def status_reason(self, v): self._fields['status_reason'] = v

    @property
    def headers(self) -> dict[str, str]: return self._fields.get('headers', {})
    @headers.setter
    def headers(self, v): self._fields['headers'] = v

    @property
    def content_type(self): return self._fields.get('content_type')
    @content_type.setter
    def content_type(self, v): self._fields['content_type'] = v

    @property
    def content_length(self): return self._fields.get('content_length')
    @content_length.setter
    def content_length(self, v): self._fields['content_length'] = v

    @property
    def version(self): return self._fields.get('version')
    @version.setter
    def version(self, v): self._fields['version'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

    @property
    def is_request(self) -> bool: return self.method is not None
    @property
    def is_response(self) -> bool: return self.status_code is not None

    def merge(self, other: 'HTTPInfo') -> None:
        """Merge another HTTPInfo (first-wins for scalars, merge dicts)."""
        for k, v in other._fields.items():
            cur = self._fields.get(k)
            if cur is None and v is not None:
                self._fields[k] = v
            elif isinstance(cur, dict) and isinstance(v, dict):
                for hk, hv in v.items():
                    if hk not in cur:
                        cur[hk] = hv


class DNSInfo(ProtocolInfo):
    """DNS protocol information."""
    __slots__ = ()

    def __init__(self, queries=None, answers=None, response_code=0,
                 question_count=0, answer_count=0, authority_count=0,
                 additional_count=0, flags=0, _raw=b"",
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'queries': queries if queries is not None else [],
                'answers': answers if answers is not None else [],
                'response_code': response_code, 'question_count': question_count,
                'answer_count': answer_count, 'authority_count': authority_count,
                'additional_count': additional_count, 'flags': flags, '_raw': _raw,
            })

    @property
    def queries(self) -> list[str]: return self._fields.get('queries', [])
    @queries.setter
    def queries(self, v): self._fields['queries'] = v

    @property
    def answers(self) -> list[str]: return self._fields.get('answers', [])
    @answers.setter
    def answers(self, v): self._fields['answers'] = v

    @property
    def response_code(self) -> int: return self._fields.get('response_code', 0)
    @response_code.setter
    def response_code(self, v): self._fields['response_code'] = v

    @property
    def question_count(self) -> int: return self._fields.get('question_count', 0)
    @question_count.setter
    def question_count(self, v): self._fields['question_count'] = v

    @property
    def answer_count(self) -> int: return self._fields.get('answer_count', 0)
    @answer_count.setter
    def answer_count(self, v): self._fields['answer_count'] = v

    @property
    def authority_count(self) -> int: return self._fields.get('authority_count', 0)
    @authority_count.setter
    def authority_count(self, v): self._fields['authority_count'] = v

    @property
    def additional_count(self) -> int: return self._fields.get('additional_count', 0)
    @additional_count.setter
    def additional_count(self, v): self._fields['additional_count'] = v

    @property
    def flags(self) -> int: return self._fields.get('flags', 0)
    @flags.setter
    def flags(self, v): self._fields['flags'] = v

    @property
    def _raw(self) -> bytes: return self._fields.get('_raw', b"")
    @_raw.setter
    def _raw(self, v): self._fields['_raw'] = v

    @property
    def is_query(self) -> bool: return not bool(self.flags & 0x8000)
    @property
    def is_response(self) -> bool: return bool(self.flags & 0x8000)

    def merge(self, other: 'DNSInfo') -> None:
        """Merge another DNSInfo (first-wins for scalars, extend lists)."""
        for k, v in other._fields.items():
            cur = self._fields.get(k)
            if cur is None and v is not None:
                self._fields[k] = v
            elif isinstance(cur, list) and isinstance(v, list):
                for item in v:
                    if item not in cur:
                        cur.append(item)
            elif (cur is None or cur == 0) and v:
                self._fields[k] = v


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
