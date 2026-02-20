"""
Application layer protocol handlers (TLS, HTTP, DNS).

TLS parsing follows the reference implementation pattern:
- Use dpkt.ssl.tls_multi_factory(data) which returns (msgs, i)
- Buffer unprocessed data (data[i:]) for next packet
- For Certificate: handshake.data.certificates is a list of DER bytes
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from wa1kpcap.protocols.base import BaseProtocolHandler, ProtocolContext, ParseResult, Layer
from wa1kpcap.protocols.registry import register_protocol

if TYPE_CHECKING:
    from wa1kpcap.core.packet import ParsedPacket

try:
    import dpkt.ssl
    import dpkt.dns
    _HAS_DPKT = True
except ImportError:
    _HAS_DPKT = False


# TLS constants from reference implementation
ssl_version = {
    0x0300: "SSL3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

HANDSHAKE_TYPE = 22
CLIENT_HELLO_TYPE = 1
SERVER_HELLO_TYPE = 2
CERTIFICATE_TYPE = 11

# Extension type constants for convenience
EXT_SNI = 0x00
EXT_ALPN = 0x10
EXT_SIGNATURE_ALGORITHMS = 0x0D
EXT_SUPPORTED_GROUPS = 0x0A


def parse_ext_data_with_data_len(buf: bytes, ext_lenbytes: int = 2, data_lenbytes: int = 1) -> list:
    """
    Parse extension data in format: total_len, [(data_len, data), ...]

    Reference: D:\MyProgram\wa1kpcap\Wa1kPcap\protocols\tls.py
    """
    if len(buf) < ext_lenbytes:
        return []

    try:
        extensions_length = struct.unpack("!H", buf[:ext_lenbytes])[0]
        extensions = []

        pointer = ext_lenbytes
        while pointer < extensions_length:
            try:
                ext_data, parsed = dpkt.ssl.parse_variable_array(buf[pointer:], data_lenbytes) if _HAS_DPKT else (b'', 0)
                extensions.append(ext_data)
                pointer += parsed
            except Exception:
                break

        return extensions
    except Exception:
        return []


def parse_ext_data_no_data_len(buf: bytes, ext_lenbytes: int = 2, data_len: int = 2) -> list:
    """
    Parse extension data in format: total_len, [data, ...]

    Reference: D:\MyProgram\wa1kpcap\Wa1kPcap\protocols\tls.py
    """
    if len(buf) < ext_lenbytes:
        return []

    try:
        extensions_length = struct.unpack("!H", buf[:ext_lenbytes])[0]
        num = extensions_length // data_len
        return list(struct.unpack(f"!{num}H", buf[ext_lenbytes:ext_lenbytes + num * data_len]))
    except Exception:
        return []


def parse_cert_der(cert_der: bytes) -> dict | None:
    """
    Parse DER-encoded X.509 certificate using cryptography.

    Reference: D:\MyProgram\wa1kpcap\Wa1kPcap\protocols\tls.py
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID

        def _name_to_dict(name_obj):
            out = {}
            for rdn in name_obj.rdns:
                for attr in rdn:
                    oid = attr.oid
                    key_map = {
                        NameOID.COMMON_NAME: "CN",
                        NameOID.COUNTRY_NAME: "C",
                        NameOID.ORGANIZATION_NAME: "O",
                        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
                        NameOID.LOCALITY_NAME: "L",
                        NameOID.STATE_OR_PROVINCE_NAME: "ST",
                        NameOID.EMAIL_ADDRESS: "emailAddress",
                        NameOID.SERIAL_NUMBER: "serialNumber",
                    }
                    key = key_map.get(oid, oid.dotted_string if hasattr(oid, 'dotted_string') else str(oid))
                    out.setdefault(key, []).append(attr.value)
            return {k: v[0] if len(v) == 1 else v for k, v in out.items()}

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        issuer = _name_to_dict(cert.issuer)
        subject = _name_to_dict(cert.subject)

        try:
            fp = cert.fingerprint(hashes.SHA256()).hex()
        except Exception:
            import hashlib
            fp = hashlib.sha256(cert_der).hexdigest()

        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": hex(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "sha256": fp,
        }
    except ImportError:
        return None
    except Exception:
        return None


@dataclass(slots=True)
class TLSFlowState:
    """
    Per-flow TLS parsing state.

    Reference: D:\MyProgram\wa1kpcap\Wa1kPcap\protocols\tls.py TLS class
    """
    __version: bytes = b""
    c_ciphersuites: list = field(default_factory=list)
    s_ciphersuite: object = None
    certs: list = field(default_factory=list)  # List of DER bytes
    exts: dict = field(default_factory=dict)  # {ext_type: [binary_data]}

    def set_version(self, version: bytes):
        self.__version = version

    @property
    def version(self) -> str:
        """Get TLS version as string."""
        if isinstance(self.__version, int):
            return ssl_version.get(self.__version, str(self.__version))
        elif isinstance(self.__version, bytes) and len(self.__version) >= 2:
            return ssl_version.get(int.from_bytes(self.__version, 'big'), str(self.__version))
        else:
            return ssl_version.get(0x0301, "1.0")

    @property
    def sni(self) -> list[str]:
        """Extract SNI from extensions. Always returns a list."""
        if EXT_SNI not in self.exts:
            return []
        return [x[5:].decode("utf-8") for x in self.exts[EXT_SNI]]

    @property
    def alpn(self) -> list[str]:
        """Extract ALPN from extensions. Always returns a list."""
        if EXT_ALPN not in self.exts:
            return []
        return [
            x.decode("utf-8")
            for alpn_data in self.exts[EXT_ALPN]
            for x in parse_ext_data_with_data_len(alpn_data)
        ]

    @property
    def signature_algorithms(self) -> list[int]:
        """Extract signature algorithms from extensions. Always returns a list."""
        if EXT_SIGNATURE_ALGORITHMS not in self.exts:
            return []
        return [
            alg
            for algs_data in self.exts[EXT_SIGNATURE_ALGORITHMS]
            for alg in parse_ext_data_no_data_len(algs_data)
        ]

    @property
    def supported_groups(self) -> list[int]:
        """Extract supported groups from extensions. Always returns a list."""
        if EXT_SUPPORTED_GROUPS not in self.exts:
            return []
        return [
            group
            for groups_data in self.exts[EXT_SUPPORTED_GROUPS]
            for group in parse_ext_data_no_data_len(groups_data)
        ]

    def json(self) -> dict:
        """Convert to JSON-like dict."""
        res = {
            "version": self.version,
            "c_ciphersuites": [x.name for x in self.c_ciphersuites],
            "s_ciphersuite": self.s_ciphersuite.name if self.s_ciphersuite else None,
        }
        if self.certs:
            res["certs"] = [parse_cert_der(cert) for cert in self.certs]
        if self.sni:
            res["sni"] = self.sni
        if self.alpn:
            res["alpn"] = self.alpn
        if self.signature_algorithms:
            res["signature_algorithms"] = self.signature_algorithms
        if self.supported_groups:
            res["supported_groups"] = self.supported_groups
        return res


def parse_handshake(data: bytes, prev_tls: TLSFlowState) -> int:
    """
    Parse a TLS handshake message and update TLSFlowState.

    Returns the number of bytes consumed.

    Reference: D:\MyProgram\wa1kpcap\Wa1kPcap\protocols\tls.py parse_handshake
    """
    if not _HAS_DPKT:
        return len(data)
    handshake = dpkt.ssl.TLSHandshake(data)

    if handshake.type == CLIENT_HELLO_TYPE:
        clienthello: dpkt.ssl.TLSClientHello = handshake.data
        prev_tls.c_ciphersuites = clienthello.ciphersuites
        prev_tls.set_version(clienthello.version)
        for ext_type, binary_data in clienthello.extensions:
            if ext_type not in prev_tls.exts:
                prev_tls.exts[ext_type] = []
            prev_tls.exts[ext_type].append(binary_data)

    elif handshake.type == SERVER_HELLO_TYPE:
        serverhello: dpkt.ssl.TLSServerHello = handshake.data
        prev_tls.s_ciphersuite = serverhello.ciphersuite
        for ext_type, binary_data in serverhello.extensions:
            if ext_type not in prev_tls.exts:
                prev_tls.exts[ext_type] = []
            prev_tls.exts[ext_type].append(binary_data)

    elif handshake.type == CERTIFICATE_TYPE:
        certificate: dpkt.ssl.TLSCertificate = handshake.data
        # certificate.certificates is a list of DER bytes
        prev_tls.certs = certificate.certificates

    return handshake.length + 4


def parse_tls(data: bytes, prev_tls: TLSFlowState | None) -> tuple[TLSFlowState, int]:
    """
    Parse TLS records using tls_multi_factory.

    Returns (TLSFlowState, bytes_parsed).

    Reference: D:\MyProgram\wa1kpcap\Wa1kPcap\protocols\tls.py parse_tls
    """
    if not prev_tls:
        prev_tls = TLSFlowState()

    if not _HAS_DPKT:
        return prev_tls, 0

    try:
        msgs, i = dpkt.ssl.tls_multi_factory(data)
    except dpkt.ssl.SSL3Exception:
        return prev_tls, 0

    for msg in msgs:
        if msg.type != HANDSHAKE_TYPE:
            continue
        msg_data = msg.data
        pointer, total_length = 0, len(msg_data)
        while pointer < total_length:
            try:
                length = parse_handshake(msg_data[pointer:], prev_tls)
            except Exception:
                break
            pointer += length

    return prev_tls, i


# Extension name mapping for reporting
EXTENSION_NAMES = {
    0: "server_name",
    1: "max_fragment_length",
    2: "client_certificate_url",
    3: "trusted_ca_keys",
    4: "truncated_hmac",
    5: "status_request",
    6: "user_mapping",
    7: "client_authz",
    8: "server_authz",
    9: "cert_type_oi",
    10: "supported_groups",
    11: "ec_point_formats",
    12: "srp",
    13: "signature_algorithms",
    14: "use_srtp",
    15: "heartbeat",
    16: "application_layer_protocol_negotiation",
    17: "status_request_v2",
    18: "signed_certificate_timestamp",
    19: "client_certificate_type",
    20: "server_certificate_type",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    24: "token_binding",
    25: "cached_info",
    26: "tls_lts",
    27: "compress_certificate",
    28: "session_ticket",
    29: "pre_shared_key",
    30: "early_data",
    31: "supported_versions",
    32: "cookie",
    33: "psk_key_exchange_modes",
    34: "certificate_authorities",
    35: "oid_filters",
    36: "post_handshake_auth",
    37: "signature_algorithms_cert",
    38: "key_share",
    39: "certificate_groups",
    40: "certificate_with_extern",
    41: "ticket_request",
    42: "dnssec_chain",
    43: "record_size_limit",
    44: "extended_random",
    45: "session_ticket_compat",
    46: "delegated_credentials",
    47: "message_size",
    48: "ticket_extension",
    49: "pre_shared_key_mode",
    50: "application_settings",
    51: "server_name",
    52: "renegotiation_info",
    13172: "next_protocol_negotiation",
    65281: "renegotiation_info",
}


def get_extension_name(ext_type: int) -> str:
    """Get the name of an extension type."""
    return EXTENSION_NAMES.get(ext_type, f"unknown_{ext_type}")


@register_protocol('tls', Layer.PRESENTATION, encapsulates='tcp',
                   default_ports=[443, 465, 993, 995, 5061], priority=100)
class TLSHandler(BaseProtocolHandler):
    """
    TLS/SSL protocol handler using dpkt.ssl with tls_multi_factory approach.

    This handler is kept for compatibility but the main TLS parsing
    is done in analyzer.py using the parse_tls function.
    """

    name = "tls"
    layer = Layer.PRESENTATION
    encapsulates = 'tcp'
    default_ports = [443, 465, 993, 995, 5061]
    priority = 100

    CONTENT_TYPE_HANDSHAKE = 22

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse TLS record - simplified for compatibility."""
        if not _HAS_DPKT or len(payload) < 5:
            return ParseResult(success=False)

        try:
            tls_record = dpkt.ssl.TLSRecord(payload)
            from wa1kpcap.core.packet import TLSInfo

            tls_info = TLSInfo(
                version=f"{(tls_record.version >> 8) & 0xFF}.{tls_record.version & 0xFF}",
                content_type=tls_record.type,
                record_length=tls_record.length
            )

            return ParseResult(
                success=True,
                info=tls_info
            )
        except Exception:
            return ParseResult(success=False)


@register_protocol('http', Layer.APPLICATION, encapsulates='tcp',
                   default_ports=[80, 8080, 8000, 443], priority=90)
class HTTPHandler(BaseProtocolHandler):
    """HTTP protocol handler."""

    name = "http"
    layer = Layer.APPLICATION
    encapsulates = "tcp"
    default_ports = [80, 8080, 8000, 443]
    priority = 90

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse HTTP request or response."""
        if len(payload) < 4:
            return ParseResult(success=False)

        try:
            text = payload.decode('ascii', errors='ignore')

            if is_client_to_server or text.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ',
                                                        'DELETE ', 'OPTIONS ', 'PATCH ',
                                                        'TRACE ', 'CONNECT ')):
                return self._parse_request(text, context)
            elif text.startswith('HTTP/'):
                return self._parse_response(text, context)
            else:
                return ParseResult(success=False)
        except Exception:
            return ParseResult(success=False)

    def _parse_request(self, data: str, context: ProtocolContext) -> ParseResult:
        """Parse HTTP request."""
        from wa1kpcap.core.packet import HTTPInfo

        lines = data.split('\r\n')
        if not lines:
            return ParseResult(success=False)

        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 2:
            return ParseResult(success=False)

        method = parts[0]
        uri = parts[1] if len(parts) > 1 else None

        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        http_info = HTTPInfo(
            method=method,
            uri=uri,
            headers=headers,
            status_code=None
        )

        return ParseResult(success=True, info=http_info)

    def _parse_response(self, data: str, context: ProtocolContext) -> ParseResult:
        """Parse HTTP response."""
        from wa1kpcap.core.packet import HTTPInfo

        lines = data.split('\r\n')
        if not lines:
            return ParseResult(success=False)

        status_line = lines[0]
        parts = status_line.split(' ')
        if len(parts) < 2:
            return ParseResult(success=False)

        try:
            status_code = int(parts[1])
        except ValueError:
            status_code = None

        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        http_info = HTTPInfo(
            method=None,
            uri=None,
            headers=headers,
            status_code=status_code
        )

        return ParseResult(success=True, info=http_info)


@register_protocol('dns', Layer.APPLICATION, encapsulates='udp',
                   default_ports=[53], priority=100)
class DNSHandler(BaseProtocolHandler):
    """DNS protocol handler."""

    name = "dns"
    layer = Layer.APPLICATION
    encapsulates = "udp"
    default_ports = [53]
    priority = 100

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """Parse DNS message."""
        if not _HAS_DPKT or len(payload) < 12:
            return ParseResult(success=False)

        try:
            dns = dpkt.dns.DNS(payload)
            queries = [q.name for q in dns.qd] if dns.qd else []

            from wa1kpcap.core.packet import DNSInfo
            dns_info = DNSInfo(
                queries=queries,
                response_code=dns.rcode if hasattr(dns, 'rcode') else None,
                question_count=len(dns.qd) if dns.qd else 0,
                answer_count=len(dns.an) if dns.an else 0,
                authority_count=len(dns.ns) if dns.ns else 0,
                additional_count=len(dns.ar) if dns.ar else 0
            )

            return ParseResult(success=True, info=dns_info)
        except Exception:
            return ParseResult(success=False)
