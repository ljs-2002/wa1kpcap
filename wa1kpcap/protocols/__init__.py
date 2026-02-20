"""Protocol handler modules."""

from wa1kpcap.protocols.base import (
    BaseProtocolHandler,
    ProtocolContext,
    ParseResult,
    Layer
)
from wa1kpcap.protocols.registry import (
    register_protocol,
    unregister_protocol,
    get_protocol_handlers,
    get_global_registry as get_protocol_registry,
    ProtocolHandlerRegistry
)

# dpkt-dependent handler modules are lazy-imported to allow wa1kpcap to work
# without dpkt installed. Access these names via attribute lookup.
_DPKT_HANDLER_NAMES = {
    'EthernetHandler': 'wa1kpcap.protocols.link',
    'LinuxSLLHandler': 'wa1kpcap.protocols.link',
    'RawIPHandler': 'wa1kpcap.protocols.link',
    'NullHandler': 'wa1kpcap.protocols.link',
    'NFLOGHandler': 'wa1kpcap.protocols.link',
    'IPv4Handler': 'wa1kpcap.protocols.network',
    'IPv6Handler': 'wa1kpcap.protocols.network',
    'ARPHandler': 'wa1kpcap.protocols.network',
    'ICMPHandler': 'wa1kpcap.protocols.network',
    'ICMPv6Handler': 'wa1kpcap.protocols.network',
    'TCPHandler': 'wa1kpcap.protocols.transport',
    'UDPHandler': 'wa1kpcap.protocols.transport',
    'SCTPHandler': 'wa1kpcap.protocols.transport',
    'TLSHandler': 'wa1kpcap.protocols.application',
    'HTTPHandler': 'wa1kpcap.protocols.application',
    'DNSHandler': 'wa1kpcap.protocols.application',
}


def __getattr__(name):
    if name in _DPKT_HANDLER_NAMES:
        import importlib
        mod = importlib.import_module(_DPKT_HANDLER_NAMES[name])
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    'BaseProtocolHandler',
    'ProtocolContext',
    'ParseResult',
    'Layer',
    'register_protocol',
    'unregister_protocol',
    'get_protocol_handlers',
    'get_protocol_registry',
    'ProtocolHandlerRegistry',
    'EthernetHandler',
    'LinuxSLLHandler',
    'RawIPHandler',
    'NullHandler',
    'NFLOGHandler',
    'IPv4Handler',
    'IPv6Handler',
    'ARPHandler',
    'ICMPHandler',
    'ICMPv6Handler',
    'TCPHandler',
    'UDPHandler',
    'SCTPHandler',
    'TLSHandler',
    'HTTPHandler',
    'DNSHandler',
]
