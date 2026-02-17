"""
Protocol handler base classes and types.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from wa1kpcap.core.packet import Layer, ParsedPacket


class Layer(IntEnum):
    """Protocol layer enumeration."""
    PHYSICAL = 1
    DATA_LINK = 2
    NETWORK = 3
    TRANSPORT = 4
    SESSION = 5
    PRESENTATION = 6
    APPLICATION = 7


@dataclass
class ProtocolContext:
    """Context passed to protocol handlers."""
    packet: ParsedPacket
    layer: Layer
    direction: int  # 1 for forward, -1 for reverse
    is_client_to_server: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def timestamp(self) -> float:
        return self.packet.timestamp

    @property
    def payload(self) -> bytes:
        return self.packet.payload


@dataclass
class ParseResult:
    """Result returned by protocol handler."""
    success: bool
    data: bytes = b""  # Remaining data after parsing
    info: object | None = None  # Parsed protocol info (e.g., TLSInfo)
    attributes: dict[str, Any] = field(default_factory=dict)
    next_protocol: str | None = None  # Suggested next protocol to try
    consumed: bool = False  # Whether payload was fully consumed


class BaseProtocolHandler(ABC):
    """
    Abstract base class for protocol handlers.

    Protocol handlers parse specific protocol layers and extract
    relevant information from packet payloads.
    """

    # Protocol name/identifier
    name: str = ""

    # Layer this handler operates on
    layer: Layer = Layer.APPLICATION

    # Protocol this handler encapsulates (e.g., 'tcp' for TLS)
    encapsulates: str | None = None

    # Default port(s) this protocol uses (for auto-detection)
    default_ports: list[int] = []

    # Priority for handler selection (higher = preferred)
    priority: int = 0

    # Whether to attempt parsing even if default ports don't match
    force_parse: bool = False

    @abstractmethod
    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        """
        Parse protocol from payload.

        Args:
            payload: Raw payload bytes to parse
            context: Protocol parsing context
            is_client_to_server: Direction of packet (True = C2S, False = S2C)

        Returns:
            ParseResult with parsed info and remaining data
        """
        pass

    def can_parse(self, payload: bytes, context: ProtocolContext) -> bool:
        """
        Check if this handler can parse the given payload.

        Default implementation checks for minimum length and port matching.
        Override for custom detection logic.
        """
        if not self.force_parse and self.default_ports:
            # Check if port matches
            pkt = context.packet
            if pkt.tcp:
                ports = {pkt.tcp.sport, pkt.tcp.dport}
                if not any(p in self.default_ports for p in ports):
                    return False
            elif pkt.udp:
                ports = {pkt.udp.sport, pkt.udp.dport}
                if not any(p in self.default_ports for p in ports):
                    return False

        return len(payload) > 0

    def extract_fields(self, payload: bytes, context: ProtocolContext) -> dict[str, Any]:
        """
        Extract protocol-specific fields without full parsing.

        Used for quick field extraction when full parsing isn't needed.
        """
        return {}

    @classmethod
    def handler_id(cls) -> str:
        """Get unique handler identifier."""
        return f"{cls.layer.name.lower()}.{cls.name}"
