"""
Protocol handler registry with decorator support.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from functools import wraps
from wa1kpcap.protocols.base import Layer

if TYPE_CHECKING:
    from wa1kpcap.protocols.base import BaseProtocolHandler


class ProtocolHandlerRegistry:
    """
    Global registry for protocol handlers.

    Supports registration via decorator and allows querying handlers
    by layer, encapsulated protocol, or port.
    """

    def __init__(self):
        self._handlers: dict[str, type[BaseProtocolHandler]] = {}
        self._by_layer: dict[int, list[str]] = {}
        self._by_encapsulation: dict[str, list[str]] = {}
        self._by_port: dict[int, list[str]] = {}

    def register(self, handler_cls: type[BaseProtocolHandler]) -> type[BaseProtocolHandler]:
        """Register a protocol handler class."""
        if not handler_cls.name:
            raise ValueError(f"Handler {handler_cls.__name__} must have a name")

        handler_id = handler_cls.handler_id()

        if handler_id in self._handlers:
            raise ValueError(f"Handler {handler_id} already registered")

        self._handlers[handler_id] = handler_cls
        self._by_layer.setdefault(handler_cls.layer.value, []).append(handler_id)

        if handler_cls.encapsulates:
            self._by_encapsulation.setdefault(handler_cls.encapsulates, []).append(handler_id)

        for port in handler_cls.default_ports:
            self._by_port.setdefault(port, []).append(handler_id)

        return handler_cls

    def get(self, name: str) -> type[BaseProtocolHandler] | None:
        """Get handler by name (supports short name lookup)."""
        # Direct lookup first
        handler_cls = self._handlers.get(name)
        if handler_cls:
            return handler_cls

        # Try short name lookup (search through handlers)
        for cls in self._handlers.values():
            if cls.name == name:
                return cls
        return None

    def get_by_layer(self, layer: Layer) -> list[type[BaseProtocolHandler]]:
        """Get all handlers for a specific layer."""
        handler_ids = self._by_layer.get(layer.value, [])
        return [self._handlers[hid] for hid in handler_ids if hid in self._handlers]

    def get_by_encapsulation(self, protocol: str) -> list[type[BaseProtocolHandler]]:
        """Get all handlers that encapsulate a specific protocol."""
        handler_ids = self._by_encapsulation.get(protocol, [])
        return [self._handlers[hid] for hid in handler_ids if hid in self._handlers]

    def get_by_port(self, port: int) -> list[type[BaseProtocolHandler]]:
        """Get all handlers that use a specific default port."""
        handler_ids = self._by_port.get(port, [])
        return [self._handlers[hid] for hid in handler_ids if hid in self._handlers]

    def list_handlers(self) -> list[str]:
        """List all registered handler IDs."""
        return list(self._handlers.keys())

    def create_instance(self, name: str) -> BaseProtocolHandler | None:
        """Create an instance of a registered handler."""
        handler_cls = self.get(name)
        if handler_cls:
            return handler_cls()
        return None

    def unregister(self, name: str) -> bool:
        """Unregister a handler by name."""
        # Try direct lookup first
        handler_cls = self.get(name)
        if not handler_cls:
            # Try as simple name (search through handlers)
            for cls in self._handlers.values():
                if cls.name == name:
                    handler_cls = cls
                    break

        if not handler_cls:
            return False

        handler_id = handler_cls.handler_id()

        # Remove from layer index
        if handler_cls.layer.value in self._by_layer:
            self._by_layer[handler_cls.layer.value] = [
                hid for hid in self._by_layer[handler_cls.layer.value] if hid != handler_id
            ]

        # Remove from encapsulation index
        if handler_cls.encapsulates and handler_cls.encapsulates in self._by_encapsulation:
            self._by_encapsulation[handler_cls.encapsulates] = [
                hid for hid in self._by_encapsulation[handler_cls.encapsulates] if hid != handler_id
            ]

        # Remove from port index
        for port in handler_cls.default_ports:
            if port in self._by_port:
                self._by_port[port] = [
                    hid for hid in self._by_port[port] if hid != handler_id
                ]

        del self._handlers[handler_id]
        return True

    def clear(self) -> None:
        """Clear all registered handlers."""
        self._handlers.clear()
        self._by_layer.clear()
        self._by_encapsulation.clear()
        self._by_port.clear()


# Global registry instance
_global_registry = ProtocolHandlerRegistry()


def get_global_registry() -> ProtocolHandlerRegistry:
    """Get the global protocol handler registry."""
    return _global_registry


def register_protocol(
    name: str,
    layer: Layer,
    encapsulates: str | None = None,
    default_ports: list[int] | None = None,
    priority: int = 0,
    force_parse: bool = False,
    registry: ProtocolHandlerRegistry | None = None
) -> Callable[[type[BaseProtocolHandler]], type[BaseProtocolHandler]]:
    """
    Decorator to register a protocol handler.

    Args:
        name: Protocol handler name
        layer: Protocol layer this handler operates on
        encapsulates: Protocol this handler encapsulates (e.g., 'tcp' for TLS)
        default_ports: Default port(s) for this protocol
        priority: Handler priority (higher = preferred)
        force_parse: Whether to parse even if ports don't match
        registry: Registry to use (defaults to global)

    Example:
        @register_protocol('tls', Layer.PRESENTATION, encapsulates='tcp',
                          default_ports=[443], priority=100)
        class TLSHandler(BaseProtocolHandler):
            pass
    """
    if registry is None:
        registry = _global_registry

    def decorator(cls: type[BaseProtocolHandler]) -> type[BaseProtocolHandler]:
        # Set class attributes from decorator args
        cls.name = name
        cls.layer = layer
        cls.encapsulates = encapsulates
        cls.default_ports = default_ports or []
        cls.priority = priority
        cls.force_parse = force_parse

        return registry.register(cls)

    return decorator


def unregister_protocol(name: str, registry: ProtocolHandlerRegistry | None = None) -> bool:
    """Unregister a protocol handler by name."""
    if registry is None:
        registry = _global_registry
    return registry.unregister(name)


def get_protocol_handlers(
    layer: Layer | None = None,
    encapsulates: str | None = None,
    port: int | None = None,
    registry: ProtocolHandlerRegistry | None = None
) -> list[type[BaseProtocolHandler]]:
    """
    Get protocol handlers matching the given criteria.

    Args:
        layer: Filter by protocol layer
        encapsulates: Filter by encapsulated protocol
        port: Filter by default port
        registry: Registry to query (defaults to global)

    Returns:
        List of matching handler classes
    """
    if registry is None:
        registry = _global_registry

    if layer is not None:
        handlers = registry.get_by_layer(layer)
    elif encapsulates is not None:
        handlers = registry.get_by_encapsulation(encapsulates)
    elif port is not None:
        handlers = registry.get_by_port(port)
    else:
        handlers = list(registry._handlers.values())

    # Sort by priority
    return sorted(handlers, key=lambda h: h.priority, reverse=True)
