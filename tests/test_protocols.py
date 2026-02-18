"""Test protocol handler registry and base classes."""

import pytest
import sys
sys.path.insert(0, r'D:\MyProgram\wa1kpcap1')

from wa1kpcap.protocols.registry import (
    ProtocolHandlerRegistry,
    register_protocol,
    get_protocol_handlers,
    get_global_registry,
    unregister_protocol,
)
from wa1kpcap.protocols.base import (
    BaseProtocolHandler,
    Layer,
    ParseResult,
)


def test_layer_enum():
    """Test Layer enum values."""
    assert Layer.PHYSICAL.value == 1
    assert Layer.DATA_LINK.value == 2
    assert Layer.NETWORK.value == 3
    assert Layer.TRANSPORT.value == 4
    assert Layer.SESSION.value == 5
    assert Layer.PRESENTATION.value == 6
    assert Layer.APPLICATION.value == 7


def test_parse_result():
    """Test ParseResult creation."""
    result = ParseResult(
        success=True,
        data=b'data',
        attributes={"key": "value"},
        consumed=10
    )
    assert result.success == True
    assert result.data == b'data'
    assert result.attributes == {"key": "value"}
    assert result.consumed == 10


def test_protocol_handler_registry_init():
    """Test registry initialization."""
    registry = ProtocolHandlerRegistry()
    assert len(registry._handlers) == 0
    assert len(registry._by_layer) == 0
    assert len(registry._by_encapsulation) == 0
    assert len(registry._by_port) == 0


def test_protocol_handler_registry_register():
    """Test registering a handler."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class TestHandler(BaseProtocolHandler):
        name = "test"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = []
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    assert "transport.test" in registry._handlers
    assert registry.get("transport.test") is TestHandler
    assert TestHandler in registry.get_by_layer(Layer.TRANSPORT)


def test_protocol_handler_registry_register_with_ports():
    """Test registering a handler with ports."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class HTTPHandler(BaseProtocolHandler):
        name = "http"
        layer = Layer.APPLICATION
        encapsulates = "tcp"
        default_ports = [80, 8080]
        priority = 100

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    assert "application.http" in registry._handlers
    assert "tcp" in registry._by_encapsulation
    assert HTTPHandler in registry.get_by_encapsulation("tcp")
    assert HTTPHandler in registry.get_by_port(80)
    assert HTTPHandler in registry.get_by_port(8080)


def test_protocol_handler_registry_duplicate():
    """Test duplicate registration raises error."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class TestHandler(BaseProtocolHandler):
        name = "test"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = []
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    with pytest.raises(ValueError):
        @registry.register
        class TestHandler2(BaseProtocolHandler):
            name = "test"  # Duplicate name
            layer = Layer.TRANSPORT
            encapsulates = None
            default_ports = []
            priority = 0

            def parse(self, payload, context, is_client_to_server):
                return ParseResult(success=True, data=b'', attributes={}, consumed=0)


def test_protocol_handler_registry_get():
    """Test get method."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class TestHandler(BaseProtocolHandler):
        name = "test"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = []
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    handler_cls = registry.get("transport.test")
    assert handler_cls is TestHandler

    none_handler = registry.get("nonexistent")
    assert none_handler is None


def test_protocol_handler_registry_get_by_port():
    """Test get_by_port method."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class HTTPHandler(BaseProtocolHandler):
        name = "http"
        layer = Layer.APPLICATION
        encapsulates = "tcp"
        default_ports = [80]
        priority = 100

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    @registry.register
    class DNSHandler(BaseProtocolHandler):
        name = "dns"
        layer = Layer.APPLICATION
        encapsulates = "udp"
        default_ports = [53]
        priority = 100

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    handlers = registry.get_by_port(80)
    assert len(handlers) == 1
    assert handlers[0] is HTTPHandler

    handlers = registry.get_by_port(53)
    assert len(handlers) == 1
    assert handlers[0] is DNSHandler


def test_protocol_handler_registry_list_handlers():
    """Test list_handlers method."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class Handler1(BaseProtocolHandler):
        name = "handler1"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = []
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    @registry.register
    class Handler2(BaseProtocolHandler):
        name = "handler2"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = []
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    names = registry.list_handlers()
    assert "transport.handler1" in names
    assert "transport.handler2" in names


def test_protocol_handler_registry_create_instance():
    """Test create_instance method."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class TestHandler(BaseProtocolHandler):
        name = "test"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = []
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    instance = registry.create_instance("transport.test")
    assert isinstance(instance, TestHandler)

    none_instance = registry.create_instance("nonexistent")
    assert none_instance is None


def test_protocol_handler_registry_unregister():
    """Test unregister method."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class TestHandler(BaseProtocolHandler):
        name = "test"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = [80]
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    assert "transport.test" in registry._handlers
    assert registry.unregister("test") == True
    assert "transport.test" not in registry._handlers
    assert registry.unregister("test") == False  # Already removed


def test_protocol_handler_registry_clear():
    """Test clear method."""
    registry = ProtocolHandlerRegistry()

    @registry.register
    class Handler1(BaseProtocolHandler):
        name = "handler1"
        layer = Layer.TRANSPORT
        encapsulates = None
        default_ports = []
        priority = 0

        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    assert len(registry._handlers) > 0

    registry.clear()

    assert len(registry._handlers) == 0
    assert len(registry._by_layer) == 0
    assert len(registry._by_encapsulation) == 0
    assert len(registry._by_port) == 0


def test_register_protocol_decorator():
    """Test register_protocol decorator."""
    registry = get_global_registry()

    # Ensure clean state
    registry.unregister("test_proto")

    @register_protocol("test_proto", Layer.APPLICATION, encapsulates="tcp", default_ports=[9999])
    class TestProtocol(BaseProtocolHandler):
        name = "test_proto"
        layer = Layer.APPLICATION
        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    # Check attributes were set
    assert TestProtocol.name == "test_proto"
    assert TestProtocol.layer == Layer.APPLICATION
    assert TestProtocol.encapsulates == "tcp"
    assert TestProtocol.default_ports == [9999]
    assert TestProtocol.priority == 0

    # Check it was registered
    assert registry.get("application.test_proto") is not None

    # Clean up
    registry.unregister("test_proto")


def test_register_protocol_with_priority():
    """Test register_protocol with priority parameter."""
    registry = get_global_registry()

    registry.unregister("prio_proto")

    @register_protocol("prio_proto", Layer.APPLICATION, priority=100)
    class PrioProtocol(BaseProtocolHandler):
        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    assert PrioProtocol.priority == 100

    registry.unregister("prio_proto")


def test_get_protocol_handlers():
    """Test get_protocol_handlers function."""
    registry = get_global_registry()

    # Ensure clean
    registry.unregister("query_proto")

    @register_protocol("query_proto", Layer.TRANSPORT, default_ports=[8888])
    class QueryProtocol(BaseProtocolHandler):
        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    handlers = get_protocol_handlers(port=8888)
    assert len(handlers) > 0
    assert any(h.name == "query_proto" for h in handlers)

    registry.unregister("query_proto")


def test_unregister_protocol_function():
    """Test unregister_protocol function."""
    registry = get_global_registry()

    registry.unregister("temp_proto")

    @register_protocol("temp_proto", Layer.TRANSPORT)
    class TempProtocol(BaseProtocolHandler):
        name = "temp_proto"
        layer = Layer.TRANSPORT
        def parse(self, payload, context, is_client_to_server):
            return ParseResult(success=True, data=b'', attributes={}, consumed=0)

    assert registry.get("transport.temp_proto") is not None
    assert unregister_protocol("temp_proto") == True
    assert registry.get("transport.temp_proto") is None


def test_all():
    """Run all protocol tests."""
    test_layer_enum()
    test_parse_result()
    test_protocol_handler_registry_init()
    test_protocol_handler_registry_register()
    test_protocol_handler_registry_register_with_ports()
    test_protocol_handler_registry_duplicate()
    test_protocol_handler_registry_get()
    test_protocol_handler_registry_get_by_port()
    test_protocol_handler_registry_list_handlers()
    test_protocol_handler_registry_create_instance()
    test_protocol_handler_registry_unregister()
    test_protocol_handler_registry_clear()
    test_register_protocol_decorator()
    test_register_protocol_with_priority()
    test_get_protocol_handlers()
    test_unregister_protocol_function()
    print("test_protocols PASSED")


if __name__ == '__main__':
    test_all()
