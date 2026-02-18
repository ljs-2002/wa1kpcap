"""
Test: register a new protocol via YAML + ProtocolInfo, parse raw bytes through
both the struct path and dict path, verify layers are populated correctly.

Custom protocol "myproto" sits on UDP port 7777:
  - magic:   1 byte (0xAB)
  - version: 1 byte
  - msg_len: 2 bytes (big-endian)
  - msg_id:  2 bytes (big-endian)
"""
import os
import shutil
import struct
import tempfile
import pytest

from wa1kpcap.core.packet import ProtocolInfo, ProtocolRegistry, ParsedPacket


# ── Custom ProtocolInfo subclass ──

class MyProtoInfo(ProtocolInfo):
    """Custom protocol info for testing."""
    __slots__ = ()

    def __init__(self, magic=None, version=None, msg_len=None, msg_id=None,
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'magic': magic, 'version': version,
                'msg_len': msg_len, 'msg_id': msg_id,
            })

    @property
    def magic(self): return self._fields.get('magic')
    @magic.setter
    def magic(self, v): self._fields['magic'] = v

    @property
    def version(self): return self._fields.get('version')
    @version.setter
    def version(self, v): self._fields['version'] = v

    @property
    def msg_len(self): return self._fields.get('msg_len')
    @msg_len.setter
    def msg_len(self, v): self._fields['msg_len'] = v

    @property
    def msg_id(self): return self._fields.get('msg_id')
    @msg_id.setter
    def msg_id(self, v): self._fields['msg_id'] = v

    def merge(self, other: 'MyProtoInfo') -> None:
        """First-wins for scalars."""
        for k, v in other._fields.items():
            if self._fields.get(k) is None and v is not None:
                self._fields[k] = v


MYPROTO_YAML = """\
name: myproto
fields:
  - name: magic
    type: fixed
    size: 1
    format: uint
  - name: version
    type: fixed
    size: 1
    format: uint
  - name: msg_len
    type: fixed
    size: 2
    format: uint
  - name: msg_id
    type: fixed
    size: 2
    format: uint
"""

UDP_YAML_PATCHED = """\
name: udp
fields:
  - name: src_port
    type: fixed
    size: 2
    format: uint
  - name: dst_port
    type: fixed
    size: 2
    format: uint
  - name: length
    type: fixed
    size: 2
    format: uint
  - name: checksum
    type: fixed
    size: 2
    format: uint

next_protocol:
  field: [dst_port, src_port]
  mapping:
    53: dns
    7777: myproto
"""


def _build_raw_packet(src_port=12345, dst_port=7777,
                      magic=0xAB, version=2, msg_id=42):
    """Build raw Ethernet + IPv4 + UDP + myproto bytes."""
    # myproto payload: magic(1) + version(1) + msg_len(2) + msg_id(2) = 6 bytes
    myproto_payload = struct.pack('!BBHH', magic, version, 6, msg_id)

    # UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8 bytes
    udp_len = 8 + len(myproto_payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)

    # IPv4 header (20 bytes, no options)
    ip_total_len = 20 + udp_len
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45,           # version=4, IHL=5
        0,              # DSCP/ECN
        ip_total_len,   # total length
        0,              # identification
        0,              # flags + fragment offset
        64,             # TTL
        17,             # protocol = UDP
        0,              # checksum (0 = skip)
        b'\xc0\xa8\x01\x01',  # src: 192.168.1.1
        b'\xc0\xa8\x01\x02',  # dst: 192.168.1.2
    )

    # Ethernet header (14 bytes)
    eth_header = (
        b'\x00\x11\x22\x33\x44\x55'   # dst MAC
        b'\x66\x77\x88\x99\xaa\xbb'   # src MAC
        b'\x08\x00'                     # EtherType = IPv4
    )

    return eth_header + ip_header + udp_header + myproto_payload


@pytest.fixture
def protocols_dir():
    """Create a temp protocols dir with standard YAMLs + myproto + patched UDP."""
    src_dir = os.path.join(os.path.dirname(__file__),
                           '..', 'wa1kpcap', 'native', 'protocols')
    src_dir = os.path.normpath(src_dir)

    tmpdir = tempfile.mkdtemp(prefix='wa1kpcap_test_proto_')
    try:
        # Copy all standard YAMLs
        for f in os.listdir(src_dir):
            if f.endswith('.yaml') and f != 'udp.yaml':
                shutil.copy2(os.path.join(src_dir, f), tmpdir)

        # Write patched UDP (adds port 7777 → myproto)
        with open(os.path.join(tmpdir, 'udp.yaml'), 'w') as f:
            f.write(UDP_YAML_PATCHED)

        # Write myproto YAML
        with open(os.path.join(tmpdir, 'myproto.yaml'), 'w') as f:
            f.write(MYPROTO_YAML)

        yield tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(autouse=True)
def register_myproto():
    """Register MyProtoInfo in ProtocolRegistry for the duration of the test."""
    registry = ProtocolRegistry.get_instance()
    registry.register('myproto', MyProtoInfo)
    yield
    # Clean up: remove registration
    registry._registry.pop('myproto', None)


class TestCustomProtocolStructPath:
    """Test custom protocol via struct path (parse_to_dataclass)."""

    def test_struct_path_extra_layers(self, protocols_dir):
        """parse_to_dataclass should populate extra_layers with myproto fields."""
        from wa1kpcap.native import _wa1kpcap_native as _native

        parser = _native.NativeParser(protocols_dir)
        raw = _build_raw_packet()

        pkt = parser.parse_to_dataclass(raw, 1, False, 1.0, len(raw), len(raw))

        # Basic layers should be present
        assert pkt.eth is not None
        assert pkt.ip is not None
        assert pkt.udp is not None

        # Custom protocol should be in layers
        assert 'myproto' in pkt.layers, f"layers keys: {list(pkt.layers.keys())}"
        myproto = pkt.layers['myproto']
        assert isinstance(myproto, MyProtoInfo)
        assert myproto.magic == 0xAB
        assert myproto.version == 2
        assert myproto.msg_len == 6
        assert myproto.msg_id == 42

    def test_struct_path_different_values(self, protocols_dir):
        """Verify different field values are parsed correctly."""
        from wa1kpcap.native import _wa1kpcap_native as _native

        parser = _native.NativeParser(protocols_dir)
        raw = _build_raw_packet(magic=0xCD, version=5, msg_id=999)

        pkt = parser.parse_to_dataclass(raw, 1, False, 1.0, len(raw), len(raw))

        myproto = pkt.layers['myproto']
        assert myproto.magic == 0xCD
        assert myproto.version == 5
        assert myproto.msg_id == 999


class TestCustomProtocolDictPath:
    """Test custom protocol via dict path (parse_packet + dict_to_parsed_packet)."""

    def test_dict_path_extra_layers(self, protocols_dir):
        """parse_packet dict should contain myproto, converter should populate layers."""
        from wa1kpcap.native import _wa1kpcap_native as _native
        from wa1kpcap.native.converter import dict_to_parsed_packet

        parser = _native.NativeParser(protocols_dir)
        raw = _build_raw_packet()

        d = parser.parse_packet(raw, 1, False)

        # Dict should contain myproto key
        assert 'myproto' in d, f"dict keys: {list(d.keys())}"
        assert d['myproto']['magic'] == 0xAB
        assert d['myproto']['version'] == 2

        # Convert to ParsedPacket
        pkt = dict_to_parsed_packet(d, 1.0, raw, 1)

        assert 'myproto' in pkt.layers
        myproto = pkt.layers['myproto']
        assert isinstance(myproto, MyProtoInfo)
        assert myproto.magic == 0xAB
        assert myproto.version == 2
        assert myproto.msg_len == 6
        assert myproto.msg_id == 42

    def test_dict_path_raw_dict_values(self, protocols_dir):
        """Verify raw dict output from C++ contains correct field values."""
        from wa1kpcap.native import _wa1kpcap_native as _native

        parser = _native.NativeParser(protocols_dir)
        raw = _build_raw_packet(magic=0xFF, version=3, msg_id=100)

        d = parser.parse_packet(raw, 1, False)
        assert d['myproto']['magic'] == 0xFF
        assert d['myproto']['version'] == 3
        assert d['myproto']['msg_id'] == 100


class TestCustomProtocolUnregistered:
    """Test that unregistered protocols still get a generic ProtocolInfo."""

    def test_unregistered_falls_back_to_generic(self, protocols_dir):
        """Without MyProtoInfo registered, should use ProtocolInfo(fields=...)."""
        # Temporarily unregister
        registry = ProtocolRegistry.get_instance()
        registry._registry.pop('myproto', None)

        from wa1kpcap.native import _wa1kpcap_native as _native

        parser = _native.NativeParser(protocols_dir)
        raw = _build_raw_packet()

        # Struct path
        pkt = parser.parse_to_dataclass(raw, 1, False, 1.0, len(raw), len(raw))
        assert 'myproto' in pkt.layers
        myproto = pkt.layers['myproto']
        assert type(myproto) is ProtocolInfo  # generic, not MyProtoInfo
        assert myproto.get('magic') == 0xAB
        assert myproto.get('version') == 2

        # Re-register for other tests
        registry.register('myproto', MyProtoInfo)


class TestCustomProtocolMerge:
    """Test that custom protocol merge works in flow aggregation."""

    def test_merge_two_packets(self):
        """MyProtoInfo.merge() should do first-wins for scalars."""
        a = MyProtoInfo(magic=0xAB, version=2, msg_len=6, msg_id=42)
        b = MyProtoInfo(magic=0xCD, version=5, msg_len=10, msg_id=99)

        a.merge(b)
        # First-wins: a's values should be preserved
        assert a.magic == 0xAB
        assert a.version == 2
        assert a.msg_len == 6
        assert a.msg_id == 42

    def test_merge_fills_none(self):
        """merge() should fill None fields from other."""
        a = MyProtoInfo(magic=0xAB, version=None, msg_len=None, msg_id=42)
        b = MyProtoInfo(magic=0xCD, version=5, msg_len=10, msg_id=99)

        a.merge(b)
        assert a.magic == 0xAB    # kept
        assert a.version == 5     # filled from b
        assert a.msg_len == 10    # filled from b
        assert a.msg_id == 42     # kept

    def test_copy(self):
        """ProtocolInfo.copy() should deep-copy mutable values."""
        a = MyProtoInfo(magic=0xAB, version=2, msg_len=6, msg_id=42)
        b = a.copy()
        assert isinstance(b, MyProtoInfo)
        assert b.magic == 0xAB
        assert b.version == 2
        b.magic = 0xFF
        assert a.magic == 0xAB  # original unchanged


class TestCustomProtocolFlowAggregation:
    """Test that custom protocol layers aggregate correctly at flow level."""

    def test_generic_merge_in_aggregate(self, protocols_dir):
        """_aggregate_flow_info should merge custom protocol layers via generic loop."""
        from wa1kpcap.native import _wa1kpcap_native as _native

        parser = _native.NativeParser(protocols_dir)

        # Build two packets with different msg_ids
        raw1 = _build_raw_packet(magic=0xAB, version=2, msg_id=42)
        raw2 = _build_raw_packet(magic=0xAB, version=2, msg_id=99)

        pkt1 = parser.parse_to_dataclass(raw1, 1, False, 1.0, len(raw1), len(raw1))
        pkt2 = parser.parse_to_dataclass(raw2, 1, False, 2.0, len(raw2), len(raw2))

        assert 'myproto' in pkt1.layers
        assert 'myproto' in pkt2.layers

        # Simulate flow aggregation: first packet's values should win
        flow_layers = {}
        for pkt in [pkt1, pkt2]:
            for layer_name, layer_info in pkt.layers.items():
                if isinstance(layer_info, ProtocolInfo):
                    existing = flow_layers.get(layer_name)
                    if existing is None:
                        flow_layers[layer_name] = layer_info.copy()
                    else:
                        existing.merge(layer_info)

        assert 'myproto' in flow_layers
        myproto = flow_layers['myproto']
        assert myproto.msg_id == 42  # first-wins
        assert myproto.magic == 0xAB


class TestCustomProtocolBuildExtProtocol:
    """Test that build_ext_protocol includes custom protocol in stack."""

    def test_ext_protocol_includes_custom(self, protocols_dir):
        """build_ext_protocol should include MYPROTO in the protocol stack."""
        from wa1kpcap.core.flow import Flow, FlowKey
        from wa1kpcap.native import _wa1kpcap_native as _native

        parser = _native.NativeParser(protocols_dir)
        raw = _build_raw_packet()
        pkt = parser.parse_to_dataclass(raw, 1, False, 1.0, len(raw), len(raw))

        # Create a minimal flow
        key = FlowKey(
            src_ip='192.168.1.1', dst_ip='192.168.1.2',
            src_port=12345, dst_port=7777, protocol=17
        )
        flow = Flow(key=key)
        flow.packets.append(pkt)
        # Copy layers from packet to flow (simulating aggregation)
        for name, info in pkt.layers.items():
            if isinstance(info, ProtocolInfo):
                flow.layers[name] = info.copy()

        stack = flow.build_ext_protocol()
        assert "IPv4" in stack
        assert "UDP" in stack
        assert "MYPROTO" in stack  # dynamic from layers
