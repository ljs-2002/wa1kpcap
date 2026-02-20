# Complete Custom Protocol Example: QUIC Initial over UDP

This example adds a QUIC Initial packet parser with typed Python properties,
dispatched from UDP port 443. No C++ changes or recompilation needed.

## Step 1: YAML Protocol Definition

File: `wa1kpcap/native/protocols/quic_initial.yaml`

```yaml
name: quic_initial
fields:
  - name: header_form
    type: bitfield
    group_size: 1
    fields:
      - name: form
        bits: 1
      - name: fixed_bit
        bits: 1
      - name: long_packet_type
        bits: 2
      - name: reserved
        bits: 2
      - name: packet_number_length
        bits: 2
  - name: version
    type: fixed
    size: 4
    format: uint
  - name: dcid
    type: length_prefixed
    length_size: 1
    format: hex
  - name: scid
    type: length_prefixed
    length_size: 1
    format: hex
```

## Step 2: Python Info Class

File: `my_project/quic_protocol.py`

```python
from wa1kpcap.core.packet import ProtocolInfo


class QUICInitialInfo(ProtocolInfo):
    """QUIC Initial packet information."""
    __slots__ = ()

    def __init__(self, fields=None, **kwargs):
        super().__init__(fields=fields or {}, **kwargs)

    @property
    def version(self) -> int:
        return self._fields.get('version', 0)

    @property
    def dcid(self) -> str:
        """Destination Connection ID (hex string)."""
        return self._fields.get('dcid', '')

    @property
    def scid(self) -> str:
        """Source Connection ID (hex string)."""
        return self._fields.get('scid', '')

    @property
    def long_packet_type(self) -> int:
        return self._fields.get('long_packet_type', 0)

    @property
    def is_quic_v1(self) -> bool:
        """Check if this is QUIC version 1 (RFC 9000)."""
        return self.version == 0x00000001

    @property
    def is_initial(self) -> bool:
        """Check if this is an Initial packet (type 0)."""
        return self.long_packet_type == 0
```

## Step 3: Register

File: `my_project/__init__.py`

```python
from wa1kpcap.core.packet import ProtocolRegistry
from my_project.quic_protocol import QUICInitialInfo

ProtocolRegistry.get_instance().register(
    "quic_initial",
    QUICInitialInfo,
    # routing injects UDP port 443 → quic_initial into the UDP parser
    # at engine init time, no need to edit udp.yaml
    routing={"udp": {443: "quic_initial"}},
)
```

## Step 4: Use

```python
from wa1kpcap import Wa1kPcap
import my_project  # triggers registration in __init__.py

analyzer = Wa1kPcap(engine="native")
flows = analyzer.analyze_file("quic_capture.pcap")

for flow in flows:
    for pkt in flow.packets:
        quic = pkt.layers.get("quic_initial")
        if quic:
            print(f"Version: 0x{quic.version:08x}")
            print(f"DCID: {quic.dcid}")
            print(f"SCID: {quic.scid}")
            print(f"Is QUIC v1: {quic.is_quic_v1}")
            print(f"Is Initial: {quic.is_initial}")
```

## Step 5: Test

File: `tests/test_quic_initial.py`

```python
import pytest
from my_project.quic_protocol import QUICInitialInfo


class TestQUICInitialInfo:
    def test_from_fields(self):
        info = QUICInitialInfo(fields={
            'version': 0x00000001,
            'dcid': 'aabbccdd',
            'scid': '11223344',
            'long_packet_type': 0,
        })
        assert info.version == 0x00000001
        assert info.dcid == 'aabbccdd'
        assert info.scid == '11223344'
        assert info.is_quic_v1 is True
        assert info.is_initial is True

    def test_defaults(self):
        info = QUICInitialInfo()
        assert info.version == 0
        assert info.dcid == ''
        assert info.is_quic_v1 is False

    def test_version_check(self):
        info = QUICInitialInfo(fields={'version': 0xFF000020})
        assert info.is_quic_v1 is False
```
