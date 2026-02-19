"""
NativeEngine: wraps C++ NativePcapReader + NativeParser + NativeFilter
into a single interface for the analyzer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

class NativeEngine:
    """High-level wrapper around the C++ native engine components."""

    def __init__(self, bpf_filter: str | None = None):
        from wa1kpcap.native import _wa1kpcap_native as _native
        if _native is None:
            raise RuntimeError(
                "Native C++ engine not available. "
                "Install with: pip install -e '.[native]'"
            )
        self._native = _native

        # Locate YAML protocol configs
        protocols_dir = str(Path(__file__).parent / "protocols")
        self._parser = _native.NativeParser(protocols_dir)

        # Load extra protocol YAML files from registry
        from wa1kpcap.core.packet import ProtocolRegistry
        registry = ProtocolRegistry.get_instance()
        for name, path in registry.get_yaml_paths().items():
            self._parser.load_extra_file(str(path))

        # Inject protocol routing from registry
        for name, routing in registry.get_routing().items():
            for parent_proto, mappings in routing.items():
                for value, target in mappings.items():
                    self._parser.add_protocol_routing(parent_proto, value, target)

        self._filter = _native.NativeFilter(bpf_filter or "") if bpf_filter else None
        # Cache whether filter can be fully evaluated on raw bytes
        self._filter_can_raw = (
            self._filter.can_match_raw() if self._filter else False
        )

    def read_and_parse(
        self,
        pcap_path: str | Path,
        save_raw_bytes: bool = False,
    ) -> Iterator:
        """Iterate over packets in a pcap file, yielding ParsedPacket.

        Uses NativePipeline: fused read→filter→parse→dataclass in a single
        C++ loop, eliminating per-packet Python↔C++ boundary crossing.

        Args:
            pcap_path: Path to pcap/pcapng file
            save_raw_bytes: Whether to save raw bytes in parsed packet

        Yields:
            ParsedPacket objects (Python dataclasses, fast attribute access)
        """
        pipeline = self._native.NativePipeline(
            str(pcap_path), self._parser, self._filter, save_raw_bytes)
        with pipeline:
            yield from pipeline

    def create_flow_buffer(self):
        """Create a new FlowBuffer for TCP stream reassembly bridge."""
        return self._native.FlowBuffer()

    def try_parse_app(self, flow_buffer, protocol: str) -> dict:
        """Try to parse application layer from a flow buffer.

        Args:
            flow_buffer: FlowBuffer instance
            protocol: Protocol name (e.g., "tls_record")

        Returns:
            Parsed dict (empty if not enough data)
        """
        return flow_buffer.try_parse_app(self._parser, protocol)

    def parse_tls_record(self, data: bytes):
        """Parse a complete TLS record using C++ engine.

        Args:
            data: Complete TLS record bytes (header + payload)

        Returns:
            NativeParsedPacket with TLS info filled, or None if parse fails.
        """
        try:
            result = self._parser.parse_tls_record(data)
            if result.tls is not None:
                return result
        except Exception:
            pass
        return None
