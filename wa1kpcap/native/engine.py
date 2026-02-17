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

        Uses raw-byte BPF pre-filtering to skip non-matching packets
        before full protocol parsing. C++ directly constructs Python
        dataclass objects, bypassing dict + converter.py overhead.

        Args:
            pcap_path: Path to pcap/pcapng file
            save_raw_bytes: Whether to save raw bytes in parsed packet

        Yields:
            ParsedPacket objects (Python dataclasses, fast attribute access)
        """
        reader = self._native.NativePcapReader(str(pcap_path))
        bpf = self._filter
        can_raw = self._filter_can_raw
        parse = self._parser.parse_to_dataclass

        with reader:
            for ts, raw_data, caplen, wirelen, pkt_link_type in reader:
                # Fast raw-byte pre-filter (skips full parse for non-matching)
                if bpf and can_raw:
                    if not bpf.matches_raw(raw_data, pkt_link_type):
                        continue

                # App-layer filter needs parsed dict (fallback path)
                if bpf and not can_raw:
                    parsed_dict = self._parser.parse_packet(
                        raw_data, pkt_link_type, save_raw_bytes
                    )
                    if not bpf.matches(parsed_dict):
                        continue

                # C++ parse → directly construct Python dataclasses
                pkt = parse(raw_data, pkt_link_type, save_raw_bytes,
                            ts, caplen, wirelen)
                yield pkt

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
