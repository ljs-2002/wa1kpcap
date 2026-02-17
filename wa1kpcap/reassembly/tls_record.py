"""
TLS record reassembly engine.

Handles reassembly of TLS records that span multiple TCP segments.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
import struct
import time

if TYPE_CHECKING:
    from wa1kpcap.core.packet import ParsedPacket


@dataclass
class TLSRecordHeader:
    """Parsed TLS record header."""
    content_type: int
    major_version: int
    minor_version: int
    length: int

    @classmethod
    def parse(cls, data: bytes) -> TLSRecordHeader | None:
        """Parse TLS record header from bytes."""
        if len(data) < 5:
            return None

        return cls(
            content_type=data[0],
            major_version=data[1],
            minor_version=data[2],
            length=struct.unpack('>H', data[3:5])[0]
        )


@dataclass
class TLSReassemblyBuffer:
    """
    Buffer for reassembling TLS records across TCP segments.
    """

    flow_key: str
    partial_data: bytearray = field(default_factory=bytearray)
    expected_record_length: int = 0
    last_seen: float = field(default_factory=time.time)
    records_found: int = 0
    incomplete_records: int = 0

    def add_data(self, data: bytes) -> list[bytes]:
        """
        Add TCP data and return complete TLS records.

        Returns:
            List of complete TLS record payloads
        """
        self.last_seen = time.time()
        records = []

        self.partial_data.extend(data)

        while True:
            if self.expected_record_length == 0:
                # Need to parse header
                if len(self.partial_data) < 5:
                    break

                header = TLSRecordHeader.parse(bytes(self.partial_data[:5]))
                if not header:
                    # Invalid header, clear buffer
                    self.partial_data.clear()
                    self.incomplete_records += 1
                    break

                self.expected_record_length = 5 + header.length

            # Check if we have a complete record
            if len(self.partial_data) < self.expected_record_length:
                break

            # Extract complete record
            record = bytes(self.partial_data[:self.expected_record_length])
            records.append(record)
            self.records_found += 1

            # Remove record from buffer
            self.partial_data = self.partial_data[self.expected_record_length:]
            self.expected_record_length = 0

        return records

    def get_partial(self) -> bytes:
        """Get partial data (incomplete record)."""
        return bytes(self.partial_data)

    def clear(self) -> None:
        """Clear the buffer."""
        self.partial_data.clear()
        self.expected_record_length = 0

    def is_idle(self, timeout: float) -> bool:
        """Check if buffer has been idle too long."""
        return time.time() - self.last_seen > timeout


class TLSRecordReassembler:
    """
    Reassembles TLS records that may span multiple TCP segments.

    TLS records have a 5-byte header followed by payload. When TCP
    segmentation splits a TLS record, this reassembler collects the
    segments and delivers complete records.
    """

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout
        self._buffers: dict[str, TLSReassemblyBuffer] = {}
        self._records_processed: int = 0
        self._incomplete_records: int = 0

    def get_or_create_buffer(self, flow_key: str) -> TLSReassemblyBuffer:
        """Get or create a reassembly buffer for a flow."""
        if flow_key not in self._buffers:
            self._buffers[flow_key] = TLSReassemblyBuffer(flow_key=flow_key)
        return self._buffers[flow_key]

    def add_data(self, flow_key: str, data: bytes) -> list[bytes]:
        """
        Add TCP data and return complete TLS records.

        Args:
            flow_key: Unique flow identifier
            data: TCP payload data

        Returns:
            List of complete TLS records
        """
        if not data:
            return []

        buffer = self.get_or_create_buffer(flow_key)
        records = buffer.add_data(data)

        self._records_processed += len(records)

        return records

    def process_packet(self, pkt: ParsedPacket, flow_key: str, tcp_payload: bytes | None = None) -> list[bytes]:
        """
        Process a packet through TLS record reassembly.

        Args:
            pkt: Parsed packet
            flow_key: Unique flow identifier
            tcp_payload: TCP payload data (required, extracted from packet)

        Returns:
            List of complete TLS records found
        """
        # Get TCP payload
        if not pkt.tcp:
            return []

        if tcp_payload is None:
            return []

        return self.add_data(flow_key, tcp_payload)

    def extract_records(self, data: bytes) -> list[tuple[int, bytes]]:
        """
        Extract all complete TLS records from a byte stream.

        Args:
            data: Raw TLS byte stream

        Returns:
            List of (content_type, record_data) tuples
        """
        records = []
        offset = 0

        while offset + 5 <= len(data):
            header = TLSRecordHeader.parse(data[offset:])
            if not header:
                break

            record_end = offset + 5 + header.length
            if record_end > len(data):
                break

            record_data = data[offset + 5:record_end]
            records.append((header.content_type, record_data))

            offset = record_end

        return records

    def cleanup(self, force: bool = False) -> int:
        """
        Clean up old reassembly buffers.

        Args:
            force: If True, clean all buffers

        Returns:
            Number of buffers cleaned up
        """
        to_remove = []

        for key, buffer in self._buffers.items():
            if force or buffer.is_idle(self.timeout):
                if len(buffer.get_partial()) > 0:
                    self._incomplete_records += 1
                to_remove.append(key)

        for key in to_remove:
            del self._buffers[key]

        return len(to_remove)

    def clear(self) -> None:
        """Clear all reassembly buffers."""
        self._buffers.clear()

    @property
    def buffer_count(self) -> int:
        """Number of active reassembly buffers."""
        return len(self._buffers)

    @property
    def stats(self) -> dict:
        """Get reassembly statistics."""
        return {
            'records_processed': self._records_processed,
            'incomplete_records': self._incomplete_records,
            'active_buffers': len(self._buffers)
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._records_processed = 0
        self._incomplete_records = 0

    @staticmethod
    def get_content_type_name(content_type: int) -> str:
        """Get content type name."""
        names = {
            20: 'change_cipher_spec',
            21: 'alert',
            22: 'handshake',
            23: 'application_data',
            24: 'heartbeat',
        }
        return names.get(content_type, f'unknown({content_type})')

    @staticmethod
    def is_tls_client_hello(data: bytes) -> bool:
        """
        Check if data contains a TLS ClientHello.

        Args:
            data: Potential TLS record data

        Returns:
            True if ClientHello detected
        """
        if len(data) < 20:
            return False

        # Check for TLS record header
        # Content type 22 = Handshake
        if data[0] != 22:
            return False

        # Check version (3.0 - 3.4)
        major = data[1]
        minor = data[2]
        if major != 3 or minor > 4:
            return False

        # Check length
        length = struct.unpack('>H', data[3:5])[0]
        if length < 40 or length > 16384:
            return False

        # Check for ClientHello (handshake type 1 at offset 5)
        if len(data) < 6:
            return False

        handshake_type = data[5]
        return handshake_type == 1

    @staticmethod
    def is_tls_server_hello(data: bytes) -> bool:
        """
        Check if data contains a TLS ServerHello.
        """
        if len(data) < 20:
            return False

        # Check for TLS record header
        if data[0] != 22:  # Handshake
            return False

        # Check version
        major = data[1]
        minor = data[2]
        if major != 3 or minor > 4:
            return False

        # Check for ServerHello (handshake type 2 at offset 5)
        if len(data) < 6:
            return False

        handshake_type = data[5]
        return handshake_type == 2
