"""
TCP stream reassembly engine.

Handles TCP sequence tracking, out-of-order data, and reassembly
of application layer data across multiple TCP segments.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
import time

if TYPE_CHECKING:
    from wa1kpcap.core.packet import ParsedPacket


@dataclass
class TCPReassemblyBuffer:
    """
    Buffer for reassembling TCP stream data.

    Maintains sequence tracking for both directions.
    """

    flow_key: str  # Unique flow identifier
    up_buffer: bytearray = field(default_factory=bytearray)
    down_buffer: bytearray = field(default_factory=bytearray)
    up_seq: int | None = None
    down_seq: int | None = None
    up_ack: int | None = None
    down_ack: int | None = None
    up_next_seq: int = 0
    down_next_seq: int = 0

    # Out-of-order data storage
    up_ooo: dict[int, bytes] = field(default_factory=dict)
    down_ooo: dict[int, bytes] = field(default_factory=dict)

    # Statistics
    up_packets: int = 0
    down_packets: int = 0
    up_retrans: int = 0
    down_retrans: int = 0
    up_ooo_count: int = 0
    down_ooo_count: int = 0
    last_seen: float = field(default_factory=time.time)

    def add_data(
        self,
        seq: int,
        ack: int | None,
        data: bytes,
        is_forward: bool
    ) -> tuple[bytes, int, int]:
        """
        Add data to the appropriate buffer.

        Returns:
            (new_data, retrans_count, ooo_count)
        """
        self.last_seen = time.time()

        if is_forward:
            return self._add_to_buffer(
                seq, ack, data,
                self.up_buffer,
                self.up_seq,
                self.up_ack,
                self.up_next_seq,
                self.up_ooo
            )
        else:
            return self._add_to_buffer(
                seq, ack, data,
                self.down_buffer,
                self.down_seq,
                self.down_ack,
                self.down_next_seq,
                self.down_ooo
            )

    def _add_to_buffer(
        self,
        seq: int,
        ack: int | None,
        data: bytes,
        buffer: bytearray,
        init_seq: int | None,
        init_ack: int | None,
        next_seq: int,
        ooo: dict[int, bytes]
    ) -> tuple[bytes, int, int]:
        """Internal method to add data to buffer."""
        retrans_count = 0
        ooo_count = 0

        if not data:
            return b"", retrans_count, ooo_count

        # Initialize sequence tracking
        if init_seq is None:
            # This is the first segment for this direction
            # We need to determine which direction we're initializing
            # Use the buffer identity to know which direction
            if buffer is self.up_buffer:
                self.up_seq = seq
                self.up_next_seq = seq + len(data)
            else:
                self.down_seq = seq
                self.down_next_seq = seq + len(data)
            buffer.extend(data)
            return data, 0, 0

        seq_offset = seq - init_seq

        # Check if this is a retransmission (seq < next_seq)
        if seq_offset < next_seq:
            if seq_offset + len(data) <= next_seq:
                # Completely within already received data
                retrans_count += 1
                return b"", retrans_count, ooo_count
            else:
                # Partial retrans, new data at end
                new_data = data[next_seq - seq_offset:]
                buffer.extend(new_data)
                return new_data, retrans_count, ooo_count

        # Check if this is out of order (seq > next_seq)
        if seq_offset > next_seq:
            ooo[seq_offset] = data
            ooo_count += 1
            return b"", retrans_count, ooo_count

        # In-order data
        buffer.extend(data)

        # Check if we can fill in OOO gaps
        new_data = data
        current_next = next_seq + len(data)

        while True:
            if current_next in ooo:
                gap_data = ooo.pop(current_next)
                buffer.extend(gap_data)
                new_data += gap_data
                current_next += len(gap_data)
            else:
                break

        return new_data, retrans_count, ooo_count

    def get_up_data(self) -> bytes:
        """Get all forward direction data."""
        return bytes(self.up_buffer)

    def get_down_data(self) -> bytes:
        """Get all reverse direction data."""
        return bytes(self.down_buffer)

    def cleanup_ooo(self, max_wait: float = 10.0) -> int:
        """Remove old OOO data that hasn't been filled in."""
        current_time = time.time()
        to_remove = []

        for seq in self.up_ooo:
            if current_time - self.last_seen > max_wait:
                to_remove.append(seq)

        for seq in to_remove:
            del self.up_ooo[seq]

        return len(to_remove)


@dataclass
class TCPSegment:
    """TCP segment information."""
    seq: int
    ack: int | None
    flags: int
    data: bytes
    timestamp: float


class TCPStreamReassembler:
    """
    Reassembles TCP streams for protocol analysis.

    Tracks sequence numbers and handles out-of-order segments
    to provide complete application layer data.
    """

    def __init__(self, timeout: float = 300.0):
        self.timeout = timeout
        self._buffers: dict[str, TCPReassemblyBuffer] = {}
        self._last_cleanup: float = time.time()

    def get_or_create_buffer(self, flow_key: str) -> TCPReassemblyBuffer:
        """Get or create a reassembly buffer for a flow."""
        if flow_key not in self._buffers:
            self._buffers[flow_key] = TCPReassemblyBuffer(flow_key=flow_key)
        return self._buffers[flow_key]

    def add_packet(
        self,
        flow_key: str,
        seq: int,
        ack: int | None,
        flags: int,
        data: bytes,
        is_forward: bool,
        timestamp: float
    ) -> tuple[bytes, int, int]:
        """
        Add a TCP segment to the reassembly buffer.

        Returns:
            (new_data, retrans_count, ooo_count)
        """
        buffer = self.get_or_create_buffer(flow_key)

        # Check for SYN/FIN flags
        syn = bool(flags & 0x02)
        fin = bool(flags & 0x01)

        # SYN consumes one sequence number
        if syn:
            data = b'\x00' + data  # Placeholder for SYN

        # FIN consumes one sequence number
        if fin:
            data = data + b'\x00'  # Placeholder for FIN

        return buffer.add_data(seq, ack, data, is_forward)

    def process_packet(
        self,
        pkt: ParsedPacket,
        flow_key: str,
        is_forward: bool,
        tcp_payload: bytes | None = None
    ) -> bytes | None:
        """
        Process a packet through TCP reassembly.

        Args:
            pkt: Parsed packet with TCP layer
            flow_key: Unique flow identifier
            is_forward: True if packet is in forward direction
            tcp_payload: TCP payload data (required, extracted from packet)

        Returns:
            New data if available, None otherwise
        """
        if not pkt.tcp:
            return None

        tcp = pkt.tcp

        # Use provided TCP payload (extracted from packet's tcp.data)
        if tcp_payload is None:
            # No payload data provided
            return None

        new_data, retrans, ooo = self.add_packet(
            flow_key,
            tcp.seq,
            tcp.ack_num if tcp.ack else None,
            tcp.flags,
            tcp_payload,
            is_forward,
            pkt.timestamp
        )

        return new_data if new_data else None

    def get_stream_data(self, flow_key: str) -> tuple[bytes, bytes]:
        """Get (up_data, down_data) for a flow."""
        if flow_key not in self._buffers:
            return b"", b""

        buffer = self._buffers[flow_key]
        return buffer.get_up_data(), buffer.get_down_data()

    def cleanup(self, force: bool = False) -> int:
        """
        Clean up old reassembly buffers.

        Args:
            force: If True, clean all buffers regardless of timeout

        Returns:
            Number of buffers cleaned up
        """
        current_time = time.time()
        to_remove = []

        for key, buffer in self._buffers.items():
            if force or (current_time - buffer.last_seen > self.timeout):
                to_remove.append(key)

        for key in to_remove:
            del self._buffers[key]

        return len(to_remove)

    def get_buffer(self, flow_key: str) -> TCPReassemblyBuffer | None:
        """Get a reassembly buffer by flow key."""
        return self._buffers.get(flow_key)

    def remove_buffer(self, flow_key: str) -> bool:
        """Remove a reassembly buffer."""
        if flow_key in self._buffers:
            del self._buffers[flow_key]
            return True
        return False

    @property
    def buffer_count(self) -> int:
        """Number of active reassembly buffers."""
        return len(self._buffers)

    def clear(self) -> None:
        """Clear all reassembly buffers."""
        self._buffers.clear()

    def get_stats(self) -> dict:
        """Get reassembly statistics."""
        stats = {
            'active_buffers': len(self._buffers),
            'total_up_packets': 0,
            'total_down_packets': 0,
            'total_retrans': 0,
            'total_ooo': 0,
        }

        for buffer in self._buffers.values():
            stats['total_up_packets'] += buffer.up_packets
            stats['total_down_packets'] += buffer.down_packets
            stats['total_retrans'] += buffer.up_retrans + buffer.down_retrans
            stats['total_ooo'] += buffer.up_ooo_count + buffer.down_ooo_count

        return stats
