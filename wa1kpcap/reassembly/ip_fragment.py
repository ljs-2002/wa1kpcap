"""
IP fragment reassembly engine.

Reassembles fragmented IP packets based on RFC 791.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
import time

if TYPE_CHECKING:
    from wa1kpcap.core.packet import ParsedPacket


@dataclass
class FragmentKey:
    """Key for identifying fragments belonging to the same packet."""
    src_ip: str
    dst_ip: str
    protocol: int
    ip_id: int

    def __hash__(self) -> int:
        return hash((self.src_ip, self.dst_ip, self.protocol, self.ip_id))

    def __eq__(self, other) -> bool:
        if not isinstance(other, FragmentKey):
            return False
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.protocol == other.protocol and
                self.ip_id == other.ip_id)


@dataclass
class Fragment:
    """IP fragment data."""
    offset: int  # Fragment offset in 8-byte units
    data: bytes
    is_last: bool = False  # MF (more fragments) flag cleared


@dataclass
class ReassemblyBuffer:
    """Buffer for reassembling fragments."""
    key: FragmentKey
    fragments: list[Fragment] = field(default_factory=list)
    total_size: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def add_fragment(self, offset: int, data: bytes, is_last: bool = False) -> bool:
        """Add a fragment to the buffer."""
        self.last_seen = time.time()

        # Check for duplicate offset
        for frag in self.fragments:
            if frag.offset == offset:
                return False  # Duplicate, don't add

        frag = Fragment(offset=offset, data=data, is_last=is_last)
        self.fragments.append(frag)
        return True

    def is_complete(self) -> bool:
        """Check if all fragments have been received."""
        if not self.fragments:
            return False

        has_last = any(f.is_last for f in self.fragments)
        if not has_last:
            return False

        # Sort by offset and check for gaps
        sorted_frags = sorted(self.fragments, key=lambda f: f.offset)

        expected_offset = 0
        for frag in sorted_frags:
            if frag.offset > expected_offset:
                return False  # Gap detected
            # Fragment length in offset units (8 bytes)
            frag_len_units = (len(frag.data) + 7) // 8
            expected_offset = frag.offset + frag_len_units

        return True

    def reassemble(self) -> bytes | None:
        """Reassemble fragments into complete packet."""
        if not self.is_complete():
            return None

        sorted_frags = sorted(self.fragments, key=lambda f: f.offset)

        # Calculate total size
        total_size = sum(len(f.data) for f in sorted_frags)

        # Allocate buffer and copy data
        result = bytearray(total_size)
        for frag in sorted_frags:
            start = frag.offset * 8
            end = start + len(frag.data)
            result[start:end] = frag.data

        return bytes(result)

    def cleanup_timeout(self, timeout: float) -> bool:
        """Check if buffer has timed out."""
        return time.time() - self.first_seen > timeout


class IPFragmentReassembler:
    """
    Reassembles fragmented IP packets.

    Implements fragment reassembly per RFC 791 with timeout handling.
    """

    def __init__(self, timeout: float = 60.0, max_fragments: int = 1000):
        self.timeout = timeout
        self.max_fragments = max_fragments
        # Use a regular dict, not defaultdict, since ReassemblyBuffer requires key
        self._buffers: dict[FragmentKey, ReassemblyBuffer] = {}
        self._reassembled_count = int = 0
        self._incomplete_count: int = 0
        self._timeout_count: int = 0

    def add_fragment(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        ip_id: int,
        offset: int,
        data: bytes,
        is_last: bool = False
    ) -> tuple[bytes | None, bool]:
        """
        Add a fragment and return reassembled data if complete.

        Returns:
            (reassembled_data, is_complete)
        """
        key = FragmentKey(src_ip, dst_ip, protocol, ip_id)

        # Check if we have too many fragments pending
        if len(self._buffers) > self.max_fragments:
            self._cleanup_old()

        # Get or create buffer
        if key not in self._buffers:
            self._buffers[key] = ReassemblyBuffer(key=key)
        buffer = self._buffers[key]
        added = buffer.add_fragment(offset, data, is_last)

        if not added:
            # Duplicate fragment
            if buffer.is_complete():
                return buffer.reassemble(), True
            return None, False

        if buffer.is_complete():
            reassembled = buffer.reassemble()
            if reassembled:
                self._reassembled_count += 1
                del self._buffers[key]
                return reassembled, True

        return None, False

    def add_packet(self, pkt: ParsedPacket) -> tuple[bytes | None, bool]:
        """
        Add a packet to fragment reassembly.

        Returns:
            (reassembled_data, is_complete) or (None, False) if not fragmented
        """
        ip = pkt.ip
        if not ip:
            return None, False

        # Check if this is a fragment
        if not ip.is_fragment:
            return None, False  # Not a fragment

        # Extract fragment info
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto
        ip_id = ip.id
        offset = ip.offset

        # Check if more fragments coming
        is_last = not ip.more_fragments

        # Get payload (data after IP header)
        ip_header_len = (ip._hdr_len if hasattr(ip, '_hdr_len') else 20)
        payload = pkt.raw_data[ip_header_len:]

        return self.add_fragment(src_ip, dst_ip, protocol, ip_id, offset, payload, is_last)

    def process_packet(self, pkt: ParsedPacket) -> bytes | None:
        """
        Process a packet through reassembly.

        Returns:
            Reassembled payload if complete, original payload if not fragmented,
            None if fragment but not complete
        """
        ip = pkt.ip
        if not ip:
            return pkt.payload

        if not ip.is_fragment:
            return pkt.payload

        reassembled, is_complete = self.add_packet(pkt)

        if is_complete and reassembled:
            return reassembled

        return None  # Fragment not complete yet

    def _cleanup_old(self) -> int:
        """Remove timed-out fragment buffers."""
        to_remove = []

        for key, buffer in self._buffers.items():
            if buffer.cleanup_timeout(self.timeout):
                to_remove.append(key)
                self._timeout_count += 1
                self._incomplete_count += 1

        for key in to_remove:
            del self._buffers[key]

        return len(to_remove)

    def cleanup(self) -> int:
        """Force cleanup of timed-out buffers."""
        return self._cleanup_old()

    def clear(self) -> None:
        """Clear all reassembly buffers."""
        self._buffers.clear()

    @property
    def pending_count(self) -> int:
        """Number of pending reassembly buffers."""
        return len(self._buffers)

    @property
    def stats(self) -> dict:
        """Get reassembly statistics."""
        return {
            'reassembled': self._reassembled_count,
            'incomplete': self._incomplete_count,
            'timeout': self._timeout_count,
            'pending': self.pending_count
        }

    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self._reassembled_count = 0
        self._incomplete_count = 0
        self._timeout_count = 0
