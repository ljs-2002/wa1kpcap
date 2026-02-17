"""
Native C++ engine for wa1kpcap.

Provides optional high-performance pcap reading, protocol parsing,
and BPF filtering via a pybind11-based C++ extension.
"""

NATIVE_AVAILABLE = False
_wa1kpcap_native = None

try:
    from wa1kpcap import _wa1kpcap_native as _mod
    _wa1kpcap_native = _mod
    NATIVE_AVAILABLE = True
except ImportError:
    pass
