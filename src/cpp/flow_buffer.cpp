#include "flow_buffer.h"

void FlowBuffer::append(const uint8_t* buf, size_t len) {
    data_.insert(data_.end(), buf, buf + len);
}

size_t FlowBuffer::available() const {
    return (parse_offset_ < data_.size()) ? (data_.size() - parse_offset_) : 0;
}

py::dict FlowBuffer::try_parse_app(const NativeParser& engine, const std::string& protocol) {
    if (available() == 0) return py::dict();

    const uint8_t* buf = data_.data() + parse_offset_;
    size_t len = available();

    // Use the engine's internal protocol engine to parse
    // We need to parse just the application layer protocol, not a full packet
    // So we call parse_packet with a fake link_type that maps directly to the protocol
    // Instead, we use the engine's loader to parse a single layer

    // Access the underlying ProtocolEngine through NativeParser
    // For simplicity, we parse the buffer as if it were a raw protocol
    // The protocol name should be something like "tls_record"

    // We'll use a special approach: create a temporary dict with just the protocol data
    // and let the engine parse it

    // Actually, the simplest approach is to expose parse_layer through NativeParser
    // For now, we'll try to parse and check if we consumed any bytes

    // Try to parse the buffer as the given protocol
    try {
        // We need at least some minimum data for most protocols
        if (protocol == "tls_record" && len < 5) {
            return py::dict(); // TLS record header is 5 bytes minimum
        }

        // For TLS record: check if we have the full record
        if (protocol == "tls_record" && len >= 5) {
            uint16_t record_len = (buf[3] << 8) | buf[4];
            if (len < static_cast<size_t>(5 + record_len)) {
                return py::dict(); // Not enough data for full record
            }
        }

        // Parse using the engine
        py::bytes pybuf(reinterpret_cast<const char*>(buf), len);
        // We use link_type=0xFFFF as a sentinel that means "parse directly as protocol"
        // This requires special handling in the engine
        // For now, just parse the bytes directly
        auto result = const_cast<NativeParser&>(engine).parse_packet(pybuf, 0xFFFF, false);

        if (result.size() > 0) {
            // Advance parse offset
            // Try to determine how many bytes were consumed
            // For TLS record, it's 5 + record_length
            if (protocol == "tls_record" && len >= 5) {
                uint16_t record_len = (buf[3] << 8) | buf[4];
                parse_offset_ += 5 + record_len;
            } else {
                // Consume all available
                parse_offset_ = data_.size();
            }
            return result;
        }
    } catch (...) {
        // Parse failed — not enough data or invalid
    }

    return py::dict();
}

void FlowBuffer::clear() {
    data_.clear();
    parse_offset_ = 0;
}
