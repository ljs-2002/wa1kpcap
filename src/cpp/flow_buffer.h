#pragma once

#include "protocol_engine.h"
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>
#include <cstdint>
#include <string>

namespace py = pybind11;

// FlowBuffer: bridge between Python TCP reassembly and C++ application-layer parsing.
// Python appends reassembled bytes, C++ parses application protocols from the buffer.
class FlowBuffer {
public:
    FlowBuffer() = default;

    // Append reassembled bytes from Python
    void append(const uint8_t* buf, size_t len);

    // Number of unparsed bytes available
    size_t available() const;

    // Try to parse application layer protocol from buffer.
    // Returns parsed dict (may be empty if not enough data).
    // Advances parse_offset_ on success.
    py::dict try_parse_app(const NativeParser& engine, const std::string& protocol);

    // Clear buffer
    void clear();

private:
    std::vector<uint8_t> data_;
    size_t parse_offset_ = 0;
};
