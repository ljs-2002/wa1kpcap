#pragma once

#include "field_value.h"
#include <cstdint>
#include <string>

// Hardcoded parsers for special protocol fields that can't be expressed
// with the 8 generic primitives.

namespace hardcoded {

// DNS name decompression (handles compression pointers)
// Returns the decoded domain name and number of bytes consumed from buf.
struct DnsNameResult {
    std::string name;
    size_t bytes_consumed;
};
DnsNameResult parse_dns_name(const uint8_t* pkt_base, size_t pkt_len,
                             const uint8_t* ptr, size_t max_len);

// BSD loopback address family (host byte order 4-byte value)
// Returns the EtherType-equivalent value for next_protocol mapping.
uint32_t parse_bsd_loopback_af(const uint8_t* buf, size_t len);

// NFLOG payload extraction: walk TLV attributes to find type=9 (NFULA_PAYLOAD)
// Returns offset and length of the payload within buf.
struct NflogPayload {
    size_t offset;
    size_t length;
    bool found;
};
NflogPayload parse_nflog_payload(const uint8_t* buf, size_t len);

} // namespace hardcoded
