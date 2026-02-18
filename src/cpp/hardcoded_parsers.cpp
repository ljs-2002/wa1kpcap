#include "hardcoded_parsers.h"
#include "util.h"

#include <algorithm>

namespace hardcoded {

// ── DNS name decompression ──

DnsNameResult parse_dns_name(const uint8_t* pkt_base, size_t pkt_len,
                             const uint8_t* ptr, size_t max_len) {
    DnsNameResult result;
    result.bytes_consumed = 0;

    std::string name;
    const uint8_t* cur = ptr;
    const uint8_t* end = ptr + max_len;
    bool jumped = false;
    size_t consumed = 0;
    int jumps = 0;
    const int MAX_JUMPS = 64; // prevent infinite loops

    while (cur < end && jumps < MAX_JUMPS) {
        uint8_t label_len = *cur;

        if (label_len == 0) {
            // End of name
            if (!jumped) consumed = static_cast<size_t>(cur - ptr) + 1;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            // Compression pointer
            if (cur + 1 >= pkt_base + pkt_len) break;
            if (!jumped) consumed = static_cast<size_t>(cur - ptr) + 2;
            uint16_t offset = ((label_len & 0x3F) << 8) | *(cur + 1);
            if (offset >= pkt_len) break;
            cur = pkt_base + offset;
            jumped = true;
            jumps++;
            continue;
        }

        // Normal label
        cur++;
        if (cur + label_len > pkt_base + pkt_len) break;

        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(cur), label_len);
        cur += label_len;
    }

    if (!jumped && consumed == 0) {
        consumed = static_cast<size_t>(cur - ptr);
    }

    result.name = std::move(name);
    result.bytes_consumed = consumed;
    return result;
}

// ── BSD loopback AF ──

uint32_t parse_bsd_loopback_af(const uint8_t* buf, size_t len) {
    if (len < 4) return 0;

    // Host byte order (native endian)
    uint32_t af;
    std::memcpy(&af, buf, 4);

    // If value looks too large, try swapping
    if (af > 255) {
        af = ((af >> 24) & 0xFF) |
             ((af >> 8) & 0xFF00) |
             ((af << 8) & 0xFF0000) |
             ((af << 24) & 0xFF000000);
    }

    // Map AF to EtherType-like values for next_protocol mapping
    // AF_INET = 2 -> 0x0800 (IPv4)
    // AF_INET6 = 10/24/28/30 -> 0x86DD (IPv6)
    if (af == 2) return 0x0800;
    if (af == 10 || af == 24 || af == 28 || af == 30) return 0x86DD;
    return af;
}

// ── NFLOG payload ──

NflogPayload parse_nflog_payload(const uint8_t* buf, size_t len) {
    NflogPayload result{0, 0, false};

    // NFLOG header: 1 byte af, 1 byte version, 2 bytes resource_id
    if (len < 4) return result;
    size_t offset = 4;

    // Walk TLV attributes
    while (offset + 4 <= len) {
        uint16_t attr_len = util::read_u16_le(buf + offset);
        uint16_t attr_type = util::read_u16_le(buf + offset + 2);

        // Mask out NLA_F_NESTED and NLA_F_NET_BYTEORDER
        uint16_t clean_type = attr_type & 0x7FFF;

        if (attr_len < 4) break;

        // NFULA_PAYLOAD = 9
        if (clean_type == 9) {
            result.offset = offset + 4;
            result.length = attr_len - 4;
            result.found = true;
            return result;
        }

        // Align to 4 bytes
        size_t padded = (attr_len + 3) & ~3u;
        offset += padded;
    }

    return result;
}

} // namespace hardcoded
