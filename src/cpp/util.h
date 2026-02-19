#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <array>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

namespace util {

inline uint16_t read_u16_be(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

inline uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           p[3];
}

inline uint16_t read_u16_le(const uint8_t* p) {
    return p[0] | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t read_u32_le(const uint8_t* p) {
    return p[0] |
           (static_cast<uint32_t>(p[1]) << 8)  |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_u64_le(const uint8_t* p) {
    return static_cast<uint64_t>(read_u32_le(p)) |
           (static_cast<uint64_t>(read_u32_le(p + 4)) << 32);
}

inline std::string format_ipv4(const uint8_t* p) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return buf;
}

inline std::string format_ipv6(const uint8_t* p) {
    char buf[64];
    // Use inet_ntop for proper IPv6 formatting
    if (inet_ntop(AF_INET6, p, buf, sizeof(buf))) {
        return buf;
    }
    // Fallback: manual hex formatting
    snprintf(buf, sizeof(buf),
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
        p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    return buf;
}

inline std::string format_mac(const uint8_t* p) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             p[0], p[1], p[2], p[3], p[4], p[5]);
    return buf;
}

inline std::string format_hex(const uint8_t* p, size_t len) {
    std::string result;
    result.reserve(len * 3);
    char buf[4];
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) result += ':';
        snprintf(buf, sizeof(buf), "%02x", p[i]);
        result += buf;
    }
    return result;
}

} // namespace util
