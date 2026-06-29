/**
 * protocol_common.h — shared helpers for L7 protocol extractors
 */
#pragma once

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

struct ProtoFlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;

    bool operator==(const ProtoFlowKey& o) const noexcept {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port && proto == o.proto;
    }

    ProtoFlowKey canonical() const noexcept {
        if (src_ip < dst_ip) return *this;
        if (src_ip > dst_ip) return {dst_ip, src_ip, dst_port, src_port, proto};
        if (src_port <= dst_port) return *this;
        return {dst_ip, src_ip, dst_port, src_port, proto};
    }

    std::string id() const {
        char buf[96];
        in_addr s{src_ip}, d{dst_ip};
        char ss[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s, ss, sizeof ss);
        inet_ntop(AF_INET, &d, ds, sizeof ds);
        snprintf(buf, sizeof buf, "%s:%u-%s:%u/%u", ss, src_port, ds, dst_port, proto);
        return buf;
    }
};

struct ProtoFlowKeyHash {
    size_t operator()(const ProtoFlowKey& k) const noexcept {
        auto h = [](uint64_t x) {
            x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
            x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33; return x;
        };
        return (size_t)(h((uint64_t)k.src_ip | ((uint64_t)k.dst_ip << 32)) ^
                        h((uint64_t)k.src_port | ((uint64_t)k.dst_port << 16) | ((uint64_t)k.proto << 32)));
    }
};

inline bool is_http_port(uint16_t p) {
    return p == 80 || p == 8080 || p == 8000 || p == 8888 || p == 8008;
}

inline bool is_ssh_port(uint16_t p) { return p == 22; }

inline bool is_mqtt_port(uint16_t p) {
    return p == 1883 || p == 8883 || p == 1884;
}

inline bool is_sip_port(uint16_t p) { return p == 5060 || p == 5061; }

inline bool is_rdp_port(uint16_t p) { return p == 3389; }

inline bool is_vnc_port(uint16_t p) { return p >= 5900 && p <= 5999; }

inline bool is_quic_port(uint16_t p) { return p == 443 || p == 80 || p == 8443; }

inline bool parse_l4(const uint8_t* pkt, uint32_t caplen,
                     uint32_t& sip, uint32_t& dip, uint16_t& sp, uint16_t& dp,
                     uint8_t& proto, const uint8_t*& l4, uint32_t& l4rem) {
    if (caplen < 14) return false;
    uint16_t etype = (uint16_t)((pkt[12] << 8) | pkt[13]);
    const uint8_t* ip = pkt + 14;
    uint32_t rem = caplen - 14;
    while (etype == 0x8100 && rem >= 4) {
        etype = (uint16_t)((ip[2] << 8) | ip[3]);
        ip += 4; rem -= 4;
    }
    if (etype != 0x0800 || rem < 20) return false;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    proto = ip[9];
    if (ihl < 20 || rem < ihl) return false;
    if (proto != 6 && proto != 17) return false;
    sip = *(const uint32_t*)(ip + 12);
    dip = *(const uint32_t*)(ip + 16);
    l4 = ip + ihl;
    l4rem = rem - ihl;
    if (l4rem < 4) return false;
    sp = (uint16_t)((l4[0] << 8) | l4[1]);
    dp = (uint16_t)((l4[2] << 8) | l4[3]);
    return true;
}

inline bool tcp_payload(const uint8_t* l4, uint32_t l4rem,
                        const uint8_t*& pay, int& plen) {
    if (l4rem < 20) return false;
    uint8_t th = (l4[12] >> 4) * 4;
    if (l4rem < th) return false;
    pay = l4 + th;
    plen = (int)(l4rem - th);
    return plen > 0;
}

inline bool udp_payload(const uint8_t* l4, uint32_t l4rem,
                        const uint8_t*& pay, int& plen) {
    if (l4rem < 8) return false;
    pay = l4 + 8;
    plen = (int)(l4rem - 8);
    return plen > 0;
}
