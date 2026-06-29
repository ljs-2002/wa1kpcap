/**
 * payload_flow.h  ——  每条流 TCP/UDP 负载（nvers 动态包数 + JSON Lines）
 */
#pragma once

#include "flow_limit.h"
#include "json_log.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>

#ifndef PAY_MAX_BYTES
#  define PAY_MAX_BYTES 256
#endif

static constexpr int PAY_BUF_SIZE = PAY_MAX_BYTES;

struct PayloadPkt {
    int8_t   direction;
    uint32_t ts_rel_us;
    uint16_t ip_len;
    uint16_t pay_len;
    uint16_t cap_bytes;
    uint8_t  data[PAY_BUF_SIZE];
};

struct PayloadFlowRecord {
    char     flow_id[96];
    char     src_ip[INET_ADDRSTRLEN];
    char     dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    int      n_limit = FLOW_LIMIT_ALL;
    double   first_ts;
    double   last_ts;
    int      n_pkts;
    std::vector<PayloadPkt> pkts;
    bool     _initialized = false;

    void init(const char* fid, uint8_t pr, int limit,
              uint32_t sip, uint32_t dip,
              uint16_t sport, uint16_t dport) noexcept {
        memset(flow_id, 0, sizeof flow_id);
        strncpy(flow_id, fid, sizeof(flow_id) - 1);
        proto = pr;
        n_limit = limit;
        src_port = sport;
        dst_port = dport;
        first_ts = last_ts = 0.0;
        n_pkts = 0;
        pkts.clear();
        _initialized = true;
        in_addr sa{sip}, da{dip};
        inet_ntop(AF_INET, &sa, src_ip, sizeof src_ip);
        inet_ntop(AF_INET, &da, dst_ip, sizeof dst_ip);
    }

    inline void add_packet(bool is_fwd, double ts,
                           uint16_t ip_len, uint16_t pay_len_raw,
                           const uint8_t* pay_ptr, uint32_t available) noexcept {
        if (flow_limit_reached((uint32_t)n_pkts, n_limit)) return;

        if (n_pkts == 0) first_ts = ts;
        double rel = ts - first_ts;
        if (rel < 0) rel = 0;
        last_ts = ts;

        PayloadPkt p{};
        p.direction = is_fwd ? +1 : -1;
        p.ts_rel_us = (uint32_t)(rel * 1e6 + 0.5);
        p.ip_len    = ip_len;
        p.pay_len   = pay_len_raw;
        p.cap_bytes = (uint16_t)(available < (uint32_t)PAY_BUF_SIZE
                                 ? available : (uint32_t)PAY_BUF_SIZE);
        if (p.cap_bytes > pay_len_raw) p.cap_bytes = pay_len_raw;
        if (pay_ptr && p.cap_bytes > 0)
            memcpy(p.data, pay_ptr, p.cap_bytes);
        pkts.push_back(p);
        n_pkts++;
    }

    void emit_json(FILE* f, const char* pcap_file) const {
        fprintf(f, "{\"file\":");
        json_esc_cstr(f, pcap_file);
        fprintf(f, ",\"flow_id\":");
        json_esc_cstr(f, flow_id);
        fprintf(f, ",");
        json_five_tuple(f, src_ip, src_port, dst_ip, dst_port, proto);
        fprintf(f, ",\"first_ts\":%.6f,\"last_ts\":%.6f,\"n_pkts\":%d,\"packets\":[",
                first_ts, last_ts, n_pkts);

        static char hex_buf[PAY_BUF_SIZE * 2 + 1];
        for (int i = 0; i < n_pkts; i++) {
            if (i) fputc(',', f);
            const PayloadPkt& p = pkts[(size_t)i];
            int hlen = 0;
            for (int b = 0; b < p.cap_bytes; b++) {
                hlen += snprintf(hex_buf + hlen, sizeof(hex_buf) - hlen,
                                 "%02x", (unsigned)p.data[b]);
            }
            hex_buf[hlen] = '\0';
            fprintf(f, "{\"idx\":%d,\"direction\":%d,\"ts_rel_us\":%u,"
                    "\"ip_len\":%u,\"pay_len\":%u,\"cap_bytes\":%u,\"payload_hex\":",
                    i, (int)p.direction, p.ts_rel_us,
                    (unsigned)p.ip_len, (unsigned)p.pay_len, (unsigned)p.cap_bytes);
            json_esc_cstr(f, hex_buf);
            fputc('}', f);
        }
        fprintf(f, "]}\n");
    }
};
