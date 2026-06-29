/**
 * seq_flow.h  ——  每条流序列特征（Header-Only，nvers 动态包数版）
 *
 * 采集序列（包数由运行时 -n 控制，0=全流）：
 *   direction, pkt_len, pay_len, iat_us, ts_rel_us, tcp_flags, tls_type, burst
 *
 * 输出：JSON Lines（.log），每行一条流记录。
 */
#pragma once

#include "flow_limit.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>

// ============================================================
// TLS 包类型编码（第一条 TLS 记录类型；0 表示非 TLS）
// ============================================================
enum TlsPktType : uint8_t {
    TLS_NONE              = 0,
    TLS_CLIENT_HELLO      = 1,
    TLS_SERVER_HELLO      = 2,
    TLS_CERTIFICATE       = 3,
    TLS_SERVER_KEY_EX     = 4,
    TLS_CERT_REQUEST      = 5,
    TLS_SERVER_HELLO_DONE = 6,
    TLS_CERT_VERIFY       = 7,
    TLS_CLIENT_KEY_EX     = 8,
    TLS_FINISHED          = 9,
    TLS_NEW_SESSION_TICKET= 10,
    TLS_CHANGE_CIPHER     = 11,
    TLS_ALERT             = 12,
    TLS_APP_DATA          = 13,
    TLS_HEARTBEAT         = 14,
    TLS_OTHER_HANDSHAKE   = 15,
};

inline const char* tls_type_name(uint8_t t) {
    static const char* names[] = {
        "none","ClientHello","ServerHello","Certificate",
        "ServerKeyEx","CertRequest","ServerHelloDone","CertVerify",
        "ClientKeyEx","Finished","NewSessionTicket",
        "ChangeCipher","Alert","AppData","Heartbeat","OtherHandshake"
    };
    return (t < 16) ? names[t] : "unknown";
}

inline uint8_t detect_tls_type(const uint8_t* pay, int pay_len) noexcept {
    if (pay_len < 6) return TLS_NONE;
    uint8_t  ct  = pay[0];
    uint16_t ver = (uint16_t)((pay[1] << 8) | pay[2]);
    if (ct < 20 || ct > 24) return TLS_NONE;
    if (ver < 0x0200 || ver > 0x0305) return TLS_NONE;
    if (ct == 20) return TLS_CHANGE_CIPHER;
    if (ct == 21) return TLS_ALERT;
    if (ct == 23) return TLS_APP_DATA;
    if (ct == 24) return TLS_HEARTBEAT;
    if (pay_len < 6) return TLS_OTHER_HANDSHAKE;
    switch (pay[5]) {
    case  1: return TLS_CLIENT_HELLO;
    case  2: return TLS_SERVER_HELLO;
    case  4: return TLS_NEW_SESSION_TICKET;
    case 11: return TLS_CERTIFICATE;
    case 12: return TLS_SERVER_KEY_EX;
    case 13: return TLS_CERT_REQUEST;
    case 14: return TLS_SERVER_HELLO_DONE;
    case 15: return TLS_CERT_VERIFY;
    case 16: return TLS_CLIENT_KEY_EX;
    case 20: return TLS_FINISHED;
    default: return TLS_OTHER_HANDSHAKE;
    }
}

struct SeqFlowRecord {
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

    std::vector<int8_t>   direction;
    std::vector<uint16_t> pkt_len;
    std::vector<uint16_t> pay_len;
    std::vector<uint32_t> iat_us;
    std::vector<uint32_t> ts_rel_us;
    std::vector<uint8_t>  tcp_flags;
    std::vector<uint8_t>  tls_type;
    std::vector<int32_t>  burst;
    int      n_bursts = 0;

    int8_t   _cur_burst_dir = 0;
    uint32_t _cur_burst_cnt = 0;

    void init(const char* fid, uint8_t pr, int limit,
              uint32_t sip, uint32_t dip,
              uint16_t sport, uint16_t dport) noexcept {
        direction.clear(); pkt_len.clear(); pay_len.clear();
        iat_us.clear(); ts_rel_us.clear();
        tcp_flags.clear(); tls_type.clear(); burst.clear();
        memset(flow_id, 0, sizeof flow_id);
        strncpy(flow_id, fid, sizeof(flow_id) - 1);
        proto = pr;
        n_limit = limit;
        src_port = sport;
        dst_port = dport;
        first_ts = last_ts = 0.0;
        n_pkts = n_bursts = 0;
        _cur_burst_dir = 0;
        _cur_burst_cnt = 0;
        in_addr sa{sip}, da{dip};
        inet_ntop(AF_INET, &sa, src_ip, sizeof src_ip);
        inet_ntop(AF_INET, &da, dst_ip, sizeof dst_ip);
    }

    inline void add_packet(bool is_fwd, double ts,
                           uint16_t ip_len, uint16_t payload_len,
                           uint8_t flags, uint8_t tls_t) noexcept {
        if (flow_limit_reached((uint32_t)n_pkts, n_limit)) return;

        if (n_pkts == 0) {
            first_ts = ts;
            iat_us.push_back(0);
            ts_rel_us.push_back(0);
        } else {
            double delta = ts - last_ts;
            if (delta < 0) delta = 0;
            iat_us.push_back((uint32_t)(delta * 1e6 + 0.5));
            double rel = ts - first_ts;
            if (rel < 0) rel = 0;
            ts_rel_us.push_back((uint32_t)(rel * 1e6 + 0.5));
        }
        last_ts = ts;

        int8_t dir = is_fwd ? +1 : -1;
        direction.push_back(dir);
        pkt_len.push_back(ip_len);
        pay_len.push_back(payload_len);
        tcp_flags.push_back(flags);
        tls_type.push_back(tls_t);
        n_pkts++;

        if (_cur_burst_dir == dir) {
            _cur_burst_cnt++;
        } else {
            if (_cur_burst_dir != 0) {
                burst.push_back((int32_t)_cur_burst_dir * (int32_t)_cur_burst_cnt);
                n_bursts++;
            }
            _cur_burst_dir = dir;
            _cur_burst_cnt = 1;
        }
    }

    inline void flush_burst() noexcept {
        if (_cur_burst_dir != 0) {
            burst.push_back((int32_t)_cur_burst_dir * (int32_t)_cur_burst_cnt);
            n_bursts++;
            _cur_burst_dir = 0;
            _cur_burst_cnt = 0;
        }
    }

    static void json_str(FILE* f, const char* s) {
        fputc('"', f);
        for (; *s; s++) {
            unsigned char c = (unsigned char)*s;
            if (c == '"' || c == '\\') fputc('\\', f);
            fputc((int)c, f);
        }
        fputc('"', f);
    }

    template<typename T>
    static void json_int_list(FILE* f, const T* arr, int n) {
        fputc('[', f);
        for (int i = 0; i < n; i++) {
            if (i) fputc(',', f);
            fprintf(f, "%d", (int)arr[i]);
        }
        fputc(']', f);
    }

    static void json_i32_list(FILE* f, const int32_t* arr, int n) {
        fputc('[', f);
        for (int i = 0; i < n; i++) {
            if (i) fputc(',', f);
            fprintf(f, "%d", arr[i]);
        }
        fputc(']', f);
    }

    void emit_json(FILE* f, const char* pcap_file) const {
        fprintf(f, "{\"file\":");
        json_str(f, pcap_file);
        fprintf(f, ",\"flow_id\":");
        json_str(f, flow_id);
        fprintf(f, ",\"five_tuple\":{\"src_ip\":");
        json_str(f, src_ip);
        fprintf(f, ",\"src_port\":%u,\"dst_ip\":", (unsigned)src_port);
        json_str(f, dst_ip);
        fprintf(f, ",\"dst_port\":%u,\"proto\":%u}", (unsigned)dst_port, (unsigned)proto);
        fprintf(f, ",\"first_ts\":%.6f,\"last_ts\":%.6f,\"n_pkts\":%d", first_ts, last_ts, n_pkts);
        fprintf(f, ",\"sequences\":{");
        fprintf(f, "\"direction\":");
        json_int_list(f, direction.data(), n_pkts);
        fprintf(f, ",\"pkt_len\":");
        json_int_list(f, pkt_len.data(), n_pkts);
        fprintf(f, ",\"pay_len\":");
        json_int_list(f, pay_len.data(), n_pkts);
        fprintf(f, ",\"iat_us\":");
        json_int_list(f, iat_us.data(), n_pkts);
        fprintf(f, ",\"ts_rel_us\":");
        json_int_list(f, ts_rel_us.data(), n_pkts);
        fprintf(f, ",\"tcp_flags\":");
        json_int_list(f, tcp_flags.data(), n_pkts);
        fprintf(f, ",\"tls_type\":");
        json_int_list(f, tls_type.data(), n_pkts);
        fprintf(f, ",\"burst\":");
        json_i32_list(f, burst.data(), n_bursts);
        fprintf(f, "}}\n");
    }
};
