/**
 * dhcp_flow.h  ——  DHCP/BOOTP 元特征提取（Header-Only）
 *
 * UDP 67（服务端）/ 68（客户端）
 * 解析固定头 + 常用选项（53 消息类型、1 掩码、3 路由器、6 DNS、12 主机名、
 * 15 域、50 请求地址、51 租期、54 服务器标识、55 参数列表、60 厂商类别、61 客户端标识）
 * 输出：JSON Lines，每行一条流（按事务 xid + 参与端点聚合）。
 */
#pragma once

#include "json_log.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

static constexpr int DHCP_MAX_MSGS = 64;

static inline bool is_dhcp_port(uint16_t p) {
    return p == 67 || p == 68;
}

static inline const char* dhcp_msg_type_name(uint8_t t) {
    switch (t) {
    case 1:  return "DISCOVER";
    case 2:  return "OFFER";
    case 3:  return "REQUEST";
    case 4:  return "DECLINE";
    case 5:  return "ACK";
    case 6:  return "NAK";
    case 7:  return "RELEASE";
    case 8:  return "INFORM";
    default: return "UNKNOWN";
    }
}

struct DhcpMsgInfo {
    double   ts;
    uint8_t  op;           /* 1=request 2=reply */
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    char     chaddr_hex[48];
    uint8_t  msg_type;     /* option 53 */
    uint32_t requested_ip; /* option 50 */
    uint32_t server_id;    /* option 54 */
    uint32_t lease_time;   /* option 51 */
    uint32_t subnet_mask;  /* option 1 */
    uint32_t router;       /* option 3 */
    char     hostname[256];    /* option 12 */
    char     domain[256];      /* option 15 */
    char     vendor_class[256];/* option 60 */
    bool     has_hostname;
    bool     has_vendor;
    bool     broadcast;
};

struct DhcpFlowRecord {
    char     flow_id[96];
    char     src_ip[INET_ADDRSTRLEN];
    char     dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    double   first_ts;
    double   last_ts;

    DhcpMsgInfo msgs[DHCP_MAX_MSGS];
    int         n_msgs;

    uint32_t discover_cnt;
    uint32_t offer_cnt;
    uint32_t request_cnt;
    uint32_t ack_cnt;
    uint32_t nak_cnt;
    uint32_t release_cnt;
    char     client_mac[48];
    char     last_hostname[256];
    char     last_vendor[256];
    uint32_t assigned_ip;
    uint32_t server_ip;

    void init(const char* fid, uint8_t pr,
              uint32_t sip, uint32_t dip,
              uint16_t sport, uint16_t dport) noexcept {
        memset(this, 0, sizeof(*this));
        strncpy(flow_id, fid, sizeof(flow_id) - 1);
        proto = pr;
        src_port = sport;
        dst_port = dport;
        in_addr sa{sip}, da{dip};
        inet_ntop(AF_INET, &sa, src_ip, sizeof src_ip);
        inet_ntop(AF_INET, &da, dst_ip, sizeof dst_ip);
    }

    static void mac_to_hex(const uint8_t* mac, int len, char* out, int out_len) {
        int pos = 0;
        for (int i = 0; i < len && i < 16 && pos < out_len - 3; i++)
            pos += snprintf(out + pos, (size_t)(out_len - pos), "%02X%s",
                            mac[i], (i + 1 < len) ? ":" : "");
    }

    static bool parse_dhcp(const uint8_t* p, int len, double ts, DhcpMsgInfo& m) {
        if (len < 240) return false;
        memset(&m, 0, sizeof m);
        m.ts = ts;
        m.op   = p[0];
        m.htype= p[1];
        m.hlen = p[2];
        m.hops = p[3];
        m.xid  = (uint32_t)(p[4]<<24 | p[5]<<16 | p[6]<<8 | p[7]);
        m.secs = (uint16_t)((p[8]<<8)|p[9]);
        m.flags= (uint16_t)((p[10]<<8)|p[11]);
        m.broadcast = (m.flags & 0x8000) != 0;
        memcpy(&m.ciaddr, p + 12, 4);
        memcpy(&m.yiaddr, p + 16, 4);
        memcpy(&m.siaddr, p + 20, 4);
        memcpy(&m.giaddr, p + 24, 4);
        int hl = m.hlen > 16 ? 16 : m.hlen;
        memcpy(m.chaddr, p + 28, (size_t)hl);
        mac_to_hex(m.chaddr, hl, m.chaddr_hex, sizeof m.chaddr_hex);

        /* magic cookie */
        if (memcmp(p + 236, "\x63\x82\x53\x63", 4) != 0) return true;

        const uint8_t* opt = p + 240;
        const uint8_t* end = p + len;
        while (opt < end) {
            uint8_t code = *opt++;
            if (code == 0) continue;
            if (code == 255) break;
            if (opt >= end) break;
            uint8_t olen = *opt++;
            if (opt + olen > end) break;

            switch (code) {
            case 53:
                if (olen >= 1) m.msg_type = opt[0];
                break;
            case 50:
                if (olen >= 4) memcpy(&m.requested_ip, opt, 4);
                break;
            case 54:
                if (olen >= 4) memcpy(&m.server_id, opt, 4);
                break;
            case 51:
                if (olen >= 4)
                    m.lease_time = (uint32_t)((opt[0]<<24)|(opt[1]<<16)|(opt[2]<<8)|opt[3]);
                break;
            case 1:
                if (olen >= 4) memcpy(&m.subnet_mask, opt, 4);
                break;
            case 3:
                if (olen >= 4) memcpy(&m.router, opt, 4);
                break;
            case 12:
                if (olen > 0) {
                    int cpy = olen < 255 ? olen : 255;
                    memcpy(m.hostname, opt, (size_t)cpy);
                    m.hostname[cpy] = '\0';
                    m.has_hostname = true;
                }
                break;
            case 15:
                if (olen > 0) {
                    int cpy = olen < 255 ? olen : 255;
                    memcpy(m.domain, opt, (size_t)cpy);
                    m.domain[cpy] = '\0';
                }
                break;
            case 60:
                if (olen > 0) {
                    int cpy = olen < 255 ? olen : 255;
                    memcpy(m.vendor_class, opt, (size_t)cpy);
                    m.vendor_class[cpy] = '\0';
                    m.has_vendor = true;
                }
                break;
            default: break;
            }
            opt += olen;
        }
        return true;
    }

    static void ip4_str(uint32_t ip, char* buf, int buflen) {
        struct in_addr a;
        memcpy(&a, &ip, 4);
        inet_ntop(AF_INET, &a, buf, (socklen_t)buflen);
    }

    void add_msg(const DhcpMsgInfo& m) {
        if (n_msgs < DHCP_MAX_MSGS) msgs[n_msgs++] = m;
        if (first_ts == 0.0) first_ts = m.ts;
        last_ts = m.ts;

        if (m.chaddr_hex[0]) strncpy(client_mac, m.chaddr_hex, sizeof(client_mac) - 1);
        if (m.has_hostname) strncpy(last_hostname, m.hostname, sizeof(last_hostname) - 1);
        if (m.has_vendor)   strncpy(last_vendor, m.vendor_class, sizeof(last_vendor) - 1);
        if (m.yiaddr) assigned_ip = m.yiaddr;
        if (m.server_id) server_ip = m.server_id;
        else if (m.siaddr) server_ip = m.siaddr;

        switch (m.msg_type) {
        case 1: discover_cnt++; break;
        case 2: offer_cnt++; break;
        case 3: request_cnt++; break;
        case 5: ack_cnt++; break;
        case 6: nak_cnt++; break;
        case 7: release_cnt++; break;
        default: break;
        }
    }

    void emit_json(FILE* f, const char* pcap_file) const {
        char ipbuf[20];
        fprintf(f, "{\"file\":");
        json_esc_cstr(f, pcap_file);
        fprintf(f, ",\"flow_id\":");
        json_esc_cstr(f, flow_id);
        fprintf(f, ",\"protocol\":\"DHCP\",");
        json_five_tuple(f, src_ip, src_port, dst_ip, dst_port, proto);
        fprintf(f, ",\"first_ts\":%.6f,\"last_ts\":%.6f", first_ts, last_ts);

        fprintf(f, ",\"meta\":{"
                "\"client_mac\":");
        json_esc_cstr(f, client_mac);
        fprintf(f, ",\"hostname\":");
        json_esc_cstr(f, last_hostname);
        fprintf(f, ",\"vendor_class\":");
        json_esc_cstr(f, last_vendor);
        fprintf(f, ",\"assigned_ip\":");
        if (assigned_ip) { ip4_str(assigned_ip, ipbuf, sizeof ipbuf); json_esc_cstr(f, ipbuf); }
        else fputs("\"\"", f);
        fprintf(f, ",\"server_ip\":");
        if (server_ip) { ip4_str(server_ip, ipbuf, sizeof ipbuf); json_esc_cstr(f, ipbuf); }
        else fputs("\"\"", f);
        fprintf(f, ",\"msg_counts\":{\"discover\":%u,\"offer\":%u,\"request\":%u,"
                "\"ack\":%u,\"nak\":%u,\"release\":%u}",
                discover_cnt, offer_cnt, request_cnt, ack_cnt, nak_cnt, release_cnt);
        fprintf(f, "},\"n_msgs\":%d,\"messages\":[", n_msgs);

        for (int i = 0; i < n_msgs; i++) {
            if (i) fputc(',', f);
            const DhcpMsgInfo& m = msgs[i];
            fprintf(f, "{\"ts\":%.6f,\"op\":%u,\"xid\":\"0x%08x\","
                    "\"msg_type\":\"%s\",\"secs\":%u,\"broadcast\":%s,"
                    "\"client_mac\":",
                    m.ts, (unsigned)m.op, m.xid,
                    dhcp_msg_type_name(m.msg_type), (unsigned)m.secs,
                    m.broadcast ? "true" : "false");
            json_esc_cstr(f, m.chaddr_hex);
            fprintf(f, ",\"ciaddr\":");
            ip4_str(m.ciaddr, ipbuf, sizeof ipbuf); json_esc_cstr(f, ipbuf);
            fprintf(f, ",\"yiaddr\":");
            ip4_str(m.yiaddr, ipbuf, sizeof ipbuf); json_esc_cstr(f, ipbuf);
            fprintf(f, ",\"requested_ip\":");
            ip4_str(m.requested_ip, ipbuf, sizeof ipbuf); json_esc_cstr(f, ipbuf);
            fprintf(f, ",\"server_id\":");
            ip4_str(m.server_id, ipbuf, sizeof ipbuf); json_esc_cstr(f, ipbuf);
            fprintf(f, ",\"lease_time\":%u,\"hostname\":",
                    (unsigned)m.lease_time);
            json_esc_cstr(f, m.hostname);
            fprintf(f, ",\"domain\":");
            json_esc_cstr(f, m.domain);
            fprintf(f, ",\"vendor_class\":");
            json_esc_cstr(f, m.vendor_class);
            fputc('}', f);
        }
        fprintf(f, "]}\n");
    }
};
