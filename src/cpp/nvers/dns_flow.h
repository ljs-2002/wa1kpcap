/**
 * dns_flow.h  ——  DNS 流量字段提取（Header-Only）
 *
 * 支持协议：
 *   UDP/TCP port 53 (标准 DNS)
 *   UDP port 5353  (mDNS)
 *   UDP port 5355  (LLMNR)
 *
 * 每条流提取字段（按消息粒度）：
 *   Transaction ID, QR, Opcode, AA/TC/RD/RA/AD/CD flags, RCODE
 *   QDCOUNT / ANCOUNT / NSCOUNT / ARCOUNT
 *   Question: QNAME, QTYPE, QCLASS
 *   Answer RR: name, type, class, TTL, rdata（A/AAAA/CNAME/MX/NS/TXT/SOA/SRV/PTR）
 *   Authority RR（NS 记录）
 *   Additional RR（EDNS0 OPT、A/AAAA glue）
 *   EDNS0: UDP payload size, version, DO bit, options
 *   RTT: query-response 匹配，毫秒精度
 *
 * 输出：JSON Lines（.log），每行一条流
 */
#pragma once

#include "json_log.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <climits>
#include <arpa/inet.h>
#include <netinet/in.h>

// ============================================================
// 常量
// ============================================================
static constexpr int DNS_MAX_MSGS    = 64;  // 每流最多记录消息数
static constexpr int DNS_MAX_ANSWERS = 16;  // 每条消息最多答案 RR 数
static constexpr int DNS_MAX_PENDING = 64;  // 待匹配 query 缓存

// DNS 端口集合（检测用）
static inline bool is_dns_port(uint16_t p) {
    return p == 53 || p == 5353 || p == 5355;
}

// ============================================================
// DNS Opcode
// ============================================================
enum DnsOpcode : uint8_t {
    DNS_OP_QUERY  = 0, DNS_OP_IQUERY = 1, DNS_OP_STATUS = 2,
    DNS_OP_NOTIFY = 4, DNS_OP_UPDATE = 5,
};
static inline const char* dns_opcode_name(uint8_t op) {
    switch(op){case 0:return"QUERY";case 1:return"IQUERY";case 2:return"STATUS";
               case 4:return"NOTIFY";case 5:return"UPDATE";default:return"UNKNOWN";}
}

// ============================================================
// DNS RCODE
// ============================================================
static inline const char* dns_rcode_name(uint8_t rc) {
    switch(rc){
    case 0:return"NOERROR"; case 1:return"FORMERR";  case 2:return"SERVFAIL";
    case 3:return"NXDOMAIN";case 4:return"NOTIMP";   case 5:return"REFUSED";
    case 6:return"YXDOMAIN";case 7:return"YXRRSET";  case 8:return"NXRRSET";
    case 9:return"NOTAUTH"; case 10:return"NOTZONE";
    default:return"UNKNOWN";}
}

// ============================================================
// DNS QTYPE
// ============================================================
static inline const char* dns_qtype_name(uint16_t t) {
    switch(t){
    case   1:return"A";      case   2:return"NS";    case   5:return"CNAME";
    case   6:return"SOA";    case  12:return"PTR";   case  15:return"MX";
    case  16:return"TXT";    case  28:return"AAAA";  case  33:return"SRV";
    case  41:return"OPT";    case  43:return"DS";    case  46:return"RRSIG";
    case  47:return"NSEC";   case  48:return"DNSKEY";case  52:return"TLSA";
    case  65:return"HTTPS";  case 255:return"ANY";   case 256:return"URI";
    case 257:return"CAA";    case 28672:return"TA";  case 32769:return"DLV";
    default:{ static char buf[16]; snprintf(buf,sizeof buf,"TYPE%u",t); return buf; }}
}

// ============================================================
// DNS 名称解析（支持指针压缩，循环防护）
// ============================================================
// msg[0..msg_len) 为完整 DNS 消息缓冲区
// ptr 指向当前名称起始位置，end 为包体边界
// next_ptr 返回名称字段之后的下一字节位置
static inline bool parse_dns_name(
        const uint8_t* msg, int msg_len,
        const uint8_t* ptr, const uint8_t* end,
        char* out, int out_len, const uint8_t** next_ptr)
{
    int   written = 0;
    bool  jumped  = false;
    int   jumps   = 0;
    const uint8_t* cur = ptr;
    const uint8_t* msg_end = msg + msg_len;

    while (cur < end && cur < msg_end) {
        uint8_t label_len = *cur;

        if (label_len == 0) {
            if (!jumped) *next_ptr = cur + 1;
            if (written == 0 && out_len > 1) { out[0]='.'; out[1]='\0'; written=1; }
            else if (written > 0 && written < out_len) out[written] = '\0';
            return true;
        }

        // 指针压缩（高2位为11）
        if ((label_len & 0xC0) == 0xC0) {
            if (cur + 1 >= end || cur + 1 >= msg_end) return false;
            uint16_t offset = (uint16_t)(((label_len & 0x3F) << 8) | cur[1]);
            if (!jumped) *next_ptr = cur + 2;
            jumped = true;
            cur = msg + offset;
            if (++jumps > 128) return false;
            continue;
        }

        if ((label_len & 0xC0) != 0) return false;  // reserved

        cur++;
        if (cur + label_len > msg_end || cur + label_len > end) return false;

        if (written > 0 && written < out_len - 1) out[written++] = '.';
        int copy = (label_len < out_len - written - 2) ? label_len : out_len - written - 2;
        if (copy > 0) { memcpy(out + written, cur, copy); written += copy; }
        cur += label_len;
    }
    if (written < out_len) out[written] = '\0';
    return false;
}

// ============================================================
// DNS Resource Record
// ============================================================
struct DnsRR {
    char     name[256];
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    char     rdata[768];    // 人类可读的 rdata 字符串
};

// 解析 rdata 为可读字符串，返回解析后 rdata 指针之后的位置
static inline const uint8_t* parse_rdata(
        uint16_t type, const uint8_t* rdata, uint16_t rdlen,
        const uint8_t* msg, int msg_len,
        char* out, int out_len)
{
    const uint8_t* p = rdata;
    const uint8_t* end = rdata + rdlen;
    out[0] = '\0';

    switch (type) {
    case 1:  // A
        if (rdlen == 4) {
            struct in_addr a; memcpy(&a, p, 4);
            inet_ntop(AF_INET, &a, out, out_len);
        }
        break;
    case 28: // AAAA
        if (rdlen == 16) {
            struct in6_addr a; memcpy(&a, p, 16);
            inet_ntop(AF_INET6, &a, out, out_len);
        }
        break;
    case 5:  // CNAME
    case 2:  // NS
    case 12: // PTR
    {
        const uint8_t* dummy = nullptr;
        parse_dns_name(msg, msg_len, p, end, out, out_len, &dummy);
        break;
    }
    case 15: // MX
        if (rdlen >= 3) {
            uint16_t pref = (uint16_t)((p[0]<<8)|p[1]);
            char exch[256]; const uint8_t* dummy = nullptr;
            parse_dns_name(msg, msg_len, p+2, end, exch, sizeof exch, &dummy);
            snprintf(out, out_len, "%u %s", pref, exch);
        }
        break;
    case 16: // TXT
    {
        int pos = 0;
        const uint8_t* tp = p;
        while (tp < end && pos < out_len - 2) {
            uint8_t slen = *tp++;
            if (tp + slen > end) break;
            out[pos++] = '"';
            int copy = (slen < out_len - pos - 3) ? slen : out_len - pos - 3;
            memcpy(out+pos, tp, copy); pos += copy;
            out[pos++] = '"';
            tp += slen;
            if (tp < end) out[pos++] = ' ';
        }
        out[pos] = '\0';
        break;
    }
    case 6:  // SOA
    {
        char mname[256], rname[256];
        const uint8_t* next = nullptr;
        parse_dns_name(msg, msg_len, p, end, mname, sizeof mname, &next);
        if (next && next < end) {
            const uint8_t* next2 = nullptr;
            parse_dns_name(msg, msg_len, next, end, rname, sizeof rname, &next2);
            if (next2 && next2 + 20 <= end) {
                uint32_t serial  = (uint32_t)((next2[0]<<24)|(next2[1]<<16)|(next2[2]<<8)|next2[3]);
                uint32_t refresh = (uint32_t)((next2[4]<<24)|(next2[5]<<16)|(next2[6]<<8)|next2[7]);
                uint32_t retry   = (uint32_t)((next2[8]<<24)|(next2[9]<<16)|(next2[10]<<8)|next2[11]);
                uint32_t expire  = (uint32_t)((next2[12]<<24)|(next2[13]<<16)|(next2[14]<<8)|next2[15]);
                uint32_t minimum = (uint32_t)((next2[16]<<24)|(next2[17]<<16)|(next2[18]<<8)|next2[19]);
                snprintf(out, (size_t)out_len,
                         "%.128s %.128s serial=%u refresh=%u retry=%u expire=%u min=%u",
                         mname, rname, serial, refresh, retry, expire, minimum);
            }
        }
        break;
    }
    case 33: // SRV
        if (rdlen >= 7) {
            uint16_t pri  = (uint16_t)((p[0]<<8)|p[1]);
            uint16_t wgt  = (uint16_t)((p[2]<<8)|p[3]);
            uint16_t port = (uint16_t)((p[4]<<8)|p[5]);
            char target[256]; const uint8_t* dummy = nullptr;
            parse_dns_name(msg, msg_len, p+6, end, target, sizeof target, &dummy);
            snprintf(out, out_len, "pri=%u wgt=%u port=%u %s", pri, wgt, port, target);
        }
        break;
    case 41: // OPT (EDNS0) — rdata 是 option list
    {
        const uint8_t* op = p;
        int pos = 0;
        while (op + 4 <= end) {
            uint16_t ocode = (uint16_t)((op[0]<<8)|op[1]);
            uint16_t olen  = (uint16_t)((op[2]<<8)|op[3]);
            op += 4;
            pos += snprintf(out+pos, out_len-pos, "opt%u(%uB) ", ocode, olen);
            op  += olen;
        }
        if (pos == 0) snprintf(out, out_len, "(empty)");
        break;
    }
    default:
        snprintf(out, out_len, "(%u bytes)", rdlen);
        break;
    }
    return end;
}

// ============================================================
// DNS 消息结构
// ============================================================
struct DnsMsgInfo {
    double   ts;
    bool     is_response;
    uint16_t txid;
    uint8_t  opcode;
    uint8_t  rcode;
    // Flags
    bool aa, tc, rd, ra, ad, cd;
    // Section counts
    uint16_t qdcount, ancount, nscount, arcount;
    // Primary question
    char     qname[256];
    uint16_t qtype, qclass;
    // Answer section（最多 DNS_MAX_ANSWERS 条）
    DnsRR    answers[DNS_MAX_ANSWERS];
    int      n_answers;
    // Authority section（NS 名称列表）
    char     ns_names[4][256];
    int      n_ns;
    // EDNS0 (from OPT record in Additional)
    bool     has_edns;
    uint16_t edns_udp_size;   // OPT class 字段
    uint8_t  edns_version;    // OPT TTL 字段 byte[2]
    bool     edns_do;         // OPT TTL bit 15
    // RTT（仅在 response 被匹配时设置，否则 -1）
    double   rtt_ms;
    // 传输层信息
    bool     is_tcp;          // true=DNS over TCP
};

// ============================================================
// 流 DNS 汇总
// ============================================================
struct DnsFlowRecord {
    char    flow_id[96];
    char    src_ip[INET_ADDRSTRLEN];
    char    dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;

    DnsMsgInfo msgs[DNS_MAX_MSGS];
    int        n_msgs;

    // 统计
    uint32_t query_count, response_count;
    uint32_t noerror_cnt, nxdomain_cnt, servfail_cnt, refused_cnt;
    uint32_t truncated_cnt, edns_cnt, dnssec_cnt;
    double   rtt_min, rtt_max, rtt_sum;
    uint32_t rtt_count;

    // 待 RTT 匹配的 query（按 txid）
    struct Pending { uint16_t txid; double ts; };
    Pending pending[DNS_MAX_PENDING];
    int     n_pending;

    void init(const char* fid, uint8_t pr,
              uint32_t sip, uint32_t dip,
              uint16_t sport, uint16_t dport) noexcept {
        memset(this, 0, sizeof(*this));
        strncpy(flow_id, fid, sizeof(flow_id)-1);
        proto = pr;
        src_port = sport;
        dst_port = dport;
        in_addr sa{sip}, da{dip};
        inet_ntop(AF_INET, &sa, src_ip, sizeof src_ip);
        inet_ntop(AF_INET, &da, dst_ip, sizeof dst_ip);
        rtt_min  = 1e18;
        rtt_max  = -1.0;
    }

    // 添加一条已解析消息（更新统计、匹配 RTT）
    void add_msg(const DnsMsgInfo& m) {
        if (n_msgs < DNS_MAX_MSGS)
            msgs[n_msgs++] = m;

        if (!m.is_response) {
            query_count++;
            if (n_pending < DNS_MAX_PENDING) {
                pending[n_pending++] = {m.txid, m.ts};
            }
            if (m.has_edns) edns_cnt++;
            if (m.has_edns && m.edns_do) dnssec_cnt++;
        } else {
            response_count++;
            switch (m.rcode) {
            case 0: noerror_cnt++;  break;
            case 2: servfail_cnt++; break;
            case 3: nxdomain_cnt++; break;
            case 5: refused_cnt++;  break;
            }
            if (m.tc) truncated_cnt++;
            if (m.has_edns) edns_cnt++;

            // RTT 匹配
            for (int i = 0; i < n_pending; i++) {
                if (pending[i].txid == m.txid) {
                    double rtt = (m.ts - pending[i].ts) * 1000.0;
                    if (n_msgs > 0) msgs[n_msgs-1].rtt_ms = rtt;
                    if (rtt < rtt_min) rtt_min = rtt;
                    if (rtt > rtt_max) rtt_max = rtt;
                    rtt_sum += rtt;
                    rtt_count++;
                    // 移除已匹配条目
                    pending[i] = pending[--n_pending];
                    break;
                }
            }
        }
    }

    void emit_json(FILE* f, const char* pcap_file) const {
        fprintf(f, "{\"file\":");
        json_esc_cstr(f, pcap_file);
        fprintf(f, ",\"flow_id\":");
        json_esc_cstr(f, flow_id);
        fprintf(f, ",");
        json_five_tuple(f, src_ip, src_port, dst_ip, dst_port, proto);
        fprintf(f, ",\"stats\":{"
                "\"queries\":%u,\"responses\":%u,"
                "\"noerror\":%u,\"nxdomain\":%u,\"servfail\":%u,\"refused\":%u,"
                "\"truncated\":%u,\"edns\":%u,\"dnssec\":%u",
                query_count, response_count,
                noerror_cnt, nxdomain_cnt, servfail_cnt, refused_cnt,
                truncated_cnt, edns_cnt, dnssec_cnt);
        if (rtt_count > 0) {
            fprintf(f, ",\"rtt_ms\":{\"min\":%.3f,\"max\":%.3f,\"avg\":%.3f,\"samples\":%u}",
                    rtt_min, rtt_max, rtt_sum / rtt_count, rtt_count);
        }
        fprintf(f, "},\"n_msgs\":%d,\"messages\":[", n_msgs);

        for (int i = 0; i < n_msgs; i++) {
            if (i) fputc(',', f);
            const DnsMsgInfo& m = msgs[i];
            fprintf(f, "{\"idx\":%d,\"is_response\":%s,\"txid\":\"0x%04x\","
                    "\"ts\":%.6f,\"opcode\":\"%s\",\"rcode\":\"%s\","
                    "\"flags\":{\"aa\":%s,\"tc\":%s,\"rd\":%s,\"ra\":%s,\"ad\":%s,\"cd\":%s},"
                    "\"counts\":{\"qd\":%u,\"an\":%u,\"ns\":%u,\"ar\":%u},"
                    "\"question\":{\"qname\":",
                    i + 1, m.is_response ? "true" : "false", m.txid, m.ts,
                    dns_opcode_name(m.opcode),
                    m.is_response ? dns_rcode_name(m.rcode) : "",
                    m.aa ? "true" : "false", m.tc ? "true" : "false",
                    m.rd ? "true" : "false", m.ra ? "true" : "false",
                    m.ad ? "true" : "false", m.cd ? "true" : "false",
                    m.qdcount, m.ancount, m.nscount, m.arcount);
            json_esc_cstr(f, m.qname);
            fprintf(f, ",\"qtype\":\"%s\",\"qclass\":%u},"
                    "\"answers\":[",
                    dns_qtype_name(m.qtype), m.qclass);
            for (int j = 0; j < m.n_answers; j++) {
                if (j) fputc(',', f);
                const DnsRR& rr = m.answers[j];
                fprintf(f, "{\"name\":");
                json_esc_cstr(f, rr.name);
                fprintf(f, ",\"type\":\"%s\",\"class\":%u,\"ttl\":%u,\"rdata\":",
                        dns_qtype_name(rr.type), rr.rclass, rr.ttl);
                json_esc_cstr(f, rr.rdata);
                fputc('}', f);
            }
            fprintf(f, "],\"authority\":[");
            for (int j = 0; j < m.n_ns; j++) {
                if (j) fputc(',', f);
                json_esc_cstr(f, m.ns_names[j]);
            }
            fprintf(f, "],\"edns\":");
            if (m.has_edns) {
                fprintf(f, "{\"udp_size\":%u,\"version\":%u,\"do\":%s}",
                        m.edns_udp_size, m.edns_version,
                        m.edns_do ? "true" : "false");
            } else {
                fputs("null", f);
            }
            fprintf(f, ",\"is_tcp\":%s", m.is_tcp ? "true" : "false");
            if (m.is_response && m.rtt_ms >= 0)
                fprintf(f, ",\"rtt_ms\":%.3f", m.rtt_ms);
            fputc('}', f);
        }
        fprintf(f, "]}\n");
    }
};

// ============================================================
// 解析 DNS 消息体（msg 为完整 DNS payload，含12字节头）
// ============================================================
static inline bool parse_dns_message(
        const uint8_t* msg, int msg_len,
        double ts, bool is_tcp,
        DnsMsgInfo& out)
{
    if (msg_len < 12) return false;
    memset(&out, 0, sizeof out);
    out.ts       = ts;
    out.rtt_ms   = -1.0;
    out.is_tcp   = is_tcp;

    out.txid     = (uint16_t)((msg[0]<<8)|msg[1]);
    uint16_t flags = (uint16_t)((msg[2]<<8)|msg[3]);
    out.is_response = (flags >> 15) & 1;
    out.opcode   = (flags >> 11) & 0xF;
    out.aa       = (flags >> 10) & 1;
    out.tc       = (flags >>  9) & 1;
    out.rd       = (flags >>  8) & 1;
    out.ra       = (flags >>  7) & 1;
    out.ad       = (flags >>  5) & 1;
    out.cd       = (flags >>  4) & 1;
    out.rcode    = flags & 0xF;
    out.qdcount  = (uint16_t)((msg[4]<<8)|msg[5]);
    out.ancount  = (uint16_t)((msg[6]<<8)|msg[7]);
    out.nscount  = (uint16_t)((msg[8]<<8)|msg[9]);
    out.arcount  = (uint16_t)((msg[10]<<8)|msg[11]);

    const uint8_t* p   = msg + 12;
    const uint8_t* end = msg + msg_len;

    // ---- Question section ----
    for (int qi = 0; qi < out.qdcount && p < end; qi++) {
        const uint8_t* next = nullptr;
        char name[256];
        if (!parse_dns_name(msg, msg_len, p, end, name, sizeof name, &next)) break;
        p = next;
        if (p + 4 > end) break;
        uint16_t qt = (uint16_t)((p[0]<<8)|p[1]);
        uint16_t qc = (uint16_t)((p[2]<<8)|p[3]);
        p += 4;
        if (qi == 0) {
            memcpy(out.qname, name, sizeof out.qname - 1);
            out.qname[sizeof out.qname - 1] = '\0';
            out.qtype  = qt;
            out.qclass = qc;
        }
    }

    // Helper: parse one RR header, returns rdata pointer or nullptr
    auto parse_rr_header = [&](DnsRR& rr) -> const uint8_t* {
        const uint8_t* next = nullptr;
        if (!parse_dns_name(msg, msg_len, p, end, rr.name, sizeof rr.name, &next)) return nullptr;
        p = next;
        if (p + 10 > end) return nullptr;
        rr.type   = (uint16_t)((p[0]<<8)|p[1]);
        rr.rclass = (uint16_t)((p[2]<<8)|p[3]);
        rr.ttl    = (uint32_t)((p[4]<<24)|(p[5]<<16)|(p[6]<<8)|p[7]);
        uint16_t rdlen = (uint16_t)((p[8]<<8)|p[9]);
        p += 10;
        if (p + rdlen > end) return nullptr;
        return p + rdlen;  // will be returned as rdata_end
    };

    // ---- Answer section ----
    // Note: parse_rr_header advances p past the RR header; after the call,
    // p points to the start of rdata and rdata_end = p + rdlen.
    for (int ai = 0; ai < out.ancount && p < end; ai++) {
        DnsRR rr{};
        const uint8_t* rdata_end = parse_rr_header(rr);
        if (!rdata_end) break;
        uint16_t rdlen = (uint16_t)(rdata_end - p);   // p now at rdata start
        parse_rdata(rr.type, p, rdlen, msg, msg_len, rr.rdata, (int)sizeof rr.rdata);
        p = rdata_end;
        if (out.n_answers < DNS_MAX_ANSWERS)
            out.answers[out.n_answers++] = rr;
    }

    // ---- Authority section ----
    for (int ni = 0; ni < out.nscount && p < end; ni++) {
        DnsRR rr{};
        const uint8_t* rdata_end = parse_rr_header(rr);
        if (!rdata_end) break;
        uint16_t rdlen = (uint16_t)(rdata_end - p);
        parse_rdata(rr.type, p, rdlen, msg, msg_len, rr.rdata, (int)sizeof rr.rdata);
        p = rdata_end;
        if (rr.type == 2 && out.n_ns < 4) {  // NS
            int copy_len = 255;
            memcpy(out.ns_names[out.n_ns], rr.rdata, (size_t)copy_len);
            out.ns_names[out.n_ns][copy_len] = '\0';
            out.n_ns++;
        }
    }

    // ---- Additional section (EDNS0 OPT + glue) ----
    for (int ari = 0; ari < out.arcount && p < end; ari++) {
        DnsRR rr{};
        const uint8_t* rdata_end = parse_rr_header(rr);
        if (!rdata_end) break;
        if (rr.type == 41) {  // OPT => EDNS0
            out.has_edns      = true;
            out.edns_udp_size = rr.rclass;
            out.edns_version  = (uint8_t)((rr.ttl >> 16) & 0xFF);
            out.edns_do       = (rr.ttl >> 15) & 1;
        }
        p = rdata_end;
    }

    return true;
}
