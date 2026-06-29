/**
 * argus_flow.h  ——  Argus (Audit Record Generation and Utilization System) 流特征定义
 *
 * Argus 是一个面向安全分析的双向流审计工具（RFC-like 非标准，Carnegie Mellon）。
 * 本文件实现与 argus-3.0 / ra (Record Aggregator) 输出格式对齐的字段集：
 *
 *   时间类:  StartTime, LastTime, Dur
 *   5-tuple: Proto, SrcAddr, Sport, DstAddr, Dport
 *   状态类:  State, Dir, sFlgs, dFlgs
 *   流量类:  TotPkts, TotBytes, SrcPkts, DstPkts, SrcBytes, DstBytes
 *   速率类:  SrcLoad, DstLoad, SrcRate, DstRate
 *   TCP类:   SrcWin, DstWin, SrcTCPBase, DstTCPBase, SynAck(RTT), AckDat(RTT)
 *            SrcGap, DstGap (TCP seq gap = loss indicator)
 *   统计类:  SrcMeanPktSz, DstMeanPktSz, Mean(IAT), StdDev(IAT)
 *   IP类:    sTos, dTos, SrcIpId, DstIpId
 *   服务识别: Cause(service)
 *
 * State 状态机（TCP）:
 *   INIT → REQ (SYN seen) → ACC (SYN-ACK seen) → CON (3-way done)
 *        → EST (data) → FIN (one side FIN) → CLO (both FIN) / RST
 *
 * Dir 方向:
 *   "->" : 只有正向流量
 *   "<-" : 只有反向流量
 *   "<>" : 双向流量
 *   "??" : 无 payload（仅 TCP 控制）
 *
 * sFlgs/dFlgs (Argus flow flags):
 *   e = established (TCP 3-way handshake completed)
 *   s/S = SYN sent/received
 *   d/D = data sent/received
 *   f/F = FIN sent/received
 *   r/R = RST sent/received
 *   u/U = URG set
 *   i   = SYN retransmit (scanning indicator)
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <cmath>
#include <cstdio>
#include <algorithm>
#include <time.h>

/* ============================================================
 * Argus TCP 状态枚举
 * ============================================================ */
enum class ArgusState : uint8_t {
    INIT = 0, /* 未见任何包                                    */
    REQ  = 1, /* SYN 已发（或 UDP 首包）                       */
    ACC  = 2, /* SYN-ACK 已收                                  */
    CON  = 3, /* 3-way 握手完成                                */
    EST  = 4, /* 数据已传输                                    */
    FIN  = 5, /* 一侧发出 FIN                                  */
    CLO  = 6, /* 双向 FIN (clean close)                        */
    RST  = 7, /* RST 导致关闭                                  */
    TIM  = 8, /* 超时                                          */
    INT  = 9, /* Incomplete (< 1 sec, few packets)             */
    URG  = 10,/* URG bit seen                                  */
};

static inline const char *argus_state_name(ArgusState s) {
    switch (s) {
    case ArgusState::INIT: return "INIT";
    case ArgusState::REQ:  return "REQ";
    case ArgusState::ACC:  return "ACC";
    case ArgusState::CON:  return "CON";
    case ArgusState::EST:  return "EST";
    case ArgusState::FIN:  return "FIN";
    case ArgusState::CLO:  return "CLO";
    case ArgusState::RST:  return "RST";
    case ArgusState::TIM:  return "TIM";
    case ArgusState::INT:  return "INT";
    case ArgusState::URG:  return "URG";
    default:               return "???";
    }
}

/* ============================================================
 * 服务检测（基于端口）
 * ============================================================ */
static inline const char *argus_detect_service(uint8_t proto,
                                                uint16_t sport,
                                                uint16_t dport) {
    /* 选 server side port（较小且 ≤ 49151 的那个） */
    auto well_known = [](uint16_t p){ return p <= 1023; };
    auto registered = [](uint16_t p){ return p <= 49151; };
    uint16_t sp = 0;
    if (well_known(dport) || (!well_known(sport) && registered(dport))) sp = dport;
    else if (well_known(sport))                                          sp = sport;
    else sp = std::min(sport, dport);

    if (proto == 17) { /* UDP */
        switch (sp) {
        case 53: case 5353: case 5355: return "dns";
        case 67: case 68:  return "dhcp";
        case 123:          return "ntp";
        case 161: case 162:return "snmp";
        case 514:          return "syslog";
        case 1194:         return "openvpn";
        case 51820:        return "wireguard";
        default:           return nullptr;
        }
    }
    switch (sp) {
    case 21:   return "ftp";
    case 22:   return "ssh";
    case 23:   return "telnet";
    case 25:   return "smtp";
    case 53:   return "dns";
    case 80:   return "http";
    case 110:  return "pop3";
    case 143:  return "imap";
    case 389:  return "ldap";
    case 443:  return "https";
    case 445:  return "smb";
    case 465:  return "smtps";
    case 587:  return "smtp";
    case 636:  return "ldaps";
    case 993:  return "imaps";
    case 995:  return "pop3s";
    case 1194: return "openvpn";
    case 1433: return "mssql";
    case 3306: return "mysql";
    case 3389: return "rdp";
    case 5432: return "pgsql";
    case 5900: return "vnc";
    case 6379: return "redis";
    case 8080: return "http-alt";
    case 8443: return "https-alt";
    case 9200: return "elasticsearch";
    case 27017:return "mongodb";
    default:   return nullptr;
    }
}

/* ============================================================
 * 轻量 IAT / 包长统计
 * ============================================================ */
struct ArgStats {
    uint64_t n;
    double   mean, M2, sum;
    double   vmin, vmax;
    /* POD 结构，配合 memset 使用 */
    void reset() noexcept { n=0; mean=M2=sum=0.0; vmin=1e18; vmax=-1e18; }
    void add(double x) noexcept {
        n++; sum += x;
        double d = x - mean; mean += d / n;
        M2 += d * (x - mean);
        if (x < vmin) vmin = x;
        if (x > vmax) vmax = x;
    }
    double std() const noexcept {
        return n > 1 ? std::sqrt(std::max(0.0, M2/(n-1))) : 0.0;
    }
};

/* ============================================================
 * Argus 流记录
 * ============================================================ */
struct ArgusRecord {

    /* ---- 5-tuple ---- */
    uint8_t  proto;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;

    /* ---- 时间 ---- */
    double   start_time;      /* Unix 秒（微秒精度）                      */
    double   last_time;
    double   dur;             /* 持续时间（秒）                           */

    /* ---- 状态 / 方向 / 标志 ---- */
    ArgusState state;
    char     dir[4];          /* "->" "<-" "<>" "??"                      */
    char     sflgs[16];       /* 正向 Argus flow flags                    */
    char     dflgs[16];       /* 反向 Argus flow flags                    */

    /* ---- 服务 ---- */
    const char *service;      /* nullptr = 未知                           */

    /* ---- 流量计数 ---- */
    uint64_t src_pkts;        /* 正向包数                                 */
    uint64_t dst_pkts;        /* 反向包数                                 */
    uint64_t src_bytes;       /* 正向字节（IP total length）              */
    uint64_t dst_bytes;       /* 反向字节                                 */

    /* ---- 流速率 ---- */
    double   src_load;        /* 正向 pkt/s                               */
    double   dst_load;        /* 反向 pkt/s                               */
    double   src_rate;        /* 正向 bytes/s                             */
    double   dst_rate;        /* 反向 bytes/s                             */

    /* ---- TCP 窗口 / 序列号 ---- */
    uint32_t src_win;         /* 正向最后 TCP window                      */
    uint32_t dst_win;         /* 反向最后 TCP window                      */
    uint32_t src_tcp_base;    /* 正向初始 seq                             */
    uint32_t dst_tcp_base;    /* 反向初始 seq                             */
    uint32_t src_max_seq;     /* 正向见过的最大 seq+len                   */
    uint32_t dst_max_seq;

    /* TCP RTT 估计（SYN → SYN-ACK 时间差，毫秒） */
    double   syn_ack_rtt_ms;
    double   ack_dat_rtt_ms;  /* SYN-ACK → 第一个 data ACK               */

    /* TCP loss 指标（seq gap = 可能的丢包/重传） */
    uint32_t src_gap;         /* 正向 TCP seq gap 次数                    */
    uint32_t dst_gap;

    /* ---- TCP 标志计数 ---- */
    uint32_t syn_cnt;
    uint32_t fin_cnt;
    uint32_t rst_cnt;
    uint32_t psh_cnt;
    uint32_t ack_cnt;
    uint32_t urg_cnt;

    /* ---- IP 字段 ---- */
    uint8_t  src_tos;
    uint8_t  dst_tos;
    uint16_t src_ip_id;       /* 正向首包 IP ID                           */
    uint16_t dst_ip_id;       /* 反向首包 IP ID                           */

    /* ---- 统计量 ---- */
    ArgStats src_pkt_len;     /* 正向包长（IP total length）              */
    ArgStats dst_pkt_len;     /* 反向包长                                 */
    ArgStats all_iat;         /* 全流 IAT (ms)                            */
    ArgStats src_iat;         /* 正向 IAT                                 */
    ArgStats dst_iat;         /* 反向 IAT                                 */

    /* ---- 内部追踪（不进 JSON）---- */
    double   _ts_last;
    double   _ts_last_src;
    double   _ts_last_dst;
    double   _ts_syn;         /* SYN 时刻（用于 RTT 计算）               */
    double   _ts_synack;      /* SYN-ACK 时刻                             */
    bool     _saw_fin_src;
    bool     _saw_fin_dst;
    bool     _established;
    bool     _src_tos_set;
    bool     _dst_tos_set;
    bool     _src_ip_id_set;
    bool     _dst_ip_id_set;

    /* ============================================================
     * 初始化
     * ============================================================ */
    void init(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
              uint8_t proto_val) noexcept {
        memset(this, 0, sizeof *this);  /* ArgStats 是 POD，可安全 memset */
        src_pkt_len.reset(); dst_pkt_len.reset();
        all_iat.reset(); src_iat.reset(); dst_iat.reset();
        proto = proto_val;
        src_ip = sip; dst_ip = dip;
        src_port = sp; dst_port = dp;
        state = ArgusState::INIT;
        service = argus_detect_service(proto_val, sp, dp);
        dir[0] = '?'; dir[1] = '?'; dir[2] = '\0';
        sflgs[0] = '\0';
        dflgs[0] = '\0';
        syn_ack_rtt_ms = -1.0;
        ack_dat_rtt_ms = -1.0;
    }

    /* ============================================================
     * 每包处理
     * @param ip_total_len  IP 总长度
     * @param tcp_fl        TCP 标志字节（UDP 填 0）
     * @param tcp_win       TCP 窗口大小（主机字节序）
     * @param tcp_seq       TCP 序列号（主机字节序）
     * @param tcp_payload   TCP/UDP payload 长度
     * @param ttl           IP TTL
     * @param tos_val       IP TOS
     * @param ip_id         IP ID 字段（主机字节序）
     * @param is_fwd        true = 与首包同向
     * @param ts            绝对时间戳（秒）
     * ============================================================ */
    void process_packet(int ip_total_len, uint8_t tcp_fl,
                        uint16_t tcp_win, uint32_t tcp_seq, int tcp_payload,
                        uint8_t ttl, uint8_t tos_val, uint16_t ip_id,
                        bool is_fwd, double ts) noexcept {
        (void)ttl;
        bool is_first = (src_pkts + dst_pkts == 0);

        /* 时间 */
        if (is_first) {
            start_time = _ts_last = ts;
            _ts_last_src = _ts_last_dst = 0.0;
        }

        /* IAT */
        if (!is_first) {
            all_iat.add((ts - _ts_last) * 1000.0);
            if (is_fwd  && _ts_last_src > 0.0 && src_pkts > 0)
                src_iat.add((ts - _ts_last_src) * 1000.0);
            if (!is_fwd && _ts_last_dst > 0.0 && dst_pkts > 0)
                dst_iat.add((ts - _ts_last_dst) * 1000.0);
        }
        _ts_last = ts;
        if (is_fwd)  _ts_last_src = ts;
        else         _ts_last_dst = ts;

        /* 包长 */
        if (is_fwd) { src_pkt_len.add(ip_total_len); src_pkts++; src_bytes += (uint64_t)ip_total_len; }
        else        { dst_pkt_len.add(ip_total_len); dst_pkts++; dst_bytes += (uint64_t)ip_total_len; }

        /* IP 字段 */
        if (is_fwd && !_src_tos_set) { src_tos = tos_val; _src_tos_set = true; }
        if (!is_fwd && !_dst_tos_set){ dst_tos = tos_val; _dst_tos_set = true; }
        if (is_fwd && !_src_ip_id_set){ src_ip_id = ip_id; _src_ip_id_set = true; }
        if (!is_fwd && !_dst_ip_id_set){ dst_ip_id = ip_id; _dst_ip_id_set = true; }

        /* TCP 处理 */
        if (proto == 6) {
            bool syn = (tcp_fl & 0x02) != 0;
            bool ack = (tcp_fl & 0x10) != 0;
            bool fin = (tcp_fl & 0x01) != 0;
            bool rst = (tcp_fl & 0x04) != 0;
            bool psh = (tcp_fl & 0x08) != 0;
            bool urg = (tcp_fl & 0x20) != 0;

            if (syn) syn_cnt++;
            if (fin) fin_cnt++;
            if (rst) rst_cnt++;
            if (psh) psh_cnt++;
            if (ack) ack_cnt++;
            if (urg) urg_cnt++;

            /* TCP 窗口 */
            if (is_fwd) { src_win = tcp_win; }
            else        { dst_win = tcp_win; }

            /* TCP seq base */
            if (syn && is_fwd  && src_tcp_base == 0) { src_tcp_base = tcp_seq; }
            if (syn && !is_fwd && dst_tcp_base == 0) { dst_tcp_base = tcp_seq; }

            /* TCP seq gap 检测（简单版：序列号倒退）*/
            uint32_t expected_next;
            if (is_fwd) {
                expected_next = src_max_seq;
                if (tcp_seq != 0 && expected_next != 0 && tcp_seq < expected_next - 1)
                    src_gap++;
                uint32_t end_seq = tcp_seq + (uint32_t)tcp_payload;
                if (end_seq > src_max_seq) src_max_seq = end_seq;
            } else {
                expected_next = dst_max_seq;
                if (tcp_seq != 0 && expected_next != 0 && tcp_seq < expected_next - 1)
                    dst_gap++;
                uint32_t end_seq = tcp_seq + (uint32_t)tcp_payload;
                if (end_seq > dst_max_seq) dst_max_seq = end_seq;
            }

            /* RTT: SYN → SYN-ACK */
            if (syn && !ack && is_fwd) { _ts_syn = ts; }
            if (syn && ack && !is_fwd && _ts_syn > 0.0 && syn_ack_rtt_ms < 0.0) {
                syn_ack_rtt_ms = (ts - _ts_syn) * 1000.0;
                _ts_synack = ts;
            }
            if (!syn && ack && is_fwd && _ts_synack > 0.0 && ack_dat_rtt_ms < 0.0) {
                ack_dat_rtt_ms = (ts - _ts_synack) * 1000.0;
            }

            /* 状态机 */
            if (rst) {
                state = ArgusState::RST;
            } else {
                switch (state) {
                case ArgusState::INIT:
                    if (syn && !ack) { state = ArgusState::REQ; } break;
                case ArgusState::REQ:
                    if (syn && ack)               { state = ArgusState::ACC; }
                    else if (!syn && ack && !fin) { state = ArgusState::CON; }
                    break;
                case ArgusState::ACC:
                    if (!syn && ack) { state = ArgusState::CON; _established = true; }
                    break;
                case ArgusState::CON:
                    if (tcp_payload > 0) { state = ArgusState::EST; _established = true; }
                    if (fin) state = ArgusState::FIN;
                    break;
                case ArgusState::EST:
                    if (fin) { state = ArgusState::FIN; }
                    break;
                case ArgusState::FIN:
                    if (fin && is_fwd  && !_saw_fin_src) _saw_fin_src = true;
                    if (fin && !is_fwd && !_saw_fin_dst) _saw_fin_dst = true;
                    if (_saw_fin_src && _saw_fin_dst)    state = ArgusState::CLO;
                    break;
                default: break;
                }
            }
            if (fin && is_fwd)  _saw_fin_src = true;
            if (fin && !is_fwd) _saw_fin_dst = true;

            /* Argus flags */
            _update_flags(is_fwd, syn, ack, fin, rst, psh, urg, tcp_payload > 0);
        } else {
            /* UDP 状态机 */
            if (state == ArgusState::INIT) state = ArgusState::REQ;
            else if (!is_fwd)              state = ArgusState::EST;
        }
    }

    /* ============================================================
     * 流结束时调用
     * ============================================================ */
    void finalize() noexcept {
        last_time = _ts_last;
        dur = _ts_last - start_time;

        /* 速率 */
        if (dur > 0.0) {
            src_load = src_pkts > 0 ? (double)src_pkts / dur : 0.0;
            dst_load = dst_pkts > 0 ? (double)dst_pkts / dur : 0.0;
            src_rate = src_bytes > 0 ? (double)src_bytes / dur : 0.0;
            dst_rate = dst_bytes > 0 ? (double)dst_bytes / dur : 0.0;
        }

        /* 方向 */
        bool has_src = (src_pkts > 0);
        bool has_dst = (dst_pkts > 0);
        if (has_src && has_dst) {
            bool any_payload = (src_bytes > src_pkts * 40u) ||
                               (dst_bytes > dst_pkts * 40u);
            snprintf(dir, sizeof dir, any_payload ? "<>" : "??");
        } else if (has_src) { snprintf(dir, sizeof dir, "->"); }
        else                 { snprintf(dir, sizeof dir, "<-"); }

        /* short flow → INT */
        if (state == ArgusState::INIT || state == ArgusState::REQ) {
            if (dur < 1.0 && src_pkts + dst_pkts < 3) state = ArgusState::INT;
        }
    }

    /* ============================================================
     * JSON 序列化
     * ============================================================ */
    void emit_json_argus(FILE *fp, const char *ind) const {
        /* ISO 8601 timestamp */
        char ts_start[48], ts_last[48];
        auto fmt_ts = [](double t_sec, char *buf, int bsz) {
            time_t t = (time_t)t_sec;
            unsigned us = (unsigned)((t_sec - (double)t) * 1e6) % 1000000u;
            struct tm *tm = gmtime(&t);
            snprintf(buf, (size_t)bsz, "%04d-%02d-%02dT%02d:%02d:%02d.%06uZ",
                     tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
                     tm->tm_hour, tm->tm_min, tm->tm_sec, us);
        };
        fmt_ts(start_time, ts_start, (int)sizeof ts_start);
        fmt_ts(last_time,  ts_last,  (int)sizeof ts_last);

        fprintf(fp,
            "%s\"argus\": {\n"
            "%s  \"start_time\":       \"%s\",\n"
            "%s  \"last_time\":        \"%s\",\n"
            "%s  \"dur\":              %.6f,\n"
            "%s  \"state\":            \"%s\",\n"
            "%s  \"dir\":              \"%s\",\n"
            "%s  \"sflgs\":            \"%s\",\n"
            "%s  \"dflgs\":            \"%s\",\n"
            "%s  \"service\":          %s,\n"
            "%s  \"src_pkts\":         %llu,\n"
            "%s  \"dst_pkts\":         %llu,\n"
            "%s  \"tot_pkts\":         %llu,\n"
            "%s  \"src_bytes\":        %llu,\n"
            "%s  \"dst_bytes\":        %llu,\n"
            "%s  \"tot_bytes\":        %llu,\n"
            "%s  \"src_load\":         %.4f,\n"
            "%s  \"dst_load\":         %.4f,\n"
            "%s  \"src_rate\":         %.4f,\n"
            "%s  \"dst_rate\":         %.4f,\n"
            "%s  \"src_win\":          %u,\n"
            "%s  \"dst_win\":          %u,\n"
            "%s  \"src_tcp_base\":     %u,\n"
            "%s  \"dst_tcp_base\":     %u,\n"
            "%s  \"syn_ack_rtt_ms\":   %.4f,\n"
            "%s  \"ack_dat_rtt_ms\":   %.4f,\n"
            "%s  \"src_gap\":          %u,\n"
            "%s  \"dst_gap\":          %u,\n"
            "%s  \"syn_cnt\":          %u,\n"
            "%s  \"fin_cnt\":          %u,\n"
            "%s  \"rst_cnt\":          %u,\n"
            "%s  \"psh_cnt\":          %u,\n"
            "%s  \"ack_cnt\":          %u,\n"
            "%s  \"urg_cnt\":          %u,\n"
            "%s  \"src_tos\":          %u,\n"
            "%s  \"dst_tos\":          %u,\n"
            "%s  \"src_ip_id\":        %u,\n"
            "%s  \"dst_ip_id\":        %u,\n"
            "%s  \"src_mean_pkt_sz\":  %.2f,\n"
            "%s  \"dst_mean_pkt_sz\":  %.2f,\n"
            "%s  \"iat_mean_ms\":      %.4f,\n"
            "%s  \"iat_std_ms\":       %.4f,\n"
            "%s  \"src_iat_mean_ms\":  %.4f,\n"
            "%s  \"src_iat_std_ms\":   %.4f,\n"
            "%s  \"dst_iat_mean_ms\":  %.4f,\n"
            "%s  \"dst_iat_std_ms\":   %.4f\n"
            "%s}",
            ind,
            ind, ts_start,
            ind, ts_last,
            ind, dur,
            ind, argus_state_name(state),
            ind, dir,
            ind, sflgs,
            ind, dflgs,
            ind, service ? (std::string("\"") + service + "\"").c_str() : "null",
            ind,(unsigned long long)src_pkts,
            ind,(unsigned long long)dst_pkts,
            ind,(unsigned long long)(src_pkts+dst_pkts),
            ind,(unsigned long long)src_bytes,
            ind,(unsigned long long)dst_bytes,
            ind,(unsigned long long)(src_bytes+dst_bytes),
            ind,src_load, ind,dst_load,
            ind,src_rate, ind,dst_rate,
            ind,src_win, ind,dst_win,
            ind,src_tcp_base, ind,dst_tcp_base,
            ind,syn_ack_rtt_ms, ind,ack_dat_rtt_ms,
            ind,src_gap, ind,dst_gap,
            ind,syn_cnt, ind,fin_cnt, ind,rst_cnt,
            ind,psh_cnt, ind,ack_cnt, ind,urg_cnt,
            ind,(unsigned)src_tos, ind,(unsigned)dst_tos,
            ind,(unsigned)src_ip_id, ind,(unsigned)dst_ip_id,
            ind, src_pkt_len.n > 0 ? src_pkt_len.mean : 0.0,
            ind, dst_pkt_len.n > 0 ? dst_pkt_len.mean : 0.0,
            ind, all_iat.mean, ind, all_iat.std(),
            ind, src_iat.mean, ind, src_iat.std(),
            ind, dst_iat.mean, ind, dst_iat.std(),
            ind);
    }

private:
    /* 追加 flag 字符到 sflgs/dflgs */
    void _update_flags(bool is_fwd, bool syn, bool ack, bool fin,
                       bool rst, bool psh, bool urg, bool has_data) noexcept {
        char *flags = is_fwd ? sflgs : dflgs;
        int  len    = (int)strnlen(flags, 15);
        auto append = [&](char c) {
            if (len < 14 && !strchr(flags, c)) { flags[len++] = c; flags[len] = '\0'; }
        };
        if (_established)                     append('e');
        if (syn && !ack)                      append('s');
        if (syn && ack)                       append('S');
        if (has_data && is_fwd)               append('d');
        if (has_data && !is_fwd)              append('D');
        if (fin && is_fwd)                    append('f');
        if (fin && !is_fwd)                   append('F');
        if (rst && is_fwd)                    append('r');
        if (rst && !is_fwd)                   append('R');
        if (urg)                              append('u');
        (void)psh; (void)ack;
    }
};
