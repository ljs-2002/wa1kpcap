/**
 * ftp_flow.h  ——  FTP 控制通道元特征提取（Header-Only）
 *
 * TCP 21 / 990（FTPS 控制）
 * 解析 USER/PASS/SYST/FEAT/PASV/PORT/RETR/STOR/LIST/TYPE 等命令与响应码。
 * 不记录 PASS 明文（仅标记是否出现）。
 * 输出：JSON Lines，每行一条流。
 */
#pragma once

#include "json_log.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

static constexpr int FTP_MAX_EVENTS = 256;
static constexpr int FTP_LINE_BUF   = 4096;

static inline bool is_ftp_port(uint16_t p) {
    return p == 21 || p == 990;
}

struct FtpEvent {
    double   ts;
    bool     is_client;
    char     line[512];
    uint16_t resp_code;
};

struct FtpFlowRecord {
    char     flow_id[96];
    char     src_ip[INET_ADDRSTRLEN];
    char     dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    double   first_ts;
    double   last_ts;

    char     cli_buf[FTP_LINE_BUF];
    int      cli_len;
    char     srv_buf[FTP_LINE_BUF];
    int      srv_len;

    FtpEvent events[FTP_MAX_EVENTS];
    int      n_events;

    char     banner[256];
    char     username[128];
    char     syst_reply[128];
    bool     pass_seen;
    bool     login_ok;
    bool     passive_mode;
    bool     active_mode;
    bool     feat_seen;
    bool     tls_implicit;   /* 990 */
    uint32_t cmd_user;
    uint32_t cmd_retr;
    uint32_t cmd_stor;
    uint32_t cmd_list;
    uint32_t cmd_pasv;
    uint32_t cmd_port;
    uint32_t resp_2xx;
    uint32_t resp_3xx;
    uint32_t resp_4xx;
    uint32_t resp_5xx;
    char     pasv_host[64];
    uint16_t pasv_port;

    void init(const char* fid, uint8_t pr,
              uint32_t sip, uint32_t dip,
              uint16_t sport, uint16_t dport) noexcept {
        memset(this, 0, sizeof(*this));
        strncpy(flow_id, fid, sizeof(flow_id) - 1);
        proto = pr;
        src_port = sport;
        dst_port = dport;
        tls_implicit = is_ftp_port(dport) && dport == 990;
        in_addr sa{sip}, da{dip};
        inet_ntop(AF_INET, &sa, src_ip, sizeof src_ip);
        inet_ntop(AF_INET, &da, dst_ip, sizeof dst_ip);
    }

    static void trim_crlf(char* s) {
        int n = (int)strlen(s);
        while (n > 0 && (s[n-1] == '\r' || s[n-1] == '\n')) s[--n] = '\0';
    }

    void push_event(double ts, bool is_client, const char* line, uint16_t code = 0) {
        if (n_events >= FTP_MAX_EVENTS) return;
        FtpEvent& e = events[n_events++];
        e.ts = ts;
        e.is_client = is_client;
        strncpy(e.line, line, sizeof(e.line) - 1);
        e.resp_code = code;
    }

    static bool parse_pasv227(const char* line, char* host, int hlen, uint16_t* port) {
        const char* p = strchr(line, '(');
        if (!p) p = strrchr(line, ' ');
        if (!p) return false;
        while (*p && *p != '(' && *p != ' ') p++;
        if (*p == '(') p++;
        int h1,h2,h3,h4,p1,p2;
        if (sscanf(p, "%d,%d,%d,%d,%d,%d", &h1,&h2,&h3,&h4,&p1,&p2) != 6) return false;
        snprintf(host, (size_t)hlen, "%d.%d.%d.%d", h1,h2,h3,h4);
        *port = (uint16_t)(p1 * 256 + p2);
        return true;
    }

    void parse_client_line(double ts, char* line) {
        trim_crlf(line);
        if (!line[0]) return;
        push_event(ts, true, line);

        char ucmd[16] = {};
        for (int i = 0; line[i] && line[i] != ' ' && i < 15; i++)
            ucmd[i] = (char)toupper((unsigned char)line[i]);

        if (!strcmp(ucmd, "USER")) {
            cmd_user++;
            const char* sp = strchr(line, ' ');
            if (sp) strncpy(username, sp + 1, sizeof(username) - 1);
        } else if (!strcmp(ucmd, "PASS")) {
            pass_seen = true;
            /* 不保存密码 */
        } else if (!strcmp(ucmd, "PASV") || !strcmp(ucmd, "EPSV")) {
            cmd_pasv++;
            passive_mode = true;
        } else if (!strcmp(ucmd, "PORT") || !strcmp(ucmd, "EPRT")) {
            cmd_port++;
            active_mode = true;
        } else if (!strcmp(ucmd, "RETR")) cmd_retr++;
        else if (!strcmp(ucmd, "STOR") || !strcmp(ucmd, "STOU") || !strcmp(ucmd, "APPE")) cmd_stor++;
        else if (!strcmp(ucmd, "LIST") || !strcmp(ucmd, "NLST") || !strcmp(ucmd, "MLSD")) cmd_list++;
        else if (!strcmp(ucmd, "FEAT")) feat_seen = true;
    }

    void parse_server_line(double ts, char* line) {
        trim_crlf(line);
        if (!line[0]) return;
        uint16_t code = 0;
        if (isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1]) &&
            isdigit((unsigned char)line[2]))
            code = (uint16_t)((line[0]-'0')*100 + (line[1]-'0')*10 + (line[2]-'0'));

        push_event(ts, false, line, code);

        if (code >= 200 && code < 300) {
            resp_2xx++;
            if (code == 220 && !banner[0]) strncpy(banner, line, sizeof(banner) - 1);
            if (code == 230) login_ok = true;
            if (code == 215) strncpy(syst_reply, line, sizeof(syst_reply) - 1);
            if (code == 227)
                parse_pasv227(line, pasv_host, sizeof pasv_host, &pasv_port);
        } else if (code >= 300 && code < 400) resp_3xx++;
        else if (code >= 400 && code < 500) resp_4xx++;
        else if (code >= 500 && code < 600) resp_5xx++;

        if (code == 220 && !banner[0]) strncpy(banner, line, sizeof(banner) - 1);
    }

    static void drain_lines(char* buf, int& len, bool is_client,
                            FtpFlowRecord* rec, double ts) {
        int start = 0;
        for (int i = 0; i < len; i++) {
            if (buf[i] != '\n') continue;
            buf[i] = '\0';
            char* line = buf + start;
            if (is_client) rec->parse_client_line(ts, line);
            else           rec->parse_server_line(ts, line);
            start = i + 1;
        }
        if (start > 0) {
            int rem = len - start;
            memmove(buf, buf + start, (size_t)rem);
            len = rem;
            buf[len] = '\0';
        }
    }

    void add_payload(bool is_client, double ts,
                     const uint8_t* data, int dlen) {
        if (dlen <= 0) return;
        if (first_ts == 0.0) first_ts = ts;
        last_ts = ts;

        char* buf = is_client ? cli_buf : srv_buf;
        int& blen = is_client ? cli_len : srv_len;
        int copy = dlen;
        if (blen + copy >= FTP_LINE_BUF - 1)
            copy = FTP_LINE_BUF - 1 - blen;
        if (copy <= 0) return;
        memcpy(buf + blen, data, (size_t)copy);
        blen += copy;
        buf[blen] = '\0';
        drain_lines(buf, blen, is_client, this, ts);
    }

    void emit_json(FILE* f, const char* pcap_file) const {
        fprintf(f, "{\"file\":");
        json_esc_cstr(f, pcap_file);
        fprintf(f, ",\"flow_id\":");
        json_esc_cstr(f, flow_id);
        fprintf(f, ",\"protocol\":\"FTP\",");
        json_five_tuple(f, src_ip, src_port, dst_ip, dst_port, proto);
        fprintf(f, ",\"first_ts\":%.6f,\"last_ts\":%.6f", first_ts, last_ts);

        fprintf(f, ",\"meta\":{"
                "\"banner\":");
        json_esc_cstr(f, banner);
        fprintf(f, ",\"username\":");
        json_esc_cstr(f, username);
        fprintf(f, ",\"syst_reply\":");
        json_esc_cstr(f, syst_reply);
        fprintf(f, ",\"pass_seen\":%s,\"login_ok\":%s,"
                "\"passive_mode\":%s,\"active_mode\":%s,\"feat_seen\":%s,"
                "\"tls_implicit\":%s",
                pass_seen ? "true" : "false",
                login_ok ? "true" : "false",
                passive_mode ? "true" : "false",
                active_mode ? "true" : "false",
                feat_seen ? "true" : "false",
                tls_implicit ? "true" : "false");
        fprintf(f, ",\"pasv_host\":");
        json_esc_cstr(f, pasv_host);
        fprintf(f, ",\"pasv_port\":%u", (unsigned)pasv_port);
        fprintf(f, ",\"cmd_counts\":{\"user\":%u,\"retr\":%u,\"stor\":%u,"
                "\"list\":%u,\"pasv\":%u,\"port\":%u}",
                cmd_user, cmd_retr, cmd_stor, cmd_list, cmd_pasv, cmd_port);
        fprintf(f, ",\"resp_counts\":{\"2xx\":%u,\"3xx\":%u,\"4xx\":%u,\"5xx\":%u}",
                resp_2xx, resp_3xx, resp_4xx, resp_5xx);
        fprintf(f, "},\"n_events\":%d,\"events\":[", n_events);

        for (int i = 0; i < n_events; i++) {
            if (i) fputc(',', f);
            const FtpEvent& e = events[i];
            fprintf(f, "{\"ts\":%.6f,\"dir\":\"%s\",\"line\":",
                    e.ts, e.is_client ? "c2s" : "s2c");
            json_esc_cstr(f, e.line);
            if (!e.is_client && e.resp_code)
                fprintf(f, ",\"code\":%u", (unsigned)e.resp_code);
            fputc('}', f);
        }
        fprintf(f, "]}\n");
    }
};
