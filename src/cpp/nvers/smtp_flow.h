/**
 * smtp_flow.h  ——  SMTP 元特征提取（Header-Only）
 *
 * 端口：25 / 465 / 587 / 2525（TCP）
 * 按行解析命令与响应，汇总 EHLO、MAIL、RCPT、AUTH、STARTTLS 等元数据。
 * 输出：JSON Lines，每行一条流。
 */
#pragma once

#include "json_log.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

static constexpr int SMTP_MAX_EVENTS = 128;
static constexpr int SMTP_LINE_BUF   = 4096;
static constexpr int SMTP_MAX_RCPT   = 32;

static inline bool is_smtp_port(uint16_t p) {
    return p == 25 || p == 465 || p == 587 || p == 2525;
}

struct SmtpEvent {
    double   ts;
    bool     is_client;
    char     line[512];
    uint16_t resp_code;   /* 仅服务端响应 */
};

struct SmtpFlowRecord {
    char     flow_id[96];
    char     src_ip[INET_ADDRSTRLEN];
    char     dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    double   first_ts;
    double   last_ts;

    char     cli_buf[SMTP_LINE_BUF];
    int      cli_len;
    char     srv_buf[SMTP_LINE_BUF];
    int      srv_len;

    SmtpEvent events[SMTP_MAX_EVENTS];
    int      n_events;

    /* 元特征 */
    char     server_greeting[256];
    char     ehlo_host[256];
    char     mail_from[256];
    char     rcpt_to[SMTP_MAX_RCPT][256];
    int      n_rcpt;
    char     auth_method[64];
    bool     starttls_seen;
    bool     auth_seen;
    bool     data_seen;
    bool     login_ok;
    uint32_t cmd_ehlo;
    uint32_t cmd_mail;
    uint32_t cmd_rcpt;
    uint32_t cmd_data;
    uint32_t cmd_quit;
    uint32_t resp_2xx;
    uint32_t resp_3xx;
    uint32_t resp_4xx;
    uint32_t resp_5xx;

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

    static void trim_crlf(char* s) {
        int n = (int)strlen(s);
        while (n > 0 && (s[n-1] == '\r' || s[n-1] == '\n')) s[--n] = '\0';
    }

    void push_event(double ts, bool is_client, const char* line, uint16_t code = 0) {
        if (n_events >= SMTP_MAX_EVENTS) return;
        SmtpEvent& e = events[n_events++];
        e.ts = ts;
        e.is_client = is_client;
        strncpy(e.line, line, sizeof(e.line) - 1);
        e.resp_code = code;
    }

    void parse_client_line(double ts, char* line) {
        trim_crlf(line);
        if (!line[0]) return;
        push_event(ts, true, line);

        char ucmd[16] = {};
        for (int i = 0; line[i] && i < 15; i++)
            ucmd[i] = (char)toupper((unsigned char)line[i]);
        ucmd[15] = '\0';

        if (!strncmp(ucmd, "EHLO", 4) || !strncmp(ucmd, "HELO", 4)) {
            cmd_ehlo++;
            const char* sp = strchr(line, ' ');
            if (sp) strncpy(ehlo_host, sp + 1, sizeof(ehlo_host) - 1);
        } else if (!strncmp(ucmd, "MAIL FROM", 9)) {
            cmd_mail++;
            const char* p = strchr(line, '<');
            if (p) {
                const char* q = strchr(p + 1, '>');
                int len = q ? (int)(q - p - 1) : (int)strlen(p + 1);
                if (len > (int)sizeof(mail_from) - 1) len = (int)sizeof(mail_from) - 1;
                memcpy(mail_from, p + 1, (size_t)len);
                mail_from[len] = '\0';
            }
        } else if (!strncmp(ucmd, "RCPT TO", 7)) {
            cmd_rcpt++;
            if (n_rcpt < SMTP_MAX_RCPT) {
                const char* p = strchr(line, '<');
                if (p) {
                    const char* q = strchr(p + 1, '>');
                    int len = q ? (int)(q - p - 1) : (int)strlen(p + 1);
                    if (len > 255) len = 255;
                    memcpy(rcpt_to[n_rcpt], p + 1, (size_t)len);
                    rcpt_to[n_rcpt][len] = '\0';
                    n_rcpt++;
                }
            }
        } else if (!strncmp(ucmd, "DATA", 4)) {
            cmd_data++;
            data_seen = true;
        } else if (!strncmp(ucmd, "AUTH", 4)) {
            auth_seen = true;
            const char* sp = strchr(line, ' ');
            if (sp) strncpy(auth_method, sp + 1, sizeof(auth_method) - 1);
        } else if (!strncmp(ucmd, "STARTTLS", 8)) {
            starttls_seen = true;
        } else if (!strncmp(ucmd, "QUIT", 4)) {
            cmd_quit++;
        }
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
            if (code == 220 && !server_greeting[0])
                strncpy(server_greeting, line, sizeof(server_greeting) - 1);
            if (code == 235 || code == 250) login_ok = true;
        } else if (code >= 300 && code < 400) resp_3xx++;
        else if (code >= 400 && code < 500) resp_4xx++;
        else if (code >= 500 && code < 600) resp_5xx++;

        if (code == 220 && !server_greeting[0])
            strncpy(server_greeting, line, sizeof(server_greeting) - 1);

        /* EHLO 多行响应中的 STARTTLS/AUTH 能力 */
        if (strstr(line, "STARTTLS")) starttls_seen = true;
        if (strstr(line, "AUTH ")) {
            auth_seen = true;
            const char* ap = strstr(line, "AUTH ");
            if (ap) strncpy(auth_method, ap + 5, sizeof(auth_method) - 1);
        }
    }

    static void drain_lines(char* buf, int& len, bool is_client,
                            SmtpFlowRecord* rec, double ts) {
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
        if (blen + copy >= SMTP_LINE_BUF - 1)
            copy = SMTP_LINE_BUF - 1 - blen;
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
        fprintf(f, ",\"protocol\":\"SMTP\",");
        json_five_tuple(f, src_ip, src_port, dst_ip, dst_port, proto);
        fprintf(f, ",\"first_ts\":%.6f,\"last_ts\":%.6f", first_ts, last_ts);

        fprintf(f, ",\"meta\":{"
                "\"server_greeting\":");
        json_esc_cstr(f, server_greeting);
        fprintf(f, ",\"ehlo_host\":");
        json_esc_cstr(f, ehlo_host);
        fprintf(f, ",\"mail_from\":");
        json_esc_cstr(f, mail_from);
        fprintf(f, ",\"rcpt_to\":[");
        for (int i = 0; i < n_rcpt; i++) {
            if (i) fputc(',', f);
            json_esc_cstr(f, rcpt_to[i]);
        }
        fprintf(f, "],\"auth_method\":");
        json_esc_cstr(f, auth_method);
        fprintf(f, ",\"starttls_seen\":%s,\"auth_seen\":%s,\"data_seen\":%s,\"login_ok\":%s",
                starttls_seen ? "true" : "false",
                auth_seen ? "true" : "false",
                data_seen ? "true" : "false",
                login_ok ? "true" : "false");
        fprintf(f, ",\"cmd_counts\":{\"ehlo\":%u,\"mail\":%u,\"rcpt\":%u,\"data\":%u,\"quit\":%u}",
                cmd_ehlo, cmd_mail, cmd_rcpt, cmd_data, cmd_quit);
        fprintf(f, ",\"resp_counts\":{\"2xx\":%u,\"3xx\":%u,\"4xx\":%u,\"5xx\":%u}",
                resp_2xx, resp_3xx, resp_4xx, resp_5xx);
        fprintf(f, "},\"n_events\":%d,\"events\":[", n_events);

        for (int i = 0; i < n_events; i++) {
            if (i) fputc(',', f);
            const SmtpEvent& e = events[i];
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
