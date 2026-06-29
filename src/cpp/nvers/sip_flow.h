/**
 * sip_flow.h  ——  SIP 协议深度字段解析（Header-Only）
 *
 * 标准：RFC 3261 (SIP: Session Initiation Protocol)
 *       RFC 3264 (Offer/Answer with SDP)
 *       RFC 4566 (SDP: Session Description Protocol)
 *       RFC 3262, 3311, 3428, 3515, 3903, 6665 (SIP extensions)
 *
 * 默认端口：UDP/TCP 5060, TLS-SIP 5061
 *
 * 提取的元信息：
 *   ─ 请求/响应行 ─
 *   method        (INVITE / REGISTER / BYE / ACK / CANCEL / OPTIONS /
 *                  SUBSCRIBE / NOTIFY / REFER / INFO / UPDATE / MESSAGE /
 *                  PRACK / PUBLISH)
 *   request_uri   ("sip:bob@biloxi.com")
 *   sip_version   ("SIP/2.0")
 *   status_code   (100–699)  status_reason
 *   ─ 核心头域（RFC 3261 必选）─
 *   via           (transport, hop branch, rport, received)
 *   via_hops      (Via 条目数 = hop count)
 *   from_uri      from_tag  from_displayname
 *   to_uri        to_tag    to_displayname
 *   call_id
 *   cseq_num      cseq_method
 *   ─ 路由 ─
 *   contact_uri   contact_expires
 *   record_route[8]  (路由列表，最多8条)
 *   route[8]         (预载路由)
 *   ─ 能力 / 扩展 ─
 *   allow_methods     (Allow: 头)
 *   supported_exts    (Supported:)
 *   require_exts      (Require:)
 *   proxy_require
 *   ─ 内容 ─
 *   content_type    content_length  content_encoding
 *   ─ 认证 ─
 *   auth_scheme     auth_realm      auth_algorithm
 *   auth_qop        auth_username   auth_nonce
 *   ─ 事件 / 订阅 ─
 *   event_type      subscription_state  subscription_expires
 *   ─ 超时 ─
 *   expires_secs    session_expires
 *   ─ 用户代理 ─
 *   user_agent      server_str      organization
 *   ─ QoS / 优先级 ─
 *   priority        call_info       subject
 *   ─ SDP 媒体（来自消息体）─
 *   sdp_version     sdp_origin_user   sdp_session_name
 *   sdp_connection_addr   sdp_timing
 *   media[8]:  type(audio/video/application), port, proto,
 *              codecs, direction(sendrecv/sendonly/recvonly/inactive)
 *   ─ 流统计 ─
 *   request_cnt[METHOD_COUNT]  (各方法计数)
 *   response_cnt[7]            (1xx~6xx 各类计数)
 *   transaction_cnt            rtp_port_hints
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

/* ============================================================
 * SIP Method 枚举
 * ============================================================ */
enum SipMethod : uint8_t {
    SIP_NONE=0, SIP_INVITE, SIP_REGISTER, SIP_BYE, SIP_ACK,
    SIP_CANCEL, SIP_OPTIONS, SIP_SUBSCRIBE, SIP_NOTIFY,
    SIP_REFER, SIP_INFO, SIP_UPDATE, SIP_MESSAGE, SIP_PRACK,
    SIP_PUBLISH, SIP_METHOD_MAX
};

static inline const char *sip_method_name(SipMethod m) {
    static const char *names[] = {
        "NONE","INVITE","REGISTER","BYE","ACK","CANCEL","OPTIONS",
        "SUBSCRIBE","NOTIFY","REFER","INFO","UPDATE","MESSAGE","PRACK","PUBLISH"
    };
    return (unsigned)m < SIP_METHOD_MAX ? names[m] : "?";
}

static inline SipMethod sip_parse_method(const char *s, int len) {
    struct { const char *name; SipMethod m; } table[] = {
        {"INVITE",SIP_INVITE},{"REGISTER",SIP_REGISTER},{"BYE",SIP_BYE},
        {"ACK",SIP_ACK},{"CANCEL",SIP_CANCEL},{"OPTIONS",SIP_OPTIONS},
        {"SUBSCRIBE",SIP_SUBSCRIBE},{"NOTIFY",SIP_NOTIFY},{"REFER",SIP_REFER},
        {"INFO",SIP_INFO},{"UPDATE",SIP_UPDATE},{"MESSAGE",SIP_MESSAGE},
        {"PRACK",SIP_PRACK},{"PUBLISH",SIP_PUBLISH},{nullptr,SIP_NONE}
    };
    for (int i = 0; table[i].name; i++) {
        int nlen = (int)strlen(table[i].name);
        if (nlen == len && memcmp(s, table[i].name, (size_t)len) == 0)
            return table[i].m;
    }
    return SIP_NONE;
}

/* ============================================================
 * 快速识别：是否为 SIP 消息
 * ============================================================ */
static inline bool detect_sip(const uint8_t *payload, int len) {
    if (len < 8) return false;
    /* 请求: "METHOD sip:" 或 "METHOD tel:" */
    if (memcmp(payload, "SIP/2.0 ", 8) == 0) return true;  /* 响应 */
    /* 常见方法前缀 */
    static const char *pfx[] = {"INVITE ","REGISTER","BYE ","ACK ",
                                  "CANCEL ","OPTIONS ","SUBSCRIBE",
                                  "NOTIFY ","REFER ","INFO ","UPDATE ",
                                  "MESSAGE ","PRACK ","PUBLISH ",nullptr};
    for (int i = 0; pfx[i]; i++) {
        int plen = (int)strlen(pfx[i]);
        if (len >= plen && memcmp(payload, pfx[i], (size_t)plen) == 0) return true;
    }
    return false;
}

/* ============================================================
 * SDP 媒体行
 * ============================================================ */
struct SipSdpMedia {
    char type[16];            /* "audio" / "video" / "application"        */
    uint16_t port;            /* RTP 端口                                 */
    char proto[16];           /* "RTP/AVP" / "RTP/SAVP" / "UDP/TLS/RTP/SAVPF" */
    char codecs[128];         /* 格式列表 "0 8 18 101"                    */
    char direction[16];       /* sendrecv / sendonly / recvonly / inactive */
    char rtpmap[256];         /* a=rtpmap 行集合                          */
    char fmtp[128];           /* a=fmtp 参数                              */
};

/* ============================================================
 * 内部辅助：在 buf[0..len) 中查找头域值
 * ============================================================ */
static inline const char *sip__find_header(const char *buf, int len,
                                            const char *name,
                                            char *val, int valsz) {
    int nl = (int)strlen(name);
    for (int i = 0; i < len - nl - 1; i++) {
        if ((buf[i]=='\r'||buf[i]=='\n') || i==0) {
            int start = (i==0) ? 0 : i+1;
            if (start + nl + 1 >= len) continue;
            if (strncasecmp(buf + start, name, (size_t)nl) == 0) {
                char c = buf[start + nl];
                if (c == ':' || c == ' ') {
                    int vi = start + nl + 1;
                    while (vi < len && (buf[vi]==' '||buf[vi]=='\t')) vi++;
                    int ve = vi;
                    while (ve < len && buf[ve]!='\r' && buf[ve]!='\n') ve++;
                    int cp = std::min(ve - vi, valsz - 1);
                    if (cp > 0) memcpy(val, buf + vi, (size_t)cp);
                    val[std::max(cp,0)] = '\0';
                    return val;
                }
            }
        }
    }
    return nullptr;
}

/* 从 addr 字符串提取 <URI> 或裸 URI 与 displayname */
static inline void sip__parse_addr(const char *addr, char *uri, int uri_sz,
                                    char *tag, int tag_sz,
                                    char *display, int disp_sz) {
    uri[0] = tag[0] = display[0] = '\0';
    /* displayname */
    const char *lt = strchr(addr, '<');
    if (lt) {
        int dlen = (int)(lt - addr);
        /* strip quotes */
        const char *dp = addr;
        if (*dp == '"') { dp++; dlen -= 2; }
        int cp = std::min(dlen, disp_sz - 1);
        if (cp > 0) { memcpy(display, dp, (size_t)cp); display[cp] = '\0'; }
        /* URI */
        const char *gt = strchr(lt, '>');
        int ulen = gt ? (int)(gt - lt - 1) : (int)strlen(lt + 1);
        cp = std::min(ulen, uri_sz - 1);
        memcpy(uri, lt + 1, (size_t)cp); uri[cp] = '\0';
    } else {
        /* No angle brackets */
        const char *sc = strchr(addr, ';');
        int ulen = sc ? (int)(sc - addr) : (int)strlen(addr);
        /* Trim trailing space */
        while (ulen > 0 && addr[ulen-1] == ' ') ulen--;
        int cp = std::min(ulen, uri_sz - 1);
        memcpy(uri, addr, (size_t)cp); uri[cp] = '\0';
    }
    /* tag=... */
    const char *tp = strstr(addr, ";tag=");
    if (tp) {
        tp += 5;
        const char *te = tp;
        while (*te && *te!=';' && *te!=',' && *te!=' ') te++;
        int cp = std::min((int)(te-tp), tag_sz - 1);
        memcpy(tag, tp, (size_t)cp); tag[cp] = '\0';
    }
}

/* ============================================================
 * SIP 流记录
 * ============================================================ */
struct SipFlowRecord {

    /* ---- 最后/第一个请求行 ---- */
    SipMethod first_method;       /* 首个请求方法                         */
    char      request_uri[128];   /* 请求 URI                             */
    char      sip_version[16];    /* "SIP/2.0"                            */
    uint16_t  last_status_code;   /* 最后一个响应码                       */
    char      last_status_reason[64];

    /* ---- 核心头域（首个完整消息） ---- */
    char via_first[128];          /* 第一个 Via 条目                      */
    char via_transport[8];        /* UDP / TCP / TLS                      */
    char via_branch[64];          /* branch=z9hG4bK...                   */
    uint8_t via_hops;             /* Via 条目总数                         */

    char from_uri[128];
    char from_tag[64];
    char from_display[64];
    char to_uri[128];
    char to_tag[64];
    char to_display[64];
    char call_id[128];
    uint32_t cseq_num;
    char     cseq_method[16];

    /* ---- 路由 ---- */
    char contact_uri[128];
    uint32_t contact_expires;
    char record_route[8][128];
    uint8_t record_route_cnt;
    char route[8][128];
    uint8_t route_cnt;

    /* ---- 能力 ---- */
    char allow_methods[256];      /* Allow: INVITE, ACK, BYE, ...         */
    char supported_exts[256];     /* Supported: 100rel, timer, ...        */
    char require_exts[128];       /* Require:                             */
    char proxy_require[128];

    /* ---- 内容 ---- */
    char content_type[64];        /* "application/sdp" / "text/plain"     */
    uint32_t content_length;
    char content_encoding[32];

    /* ---- 认证 ---- */
    char auth_scheme[16];         /* "Digest"                             */
    char auth_realm[128];
    char auth_algorithm[16];      /* "MD5" / "SHA-256"                    */
    char auth_qop[16];            /* "auth" / "auth-int"                  */
    char auth_username[64];
    char auth_nonce[64];
    bool has_www_auth;
    bool has_proxy_auth;

    /* ---- 事件 / 订阅 ---- */
    char event_type[64];          /* presence / message-summary / ...     */
    char subscription_state[32];  /* active / pending / terminated        */
    uint32_t subscription_expires;

    /* ---- 超时 ---- */
    uint32_t expires_secs;
    uint32_t session_expires;
    char min_se[16];              /* Min-SE:                              */

    /* ---- 用户信息 ---- */
    char user_agent[128];
    char server_str[128];
    char organization[64];
    char subject[64];
    char call_info[128];          /* Call-Info: 头                        */
    char priority[16];            /* emergency / urgent / normal / ...    */

    /* ---- 历史/路径 ---- */
    char p_asserted_id[128];      /* P-Asserted-Identity                  */
    char p_preferred_id[128];     /* P-Preferred-Identity                 */
    char diversion[128];          /* Diversion:                           */
    char referred_by[128];        /* Referred-By:                         */
    char replaces[128];           /* Replaces:                            */

    /* ---- SDP 媒体信息 ---- */
    uint8_t     sdp_version;
    char        sdp_origin_user[64];    /* o= 行用户字段                  */
    char        sdp_origin_addr[64];    /* o= 行地址                      */
    char        sdp_session_name[64];
    char        sdp_conn_addr[64];      /* c= 行连接地址                  */
    char        sdp_timing[32];         /* t= 行                          */
    char        sdp_bandwidth[32];      /* b= 行                          */
    SipSdpMedia sdp_media[8];
    uint8_t     sdp_media_cnt;

    /* ---- 流统计 ---- */
    uint32_t method_cnt[SIP_METHOD_MAX]; /* 各方法出现次数                */
    uint32_t resp_1xx, resp_2xx, resp_3xx, resp_4xx, resp_5xx, resp_6xx;
    uint32_t total_msgs;
    uint32_t transaction_cnt;           /* Call-ID + CSeq 唯一事务数     */
    uint32_t rtp_port_hints[16];        /* SDP 中出现的 RTP 端口         */
    uint8_t  rtp_port_cnt;

    /* ---- 内部缓冲（用于 TCP 流重组）---- */
    static const int BUF_SZ = 4096;
    char _fwd_buf[BUF_SZ]; int _fwd_len;
    char _bwd_buf[BUF_SZ]; int _bwd_len;

    /* ============================================================
     * 初始化
     * ============================================================ */
    void init() noexcept {
        memset(this, 0, sizeof *this);
    }

    /* ============================================================
     * 解析 SDP body（msg_body 为 \r\n\r\n 之后的内容）
     * ============================================================ */
    void _parse_sdp(const char *body, int blen) {
        if (blen <= 0) return;
        const char *p = body;
        const char *end = body + blen;
        SipSdpMedia *cur = nullptr;

        while (p < end) {
            /* 找到行结束 */
            const char *nl = p;
            while (nl < end && *nl != '\r' && *nl != '\n') nl++;
            int llen = (int)(nl - p);
            if (llen < 2 || p[1] != '=') { p = nl + 1; if (p < end && *p=='\n') p++; continue; }

            char type = p[0];
            const char *val = p + 2;
            int vlen = llen - 2;
            char vbuf[256];
            int cp = std::min(vlen, 255);
            memcpy(vbuf, val, (size_t)cp); vbuf[cp] = '\0';

            switch (type) {
            /* 各 SDP 字段均以 vbuf 最大 255 字节截断写入目标 */
            case 'v': sdp_version = (uint8_t)atoi(vbuf); break;
            case 'o': {
                /* o=<user> <sess-id> <sess-ver> <nettype> <addrtype> <addr> */
                char *tok = vbuf;
                char *sp2 = strchr(tok, ' ');
                if (sp2) { *sp2 = '\0'; snprintf(sdp_origin_user, sizeof sdp_origin_user, "%s", tok); tok = sp2+1; }
                /* skip sess-id sess-ver nettype addrtype */
                for (int i = 0; i < 4; i++) { sp2 = strchr(tok,' '); if (!sp2) break; tok = sp2+1; }
                snprintf(sdp_origin_addr, sizeof sdp_origin_addr, "%s", tok);
                break;
            }
            case 's': snprintf(sdp_session_name, sizeof sdp_session_name, "%.*s", (int)sizeof(sdp_session_name)-1, vbuf); break;
            case 'c': {
                /* c=IN IP4 addr */
                char *last = strrchr(vbuf, ' ');
                if (last) snprintf(sdp_conn_addr, sizeof sdp_conn_addr, "%.*s", (int)sizeof(sdp_conn_addr)-1, last+1);
                break;
            }
            case 't': snprintf(sdp_timing,    sizeof sdp_timing,    "%.*s", (int)sizeof(sdp_timing)-1,    vbuf); break;
            case 'b': snprintf(sdp_bandwidth, sizeof sdp_bandwidth, "%.*s", (int)sizeof(sdp_bandwidth)-1, vbuf); break;
            case 'm': {
                /* m=<type> <port> <proto> <fmts...> */
                if (sdp_media_cnt < 8) {
                    cur = &sdp_media[sdp_media_cnt++];
                    memset(cur, 0, sizeof *cur);
                    char mtype[16]="", mproto[32]=""; int mport=0;
                    sscanf(vbuf, "%15s %d %31s %127[^\r\n]",
                           mtype, &mport, mproto, cur->codecs);
                    snprintf(cur->type,  sizeof cur->type,  "%s", mtype);
                    snprintf(cur->proto, sizeof cur->proto, "%s", mproto);
                    cur->port = (uint16_t)mport;
                    /* record RTP port hint */
                    if (rtp_port_cnt < 16 && mport > 0)
                        rtp_port_hints[rtp_port_cnt++] = (uint32_t)mport;
                }
                break;
            }
            case 'a': {
                if (!cur) break;
                /* a=sendrecv / sendonly / recvonly / inactive */
                if (strcmp(vbuf,"sendrecv")==0 || strcmp(vbuf,"sendonly")==0 ||
                    strcmp(vbuf,"recvonly")==0 || strcmp(vbuf,"inactive")==0) {
                    snprintf(cur->direction, sizeof cur->direction, "%s", vbuf);
                } else if (strncmp(vbuf,"rtpmap:",7)==0) {
                    int rlen = (int)strlen(cur->rtpmap);
                    if (rlen < (int)sizeof(cur->rtpmap) - 2) {
                        if (rlen > 0) cur->rtpmap[rlen++] = ';';
                        snprintf(cur->rtpmap + rlen, sizeof(cur->rtpmap) - rlen, "%s", vbuf+7);
                    }
                } else if (strncmp(vbuf,"fmtp:",5)==0) {
                    snprintf(cur->fmtp, sizeof cur->fmtp, "%s", vbuf+5);
                }
                break;
            }
            default: break;
            }
            p = nl + 1;
            if (p < end && *p == '\n') p++;
        }
    }

    /* ============================================================
     * 解析一个完整的 SIP 消息（buf 包含请求行/响应行 + 头域 + 空行 + body）
     * ============================================================ */
    void _parse_message(const char *buf, int len) {
        if (len < 8) return;
        total_msgs++;

        /* ---- 首行 ---- */
        const char *nl = buf;
        while (nl < buf+len && *nl!='\r' && *nl!='\n') nl++;
        char first_line[256];
        int flen = std::min((int)(nl - buf), 255);
        memcpy(first_line, buf, (size_t)flen); first_line[flen] = '\0';

        if (strncmp(buf, "SIP/2.0 ", 8) == 0) {
            /* 响应 */
            last_status_code = (uint16_t)atoi(buf + 8);
            snprintf(last_status_reason, sizeof last_status_reason, "%s", buf + 12);
            /* 截断 \r\n */
            for (char *p = last_status_reason; *p; p++) if (*p=='\r'||*p=='\n') { *p='\0'; break; }
            if      (last_status_code < 200) resp_1xx++;
            else if (last_status_code < 300) resp_2xx++;
            else if (last_status_code < 400) resp_3xx++;
            else if (last_status_code < 500) resp_4xx++;
            else if (last_status_code < 600) resp_5xx++;
            else                             resp_6xx++;
        } else {
            /* 请求 */
            char *sp = strchr(first_line, ' ');
            if (sp) {
                SipMethod m = sip_parse_method(first_line, (int)(sp - first_line));
                if (m != SIP_NONE) {
                    method_cnt[m]++;
                    if (first_method == SIP_NONE) first_method = m;
                    /* request URI */
                    char *sp2 = strchr(sp+1, ' ');
                    int ulen = sp2 ? (int)(sp2-sp-1) : (int)strlen(sp+1);
                    int cp = std::min(ulen, (int)sizeof(request_uri)-1);
                    memcpy(request_uri, sp+1, (size_t)cp); request_uri[cp]='\0';
                }
            }
            snprintf(sip_version, sizeof sip_version, "SIP/2.0");
        }

        /* ---- 头域区 ---- */
        char val[256];
        auto hdr = [&](const char *name) -> const char* {
            return sip__find_header(buf, len, name, val, sizeof val);
        };

        /* Via */
        if (hdr("Via") || hdr("v")) {
            snprintf(via_first, sizeof via_first, "%s", val);
            /* transport */
            const char *sl = strstr(val, "SIP/2.0/");
            if (sl) { sl += 8; char *sp = strchr(const_cast<char*>(sl), ' ');
                int tlen = sp ? (int)(sp-sl) : (int)strlen(sl);
                int cp = std::min(tlen, 7); memcpy(via_transport, sl, (size_t)cp); via_transport[cp]='\0'; }
            /* branch */
            const char *bp = strstr(val, "branch=");
            if (bp) { bp += 7; const char *be = bp;
                while (*be && *be!=';' && *be!=',') be++;
                int cp = std::min((int)(be-bp), 63); memcpy(via_branch, bp, (size_t)cp); via_branch[cp]='\0'; }
            /* count via hops by counting \r\nVia: occurrences */
            via_hops = 1;
            const char *vp = buf;
            while ((vp = strcasestr(vp+1, "\nVia")) != nullptr && (vp-buf) < len) via_hops++;
        }

        /* From/To */
        if (hdr("From") || hdr("f"))
            sip__parse_addr(val, from_uri, sizeof from_uri, from_tag, sizeof from_tag,
                            from_display, sizeof from_display);
        if (hdr("To") || hdr("t"))
            sip__parse_addr(val, to_uri, sizeof to_uri, to_tag, sizeof to_tag,
                            to_display, sizeof to_display);

        if (hdr("Call-ID") || hdr("i"))
            snprintf(call_id, sizeof call_id, "%s", val);
        if (hdr("CSeq")) {
            cseq_num = (uint32_t)atol(val);
            char *sp = strchr(val, ' ');
            if (sp) snprintf(cseq_method, sizeof cseq_method, "%s", sp+1);
        }

        /* Routing */
        if (hdr("Contact") || hdr("m")) {
            char _tmp_tag[8]={}, _tmp_disp[8]={};
            sip__parse_addr(val, contact_uri, sizeof contact_uri,
                            _tmp_tag, 8, _tmp_disp, 8);
            const char *ep = strstr(val, "expires=");
            if (ep) contact_expires = (uint32_t)atol(ep+8);
        }
        if (hdr("Record-Route") && record_route_cnt < 8)
            snprintf(record_route[record_route_cnt++], 128, "%s", val);
        if (hdr("Route") && route_cnt < 8)
            snprintf(route[route_cnt++], 128, "%s", val);

        /* Capability */
        if (hdr("Allow"))     snprintf(allow_methods,  sizeof allow_methods,  "%s", val);
        if (hdr("Supported")) snprintf(supported_exts, sizeof supported_exts, "%s", val);
        if (hdr("Require"))   snprintf(require_exts,   sizeof require_exts,   "%s", val);
        if (hdr("Proxy-Require")) snprintf(proxy_require, sizeof proxy_require, "%s", val);

        /* Content */
        if (hdr("Content-Type"))     snprintf(content_type,     sizeof content_type,     "%s", val);
        if (hdr("Content-Length"))   content_length = (uint32_t)atol(val);
        if (hdr("Content-Encoding")) snprintf(content_encoding, sizeof content_encoding, "%s", val);

        /* Auth */
        if (hdr("WWW-Authenticate") || hdr("Proxy-Authenticate")) {
            if (hdr("WWW-Authenticate")) { has_www_auth = true; }
            else                          { has_proxy_auth = true; hdr("Proxy-Authenticate"); }
            /* Scheme */
            const char *sp = strchr(val, ' ');
            if (sp) { int cp=std::min((int)(sp-val),15); memcpy(auth_scheme,val,(size_t)cp); auth_scheme[cp]='\0'; }
            /* realm */
            const char *rp = strstr(val, "realm=\"");
            if (rp) { rp+=7; const char *re=strchr(rp,'"');
                if (re) { int cp=std::min((int)(re-rp),127); memcpy(auth_realm,rp,(size_t)cp); auth_realm[cp]='\0'; } }
            /* algorithm */
            const char *ap = strstr(val, "algorithm=");
            if (ap) { ap+=10; const char *ae=ap;
                while (*ae && *ae!=',' && *ae!=' ') ae++;
                int cp=std::min((int)(ae-ap),15); memcpy(auth_algorithm,ap,(size_t)cp); auth_algorithm[cp]='\0'; }
        }
        if (hdr("Authorization") || hdr("Proxy-Authorization")) {
            const char *up = strstr(val, "username=\"");
            if (up) { up+=10; const char *ue=strchr(up,'"');
                if (ue) { int cp=std::min((int)(ue-up),63); memcpy(auth_username,up,(size_t)cp); auth_username[cp]='\0'; } }
            const char *qp = strstr(val, "qop=");
            if (qp) { qp+=4; const char *qe=qp;
                while (*qe && *qe!=',' && *qe!=' ') qe++;
                int cp=std::min((int)(qe-qp),15); memcpy(auth_qop,qp,(size_t)cp); auth_qop[cp]='\0'; }
        }

        /* Event / Subscription */
        if (hdr("Event"))                snprintf(event_type, sizeof event_type, "%s", val);
        if (hdr("Subscription-State")) {
            snprintf(subscription_state, sizeof subscription_state, "%s", val);
            const char *ep = strstr(val, "expires=");
            if (ep) subscription_expires = (uint32_t)atol(ep+8);
        }

        /* Timing */
        if (hdr("Expires"))         expires_secs     = (uint32_t)atol(val);
        if (hdr("Session-Expires")) session_expires  = (uint32_t)atol(val);
        if (hdr("Min-SE"))          snprintf(min_se, sizeof min_se, "%s", val);

        /* User info */
        if (hdr("User-Agent"))         snprintf(user_agent,   sizeof user_agent,   "%s", val);
        if (hdr("Server"))             snprintf(server_str,   sizeof server_str,   "%s", val);
        if (hdr("Organization"))       snprintf(organization, sizeof organization, "%s", val);
        if (hdr("Subject") || hdr("s")) snprintf(subject,     sizeof subject,      "%s", val);
        if (hdr("Call-Info"))          snprintf(call_info,    sizeof call_info,    "%s", val);
        if (hdr("Priority"))           snprintf(priority,     sizeof priority,     "%s", val);

        /* History */
        if (hdr("P-Asserted-Identity")) snprintf(p_asserted_id, sizeof p_asserted_id, "%s", val);
        if (hdr("P-Preferred-Identity")) snprintf(p_preferred_id, sizeof p_preferred_id, "%s", val);
        if (hdr("Diversion"))           snprintf(diversion,   sizeof diversion,    "%s", val);
        if (hdr("Referred-By"))         snprintf(referred_by, sizeof referred_by,  "%s", val);
        if (hdr("Replaces"))            snprintf(replaces,    sizeof replaces,     "%s", val);

        /* SDP body */
        const char *body_start = strstr(buf, "\r\n\r\n");
        if (!body_start) body_start = strstr(buf, "\n\n");
        if (body_start) {
            int boffset = (int)(body_start - buf) + (buf[body_start-buf+2]=='\n' ? 2 : 4);
            if (boffset < len && strstr(content_type, "sdp"))
                _parse_sdp(buf + boffset, len - boffset);
        }

        transaction_cnt++;
    }

    /* ============================================================
     * 每包处理（支持 UDP 和 TCP 两种传输）
     * ============================================================ */
    void process_pkt(const uint8_t *payload, int len,
                     bool is_fwd, bool /*is_tcp*/, double /*ts*/) noexcept {
        if (len <= 0 || !payload) return;
        if (!detect_sip(payload, len)) return;

        /* 直接尝试解析（适合 UDP；TCP 可能需要重组，此处做简化处理）*/
        char *buf = is_fwd ? _fwd_buf : _bwd_buf;
        int  &blen= is_fwd ? _fwd_len : _bwd_len;

        /* 追加到缓冲 */
        int append = std::min(len, BUF_SZ - 1 - blen);
        if (append > 0) { memcpy(buf + blen, payload, (size_t)append); blen += append; }
        buf[blen] = '\0';

        /* 查找完整消息（以 \r\n\r\n 结尾的头域区） */
        char *end_hdr = strstr(buf, "\r\n\r\n");
        if (!end_hdr) end_hdr = strstr(buf, "\n\n");
        if (end_hdr) {
            int msg_len = (int)(end_hdr - buf) + 4;
            /* 尝试读取 body */
            char clen_val[16] = "0";
            sip__find_header(buf, msg_len, "Content-Length", clen_val, sizeof clen_val);
            int cl = atoi(clen_val);
            int total = msg_len + cl;
            if (total > blen) total = blen; /* 不完整也尝试解析 */
            _parse_message(buf, total);
            /* 消费已处理内容 */
            if (total < blen) memmove(buf, buf + total, (size_t)(blen - total));
            blen = std::max(0, blen - total);
        } else if (blen >= BUF_SZ - 1) {
            blen = 0; /* 缓冲满且无完整消息：丢弃 */
        }
    }

    /* ============================================================
     * 输出日志
     * ============================================================ */
    void emit_log(FILE *fp, const char *flow_id = "") const {
        fprintf(fp, "[SIP] %s\n", flow_id);
        fprintf(fp, "  Method/Status    : %s → %u %s\n",
                sip_method_name(first_method), last_status_code, last_status_reason);
        fprintf(fp, "  Call-ID          : %s\n", call_id);
        fprintf(fp, "  From             : %s%s%s\n", from_display[0]?from_display:"", from_display[0]?" ":"", from_uri);
        fprintf(fp, "  To               : %s%s%s  tag=%s\n", to_display[0]?to_display:"", to_display[0]?" ":"", to_uri, to_tag);
        fprintf(fp, "  CSeq             : %u %s\n", cseq_num, cseq_method);
        fprintf(fp, "  Via              : [%u hops] %s transport=%s branch=%.20s\n",
                via_hops, via_first, via_transport, via_branch);
        fprintf(fp, "  Contact          : %s  expires=%u\n", contact_uri, contact_expires);
        if (allow_methods[0])    fprintf(fp, "  Allow            : %s\n", allow_methods);
        if (supported_exts[0])  fprintf(fp, "  Supported        : %s\n", supported_exts);
        if (user_agent[0])      fprintf(fp, "  User-Agent       : %s\n", user_agent);
        if (server_str[0])      fprintf(fp, "  Server           : %s\n", server_str);
        if (auth_realm[0])      fprintf(fp, "  Auth             : scheme=%s realm=%s algo=%s qop=%s user=%s\n",
                                         auth_scheme, auth_realm, auth_algorithm, auth_qop, auth_username);
        if (event_type[0])      fprintf(fp, "  Event            : %s  state=%s\n", event_type, subscription_state);
        fprintf(fp, "  Msgs             : total=%u tx=%u  1xx=%u 2xx=%u 3xx=%u 4xx=%u 5xx=%u 6xx=%u\n",
                total_msgs, transaction_cnt, resp_1xx, resp_2xx, resp_3xx, resp_4xx, resp_5xx, resp_6xx);
        /* SDP */
        if (sdp_media_cnt > 0) {
            fprintf(fp, "  SDP.origin       : %s@%s  session=%s\n",
                    sdp_origin_user, sdp_origin_addr, sdp_session_name);
            fprintf(fp, "  SDP.connection   : %s\n", sdp_conn_addr);
            for (int i = 0; i < sdp_media_cnt; i++) {
                const SipSdpMedia &m = sdp_media[i];
                fprintf(fp, "  SDP.media[%d]     : type=%s port=%u proto=%s codecs=%s dir=%s\n",
                        i, m.type, m.port, m.proto, m.codecs, m.direction);
                if (m.rtpmap[0]) fprintf(fp, "                     rtpmap=%s\n", m.rtpmap);
            }
        }
        fprintf(fp, "\n");
    }
};
