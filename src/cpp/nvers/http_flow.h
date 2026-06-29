/**
 * http_flow.h  ——  HTTP/1.x + HTTP/2 协议深度字段解析（Header-Only）
 *
 * 标准：RFC 7230–7235 (HTTP/1.1), RFC 9110–9114 (HTTP Semantics)
 *       RFC 7540 (HTTP/2), RFC 7541 (HPACK)
 *
 * 默认端口：TCP 80 (HTTP), 443 (HTTPS), 8080/8443 (ALT)
 *
 * 提取的元信息（完整列表）：
 *   ─ 请求行 ─
 *   method      (GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/CONNECT/TRACE)
 *   url         (完整 URI path + query)
 *   url_path    (去掉 query 的路径)
 *   query_str   (? 之后的部分)
 *   query_param_cnt  (查询参数个数)
 *   http_version  ("HTTP/1.0" / "HTTP/1.1" / "HTTP/2")
 *   ─ 响应行 ─
 *   status_code, status_reason
 *   ─ 通用头域 ─
 *   host            connection        upgrade
 *   cache_control   pragma            transfer_encoding
 *   content_type    content_length    content_encoding
 *   content_language  content_location  content_md5
 *   vary            etag              last_modified
 *   date            expires           age
 *   location        (3xx redirect target)
 *   retry_after
 *   ─ 请求头域 ─
 *   user_agent      accept            accept_encoding
 *   accept_language accept_charset    accept_ranges
 *   referer         origin            authorization
 *   cookie_header   cookie_cnt        cookie_names[8]
 *   if_modified_since  if_none_match  if_match  if_range
 *   range           expect
 *   x_forwarded_for x_real_ip         x_forwarded_proto
 *   x_requested_with  dnt             te
 *   ─ 响应头域 ─
 *   server          set_cookie_cnt    set_cookie_names[8]
 *   www_authenticate proxy_authenticate
 *   access_control_allow_origin       (CORS)
 *   access_control_allow_methods
 *   access_control_allow_headers
 *   access_control_max_age
 *   strict_transport_security         (HSTS)
 *   content_security_policy           (CSP)
 *   x_content_type_options            (MIME sniff protection)
 *   x_frame_options                   (Clickjacking protection)
 *   x_xss_protection
 *   referrer_policy
 *   permissions_policy                (Feature-Policy)
 *   ─ 扩展头域 ─
 *   x_powered_by    via               forwarded
 *   x_request_id    x_trace_id        x_correlation_id
 *   x_cache         cdn_cache_control
 *   cf_ray          cf_cache_status   (Cloudflare)
 *   ─ HTTP/2 ─
 *   is_http2          h2_streams        h2_push_cnt
 *   ─ 请求体 ─
 *   body_is_json      body_is_form      body_is_xml
 *   body_is_multipart body_boundary
 *   form_fields[8]    (application/x-www-form-urlencoded 参数名)
 *   form_field_cnt
 *   ─ 流统计 ─
 *   request_cnt[METHOD_MAX]     (各 HTTP 方法计数)
 *   status_1xx..5xx             (响应码分布)
 *   total_request_cnt           total_response_cnt
 *   avg_response_time_ms        max_response_time_ms
 *   total_request_bytes         total_response_bytes
 *   keep_alive_reqs             websocket_upgrade
 *   ─ 安全 ─
 *   has_auth                    has_basic_auth
 *   has_bearer_token            has_api_key
 *   has_sql_injection_hint      has_path_traversal_hint
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
/* snprintf 向较小缓冲写入时会自动截断，这是预期行为 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

/* ============================================================
 * HTTP Method 枚举
 * ============================================================ */
enum HttpMethod : uint8_t {
    HTTP_NONE=0, HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE,
    HTTP_HEAD, HTTP_OPTIONS, HTTP_PATCH, HTTP_CONNECT, HTTP_TRACE,
    HTTP_METHOD_MAX
};

static inline const char *http_method_name(HttpMethod m) {
    static const char *n[] = {
        "NONE","GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT","TRACE"
    };
    return (unsigned)m < HTTP_METHOD_MAX ? n[m] : "?";
}

static inline HttpMethod http_parse_method(const char *s, int len) {
    struct { const char *nm; HttpMethod m; } tbl[] = {
        {"GET",HTTP_GET},{"POST",HTTP_POST},{"PUT",HTTP_PUT},
        {"DELETE",HTTP_DELETE},{"HEAD",HTTP_HEAD},{"OPTIONS",HTTP_OPTIONS},
        {"PATCH",HTTP_PATCH},{"CONNECT",HTTP_CONNECT},{"TRACE",HTTP_TRACE},
        {nullptr,HTTP_NONE}
    };
    for (int i = 0; tbl[i].nm; i++) {
        int nl = (int)strlen(tbl[i].nm);
        if (nl == len && memcmp(s, tbl[i].nm, (size_t)len) == 0) return tbl[i].m;
    }
    return HTTP_NONE;
}

/* ============================================================
 * 快速识别：是否为 HTTP/1.x 或 HTTP/2
 * ============================================================ */
static inline bool detect_http(const uint8_t *p, int len) {
    if (len < 8) return false;
    /* HTTP/2 客户端连接前言 */
    if (len >= 24 && memcmp(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) return true;
    /* HTTP/1.x 响应 */
    if (memcmp(p, "HTTP/1.", 7) == 0) return true;
    /* HTTP/1.x 请求方法 */
    static const char *pfx[] = {"GET ","POST ","PUT ","DELETE ","HEAD ",
                                  "OPTIONS ","PATCH ","CONNECT ","TRACE ",nullptr};
    for (int i = 0; pfx[i]; i++) {
        int plen = (int)strlen(pfx[i]);
        if (len >= plen && memcmp(p, pfx[i], (size_t)plen) == 0) return true;
    }
    return false;
}

/* ============================================================
 * 内部辅助：在 buf 中查找头域值（case-insensitive name match）
 * ============================================================ */
static inline const char *http__find_header(const char *buf, int len,
                                              const char *name,
                                              char *val, int valsz) {
    int nl = (int)strlen(name);
    const char *p = buf;
    const char *end = buf + len;
    /* 跳过请求/响应行 */
    while (p < end && *p != '\r' && *p != '\n') p++;
    while (p < end && (*p == '\r' || *p == '\n')) p++;

    while (p < end) {
        /* 每行以 name: value\r\n */
        if ((int)(end - p) <= nl + 1) break;
        if (strncasecmp(p, name, (size_t)nl) == 0 && p[nl] == ':') {
            const char *vs = p + nl + 1;
            while (vs < end && (*vs == ' ' || *vs == '\t')) vs++;
            const char *ve = vs;
            while (ve < end && *ve != '\r' && *ve != '\n') ve++;
            int cp = std::min((int)(ve - vs), valsz - 1);
            if (cp > 0) memcpy(val, vs, (size_t)cp);
            val[std::max(cp, 0)] = '\0';
            return val;
        }
        /* 找到行尾 */
        while (p < end && *p != '\r' && *p != '\n') p++;
        while (p < end && (*p == '\r' || *p == '\n')) p++;
    }
    return nullptr;
}

/* URL 解析 */
static inline void http__parse_url(const char *url, char *path, int psz,
                                    char *query, int qsz, int *qparams) {
    path[0] = query[0] = '\0'; *qparams = 0;
    const char *qmark = strchr(url, '?');
    if (qmark) {
        int plen = std::min((int)(qmark - url), psz - 1);
        memcpy(path, url, (size_t)plen); path[plen] = '\0';
        int qlen = std::min((int)strlen(qmark+1), qsz - 1);
        memcpy(query, qmark+1, (size_t)qlen); query[qlen] = '\0';
        /* count params */
        const char *p2 = query; *qparams = 1;
        while (*p2) { if (*p2++ == '&') (*qparams)++; }
    } else {
        int plen = std::min((int)strlen(url), psz - 1);
        memcpy(path, url, (size_t)plen); path[plen] = '\0';
    }
}

/* Cookie: name1=v1; name2=v2 → extract first N names */
static inline int http__parse_cookies(const char *cookie, char names[][64], int max_cnt) {
    int cnt = 0;
    const char *p = cookie;
    while (*p && cnt < max_cnt) {
        while (*p == ' ') p++;
        const char *eq = strchr(p, '=');
        const char *sc = strchr(p, ';');
        if (!eq) break;
        int nlen = std::min((int)(eq - p), 63);
        memcpy(names[cnt++], p, (size_t)nlen); names[cnt-1][nlen] = '\0';
        if (!sc) break;
        p = sc + 1;
    }
    return cnt;
}

/* 简单安全特征启发式（不替代真正的 WAF）*/
static inline bool http__has_sqli_hint(const char *url) {
    static const char *patterns[] = {
        "' OR ", "' AND ", "UNION SELECT", "DROP TABLE", "--",
        "1=1", "1 OR 1", "'='", "xp_", "exec(", nullptr
    };
    for (int i = 0; patterns[i]; i++)
        if (strcasestr(url, patterns[i])) return true;
    return false;
}
static inline bool http__has_traversal_hint(const char *url) {
    return strstr(url, "../") || strstr(url, "..\\") ||
           strstr(url, "%2e%2e%2f") || strstr(url, "%252e");
}

/* ============================================================
 * HTTP 流记录
 * ============================================================ */
struct HttpFlowRecord {

    /* ---- 版本 & 升级 ---- */
    char     http_version[16];     /* "HTTP/1.0" / "HTTP/1.1" / "HTTP/2"  */
    bool     is_http2;
    bool     websocket_upgrade;    /* Upgrade: websocket                   */

    /* ---- 最后一个请求 ---- */
    HttpMethod method;
    char     url[512];             /* 完整 URI                            */
    char     url_path[256];        /* 路径部分                            */
    char     query_str[256];       /* 查询字符串                          */
    int      query_param_cnt;

    /* ---- 最后一个响应 ---- */
    uint16_t status_code;
    char     status_reason[64];

    /* ---- 通用头域 ---- */
    char host[128];
    char connection[32];
    char upgrade[32];
    char cache_control[128];
    char pragma[32];
    char transfer_encoding[32];
    char content_type[128];
    uint64_t content_length;
    char content_encoding[32];
    char content_language[32];
    char content_location[128];
    char vary[64];
    char etag[128];
    char last_modified[64];
    char date_header[64];
    char expires_header[64];
    char age_header[16];
    char location[256];
    char retry_after[32];

    /* ---- 请求头域 ---- */
    char user_agent[256];
    char accept[128];
    char accept_encoding[64];
    char accept_language[64];
    char accept_charset[32];
    char referer[256];
    char origin[128];
    char authorization[128];       /* 首64字符                            */
    bool has_auth;
    bool has_basic_auth;
    bool has_bearer_token;
    bool has_api_key;
    char cookie_header[512];       /* Cookie: 完整值（截断）              */
    uint16_t cookie_cnt;
    char cookie_names[8][64];
    char if_modified_since[64];
    char if_none_match[64];
    char if_match[64];
    char if_range[64];
    char range_header[64];
    char expect[32];
    char x_forwarded_for[128];
    char x_real_ip[64];
    char x_forwarded_proto[16];
    char x_requested_with[64];
    bool dnt;                      /* Do Not Track                        */
    char te_header[32];

    /* ---- 响应头域 ---- */
    char server[128];
    uint16_t set_cookie_cnt;
    char set_cookie_names[8][64];

    /* ---- 认证质询 ---- */
    char www_authenticate[128];
    char proxy_authenticate[64];

    /* ---- 安全头域 ---- */
    char strict_transport_security[128]; /* HSTS                          */
    char content_security_policy[256];   /* CSP                           */
    char x_content_type_options[16];     /* "nosniff"                     */
    char x_frame_options[32];            /* DENY / SAMEORIGIN             */
    char x_xss_protection[32];
    char referrer_policy[64];
    char permissions_policy[256];

    /* ---- CORS ---- */
    char access_control_allow_origin[128];
    char access_control_allow_methods[128];
    char access_control_allow_headers[128];
    char access_control_max_age[16];
    char access_control_allow_credentials[8];

    /* ---- 扩展 / 追踪 ---- */
    char x_powered_by[64];
    char via_header[128];
    char forwarded[128];
    char x_request_id[64];
    char x_trace_id[64];
    char x_correlation_id[64];
    char x_cache[32];
    char cdn_cache_control[32];
    char cf_ray[32];                     /* Cloudflare Ray ID             */
    char cf_cache_status[16];

    /* ---- HTTP/2 ---- */
    uint32_t h2_streams;
    uint32_t h2_push_cnt;

    /* ---- 请求体分析 ---- */
    bool body_is_json;
    bool body_is_form;
    bool body_is_xml;
    bool body_is_multipart;
    char body_boundary[64];            /* multipart boundary             */
    char form_fields[8][64];           /* form 参数名                    */
    uint8_t form_field_cnt;

    /* ---- 安全特征 ---- */
    bool has_sql_injection_hint;
    bool has_path_traversal_hint;

    /* ---- 流统计 ---- */
    uint32_t request_cnt[HTTP_METHOD_MAX];
    uint32_t status_1xx, status_2xx, status_3xx, status_4xx, status_5xx;
    uint32_t total_request_cnt, total_response_cnt;
    uint64_t total_request_bytes, total_response_bytes;
    double   avg_response_time_ms;
    double   max_response_time_ms;
    uint32_t keep_alive_reqs;

    /* ---- 内部追踪 ---- */
    static const int BUF_SZ = 8192;
    char _req_buf[BUF_SZ]; int _req_len;
    char _rsp_buf[BUF_SZ]; int _rsp_len;
    double _last_req_ts;
    double _total_rtt;
    uint32_t _rtt_cnt;

    /* ============================================================
     * 初始化
     * ============================================================ */
    void init() noexcept {
        memset(this, 0, sizeof *this);
        _last_req_ts = -1.0;
    }

    /* ============================================================
     * 解析请求消息（buf 包含完整请求头）
     * ============================================================ */
    void _parse_request(const char *buf, int len, double ts) {
        total_request_cnt++;
        _last_req_ts = ts;
        total_request_bytes += (uint64_t)len;

        /* 请求行: METHOD URL HTTP/x.x */
        const char *lend = buf;
        while (lend < buf+len && *lend!='\r' && *lend!='\n') lend++;
        char req_line[512]; int rlen = std::min((int)(lend-buf),511);
        memcpy(req_line, buf, (size_t)rlen); req_line[rlen] = '\0';

        /* Method */
        char *sp1 = strchr(req_line, ' ');
        if (!sp1) return;
        method = http_parse_method(req_line, (int)(sp1 - req_line));
        if (method != HTTP_NONE) request_cnt[method]++;

        /* URL */
        char *sp2 = strchr(sp1+1, ' ');
        int ulen = sp2 ? (int)(sp2 - sp1 - 1) : (int)strlen(sp1+1);
        ulen = std::min(ulen, 511);
        memcpy(url, sp1+1, (size_t)ulen); url[ulen] = '\0';
        http__parse_url(url, url_path, sizeof url_path, query_str, sizeof query_str, &query_param_cnt);

        /* Version */
        if (sp2) {
            int vlen = std::min((int)strlen(sp2+1), 15);
            memcpy(http_version, sp2+1, (size_t)vlen);
            /* trim \r\n */
            for (char *p = http_version; *p; p++) if (*p=='\r'||*p=='\n') { *p='\0'; break; }
        }

        /* 安全 */
        has_sql_injection_hint  = http__has_sqli_hint(url);
        has_path_traversal_hint = http__has_traversal_hint(url);

        /* 头域 */
        char val[512];
        auto hdr = [&](const char *name) -> const char* {
            return http__find_header(buf, len, name, val, sizeof val);
        };

        if (hdr("Host"))              snprintf(host,       sizeof host,       "%s", val);
        if (hdr("Connection"))        snprintf(connection, sizeof connection, "%s", val);
        if (hdr("Upgrade")) {
            snprintf(upgrade, sizeof upgrade, "%s", val);
            if (strcasestr(val,"websocket")) websocket_upgrade = true;
        }
        if (hdr("Cache-Control"))     snprintf(cache_control,    sizeof cache_control,    "%s", val);
        if (hdr("User-Agent"))        snprintf(user_agent,       sizeof user_agent,       "%s", val);
        if (hdr("Accept"))            snprintf(accept,           sizeof accept,           "%s", val);
        if (hdr("Accept-Encoding"))   snprintf(accept_encoding,  sizeof accept_encoding,  "%s", val);
        if (hdr("Accept-Language"))   snprintf(accept_language,  sizeof accept_language,  "%s", val);
        if (hdr("Accept-Charset"))    snprintf(accept_charset,   sizeof accept_charset,   "%s", val);
        if (hdr("Referer"))           snprintf(referer,          sizeof referer,          "%s", val);
        if (hdr("Origin"))            snprintf(origin,           sizeof origin,           "%s", val);
        if (hdr("Content-Type")) {
            snprintf(content_type, sizeof content_type, "%s", val);
            body_is_json      = strcasestr(val,"json") != nullptr;
            body_is_xml       = strcasestr(val,"xml")  != nullptr;
            body_is_form      = strcasestr(val,"x-www-form-urlencoded") != nullptr;
            body_is_multipart = strcasestr(val,"multipart") != nullptr;
            const char *bp = strstr(val, "boundary=");
            if (bp) snprintf(body_boundary, sizeof body_boundary, "%s", bp+9);
        }
        if (hdr("Content-Length"))    content_length = (uint64_t)atoll(val);
        if (hdr("Content-Encoding"))  snprintf(content_encoding,  sizeof content_encoding,  "%s", val);
        if (hdr("Transfer-Encoding")) snprintf(transfer_encoding, sizeof transfer_encoding, "%s", val);

        /* Auth */
        if (hdr("Authorization")) {
            has_auth = true;
            snprintf(authorization, sizeof authorization, "%.127s", val);
            if (strncasecmp(val,"Basic",5)==0)   has_basic_auth    = true;
            if (strncasecmp(val,"Bearer",6)==0)  has_bearer_token  = true;
            if (strncasecmp(val,"ApiKey",6)==0 || strstr(val,"api_key") || strstr(val,"apikey"))
                has_api_key = true;
        }
        /* Cookies */
        if (hdr("Cookie")) {
            snprintf(cookie_header, sizeof cookie_header, "%.511s", val);
            cookie_cnt = (uint16_t)http__parse_cookies(val, cookie_names, 8);
        }

        /* Request headers */
        if (hdr("If-Modified-Since")) snprintf(if_modified_since, sizeof if_modified_since, "%s", val);
        if (hdr("If-None-Match"))     snprintf(if_none_match,     sizeof if_none_match,     "%s", val);
        if (hdr("If-Match"))          snprintf(if_match,          sizeof if_match,          "%s", val);
        if (hdr("If-Range"))          snprintf(if_range,          sizeof if_range,          "%s", val);
        if (hdr("Range"))             snprintf(range_header,      sizeof range_header,      "%s", val);
        if (hdr("Expect"))            snprintf(expect,            sizeof expect,            "%s", val);
        if (hdr("X-Forwarded-For"))   snprintf(x_forwarded_for,   sizeof x_forwarded_for,   "%s", val);
        if (hdr("X-Real-IP"))         snprintf(x_real_ip,         sizeof x_real_ip,         "%s", val);
        if (hdr("X-Forwarded-Proto")) snprintf(x_forwarded_proto, sizeof x_forwarded_proto, "%s", val);
        if (hdr("X-Requested-With"))  snprintf(x_requested_with,  sizeof x_requested_with,  "%s", val);
        if (hdr("DNT"))               dnt = (val[0] == '1');
        if (hdr("TE"))                snprintf(te_header, sizeof te_header, "%s", val);

        /* Tracking */
        if (hdr("X-Request-ID"))      snprintf(x_request_id,    sizeof x_request_id,    "%s", val);
        if (hdr("X-Trace-ID"))        snprintf(x_trace_id,      sizeof x_trace_id,      "%s", val);
        if (hdr("X-Correlation-ID"))  snprintf(x_correlation_id,sizeof x_correlation_id,"%s", val);
        if (hdr("Via"))               snprintf(via_header,      sizeof via_header,       "%s", val);
        if (hdr("Forwarded"))         snprintf(forwarded,       sizeof forwarded,        "%s", val);

        /* Keep-Alive detection */
        if (connection[0] && strncasecmp(connection,"keep-alive",10)==0)
            keep_alive_reqs++;

        /* Form body field names (application/x-www-form-urlencoded) */
        if (body_is_form) {
            const char *body = strstr(buf, "\r\n\r\n");
            if (body) {
                body += 4;
                const char *p = body;
                while (*p && form_field_cnt < 8) {
                    const char *eq = strchr(p, '=');
                    const char *amp = strchr(p, '&');
                    if (!eq) break;
                    int fnlen = std::min((int)(eq-p), 63);
                    memcpy(form_fields[form_field_cnt++], p, (size_t)fnlen);
                    form_fields[form_field_cnt-1][fnlen] = '\0';
                    p = amp ? amp+1 : p + strlen(p);
                }
            }
        }
    }

    /* ============================================================
     * 解析响应消息
     * ============================================================ */
    void _parse_response(const char *buf, int len, double ts) {
        total_response_cnt++;
        total_response_bytes += (uint64_t)len;

        /* RTT */
        if (_last_req_ts > 0.0) {
            double rtt = (ts - _last_req_ts) * 1000.0;
            _total_rtt += rtt; _rtt_cnt++;
            if (rtt > max_response_time_ms) max_response_time_ms = rtt;
            avg_response_time_ms = _rtt_cnt > 0 ? _total_rtt / _rtt_cnt : 0.0;
            _last_req_ts = -1.0;
        }

        /* 响应行: HTTP/x.x status_code reason */
        const char *lend = buf;
        while (lend < buf+len && *lend!='\r' && *lend!='\n') lend++;
        char rsp_line[256]; int rlen = std::min((int)(lend-buf),255);
        memcpy(rsp_line, buf, (size_t)rlen); rsp_line[rlen] = '\0';

        char *sp1 = strchr(rsp_line, ' ');
        if (sp1) {
            /* version */
            int vlen = std::min((int)(sp1-rsp_line),15);
            if (!http_version[0]) { memcpy(http_version,rsp_line,(size_t)vlen); http_version[vlen]='\0'; }
            status_code = (uint16_t)atoi(sp1+1);
            char *sp2 = strchr(sp1+1,' ');
            if (sp2) { int slen=std::min((int)strlen(sp2+1),63); memcpy(status_reason,sp2+1,(size_t)slen);
                for(char *p=status_reason;*p;p++) if(*p=='\r'||*p=='\n'){*p='\0';break;} }
            if      (status_code < 200) status_1xx++;
            else if (status_code < 300) status_2xx++;
            else if (status_code < 400) status_3xx++;
            else if (status_code < 500) status_4xx++;
            else                        status_5xx++;
        }

        char val[512];
        auto hdr = [&](const char *name) -> const char* {
            return http__find_header(buf, len, name, val, sizeof val);
        };

        if (hdr("Server"))           snprintf(server,       sizeof server,       "%s", val);
        if (hdr("Content-Type"))     snprintf(content_type, sizeof content_type, "%s", val);
        if (hdr("Content-Length"))   content_length = (uint64_t)atoll(val);
        if (hdr("Content-Encoding")) snprintf(content_encoding, sizeof content_encoding, "%s", val);
        if (hdr("Transfer-Encoding")) snprintf(transfer_encoding,sizeof transfer_encoding,"%s",val);
        if (hdr("Location"))         snprintf(location,    sizeof location,    "%s", val);
        if (hdr("ETag"))             snprintf(etag,        sizeof etag,        "%s", val);
        if (hdr("Last-Modified"))    snprintf(last_modified,sizeof last_modified,"%s", val);
        if (hdr("Date"))             snprintf(date_header, sizeof date_header, "%s", val);
        if (hdr("Expires"))          snprintf(expires_header,sizeof expires_header,"%s",val);
        if (hdr("Age"))              snprintf(age_header,  sizeof age_header,  "%s", val);
        if (hdr("Cache-Control"))    snprintf(cache_control,sizeof cache_control,"%s",val);
        if (hdr("Vary"))             snprintf(vary,        sizeof vary,        "%s", val);
        if (hdr("Retry-After"))      snprintf(retry_after, sizeof retry_after, "%s", val);
        if (hdr("Connection"))       snprintf(connection,  sizeof connection,  "%s", val);
        if (hdr("Upgrade")) {
            snprintf(upgrade, sizeof upgrade, "%s", val);
            if (strcasestr(val,"websocket")) websocket_upgrade = true;
        }

        /* Set-Cookie counting */
        if (hdr("Set-Cookie")) {
            if (set_cookie_cnt < 8) {
                const char *eq = strchr(val, '=');
                int nlen = eq ? std::min((int)(eq-val),63) : std::min((int)strlen(val),63);
                memcpy(set_cookie_names[set_cookie_cnt], val, (size_t)nlen);
                set_cookie_names[set_cookie_cnt][nlen] = '\0';
            }
            set_cookie_cnt++;
        }

        /* Auth challenge */
        if (hdr("WWW-Authenticate"))   snprintf(www_authenticate,  sizeof www_authenticate,  "%s", val);
        if (hdr("Proxy-Authenticate")) snprintf(proxy_authenticate,sizeof proxy_authenticate,"%s", val);

        /* Security headers */
        if (hdr("Strict-Transport-Security")) snprintf(strict_transport_security, sizeof strict_transport_security, "%s", val);
        if (hdr("Content-Security-Policy"))   snprintf(content_security_policy,   sizeof content_security_policy,   "%s", val);
        if (hdr("X-Content-Type-Options"))    snprintf(x_content_type_options,    sizeof x_content_type_options,    "%s", val);
        if (hdr("X-Frame-Options"))           snprintf(x_frame_options,           sizeof x_frame_options,           "%s", val);
        if (hdr("X-XSS-Protection"))          snprintf(x_xss_protection,          sizeof x_xss_protection,          "%s", val);
        if (hdr("Referrer-Policy"))           snprintf(referrer_policy,           sizeof referrer_policy,           "%s", val);
        if (hdr("Permissions-Policy"))        snprintf(permissions_policy,        sizeof permissions_policy,        "%s", val);
        /* Feature-Policy (old name) */
        if (!permissions_policy[0] && hdr("Feature-Policy")) snprintf(permissions_policy, sizeof permissions_policy, "%s", val);

        /* CORS */
        if (hdr("Access-Control-Allow-Origin"))      snprintf(access_control_allow_origin,      sizeof access_control_allow_origin,      "%s", val);
        if (hdr("Access-Control-Allow-Methods"))     snprintf(access_control_allow_methods,     sizeof access_control_allow_methods,     "%s", val);
        if (hdr("Access-Control-Allow-Headers"))     snprintf(access_control_allow_headers,     sizeof access_control_allow_headers,     "%s", val);
        if (hdr("Access-Control-Max-Age"))           snprintf(access_control_max_age,           sizeof access_control_max_age,           "%s", val);
        if (hdr("Access-Control-Allow-Credentials")) snprintf(access_control_allow_credentials, sizeof access_control_allow_credentials, "%s", val);

        /* CDN / Infra */
        if (hdr("X-Powered-By"))     snprintf(x_powered_by,     sizeof x_powered_by,     "%s", val);
        if (hdr("Via"))              snprintf(via_header,        sizeof via_header,        "%s", val);
        if (hdr("X-Cache"))          snprintf(x_cache,          sizeof x_cache,           "%s", val);
        if (hdr("CDN-Cache-Control"))snprintf(cdn_cache_control, sizeof cdn_cache_control, "%s", val);
        if (hdr("CF-Ray"))           snprintf(cf_ray,           sizeof cf_ray,            "%s", val);
        if (hdr("CF-Cache-Status"))  snprintf(cf_cache_status,  sizeof cf_cache_status,   "%s", val);
        if (hdr("X-Request-ID"))     snprintf(x_request_id,     sizeof x_request_id,      "%s", val);
        if (hdr("X-Trace-ID"))       snprintf(x_trace_id,       sizeof x_trace_id,        "%s", val);
    }

    /* ============================================================
     * 每包处理（支持客户端/服务端方向）
     * ============================================================ */
    void process_pkt(const uint8_t *payload, int len,
                     bool is_client, double ts) noexcept {
        if (len < 8 || !payload) return;

        /* HTTP/2 检测 */
        if (!is_http2 && len >= 24 &&
            memcmp(payload, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
            is_http2 = true;
            snprintf(http_version, sizeof http_version, "HTTP/2");
            return;
        }
        if (is_http2) { h2_streams++; return; }

        /* 使用对应方向的缓冲 */
        char *bbuf = is_client ? _req_buf : _rsp_buf;
        int  &bblen= is_client ? _req_len : _rsp_len;

        int append = std::min(len, BUF_SZ - 1 - bblen);
        if (append > 0) { memcpy(bbuf + bblen, payload, (size_t)append); bblen += append; }
        bbuf[bblen] = '\0';

        /* 搜索 \r\n\r\n（头域结束）*/
        char *end_hdr = strstr(bbuf, "\r\n\r\n");
        if (!end_hdr) {
            if (bblen >= BUF_SZ - 1) bblen = 0;
            return;
        }

        int hdr_len = (int)(end_hdr - bbuf) + 4;
        char cl_val[32] = "0";
        http__find_header(bbuf, hdr_len, "Content-Length", cl_val, sizeof cl_val);
        int content_len = std::max(0, atoi(cl_val));
        int total_len   = std::min(hdr_len + content_len, bblen);

        if (is_client)
            _parse_request(bbuf, total_len, ts);
        else
            _parse_response(bbuf, total_len, ts);

        /* 消费处理完的数据 */
        if (total_len < bblen) memmove(bbuf, bbuf + total_len, (size_t)(bblen - total_len));
        bblen = std::max(0, bblen - total_len);
    }

    /* ============================================================
     * 输出日志
     * ============================================================ */
    void emit_log(FILE *fp, const char *flow_id = "") const {
        fprintf(fp, "[HTTP] %s\n", flow_id);
        fprintf(fp, "  Version          : %s%s\n", http_version, is_http2?" (h2)":"");
        fprintf(fp, "  Method           : %s → %u %s\n",
                http_method_name(method), status_code, status_reason);
        fprintf(fp, "  URL              : %s\n", url);
        if (query_str[0]) fprintf(fp, "  Query            : %s  (%d params)\n", query_str, query_param_cnt);
        fprintf(fp, "  Host             : %s\n", host);
        if (user_agent[0]) fprintf(fp, "  User-Agent       : %s\n", user_agent);
        if (server[0])     fprintf(fp, "  Server           : %s\n", server);
        fprintf(fp, "  Content-Type     : %s  len=%llu\n", content_type, (unsigned long long)content_length);
        if (content_encoding[0]) fprintf(fp, "  Content-Encoding : %s\n", content_encoding);
        if (location[0])   fprintf(fp, "  Location         : %s\n", location);
        if (referer[0])    fprintf(fp, "  Referer          : %.80s\n", referer);
        if (origin[0])     fprintf(fp, "  Origin           : %s\n", origin);
        if (has_auth)      fprintf(fp, "  Auth             : Basic=%d Bearer=%d ApiKey=%d\n",
                                    has_basic_auth, has_bearer_token, has_api_key);
        if (cookie_cnt)    fprintf(fp, "  Cookies          : %u names\n", cookie_cnt);
        if (set_cookie_cnt) fprintf(fp,"  Set-Cookie       : %u\n", set_cookie_cnt);
        if (x_forwarded_for[0]) fprintf(fp, "  X-Forwarded-For  : %s\n", x_forwarded_for);
        if (x_real_ip[0])       fprintf(fp, "  X-Real-IP        : %s\n", x_real_ip);
        /* Security headers */
        if (strict_transport_security[0])
            fprintf(fp, "  HSTS             : %s\n", strict_transport_security);
        if (content_security_policy[0])
            fprintf(fp, "  CSP              : %.80s...\n", content_security_policy);
        if (x_content_type_options[0])
            fprintf(fp, "  X-Content-Type   : %s\n", x_content_type_options);
        if (x_frame_options[0])
            fprintf(fp, "  X-Frame-Options  : %s\n", x_frame_options);
        if (access_control_allow_origin[0])
            fprintf(fp, "  CORS Origin      : %s\n", access_control_allow_origin);
        /* CORS */
        if (www_authenticate[0])
            fprintf(fp, "  WWW-Auth         : %.60s\n", www_authenticate);
        /* CDN */
        if (cf_ray[0])     fprintf(fp, "  CF-Ray           : %s  cache=%s\n", cf_ray, cf_cache_status);
        if (x_powered_by[0]) fprintf(fp, "  X-Powered-By     : %s\n", x_powered_by);
        /* Body */
        if (body_is_json||body_is_form||body_is_xml||body_is_multipart)
            fprintf(fp, "  Body type        : json=%d form=%d xml=%d multipart=%d\n",
                    body_is_json, body_is_form, body_is_xml, body_is_multipart);
        /* Security hints */
        if (has_sql_injection_hint)  fprintf(fp, "  [!] SQLi hint in URL\n");
        if (has_path_traversal_hint) fprintf(fp, "  [!] Path traversal hint in URL\n");
        /* Stats */
        fprintf(fp, "  Requests         : %u  Responses: %u  Keep-alive: %u\n",
                total_request_cnt, total_response_cnt, keep_alive_reqs);
        fprintf(fp, "  Status dist      : 1xx=%u 2xx=%u 3xx=%u 4xx=%u 5xx=%u\n",
                status_1xx, status_2xx, status_3xx, status_4xx, status_5xx);
        fprintf(fp, "  Bytes            : req=%llu rsp=%llu\n",
                (unsigned long long)total_request_bytes,
                (unsigned long long)total_response_bytes);
        fprintf(fp, "  RTT (ms)         : avg=%.1f max=%.1f\n",
                avg_response_time_ms, max_response_time_ms);
        if (websocket_upgrade) fprintf(fp, "  [WebSocket upgrade detected]\n");
        fprintf(fp, "\n");
    }
};
