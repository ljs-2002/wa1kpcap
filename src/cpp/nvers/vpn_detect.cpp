/**
 * vpn_detect.cpp  ——  广义 VPN 协议识别实现（C++ 版）
 *
 * 编译：
 *   g++ -O2 -std=c++17 -c vpn_detect.cpp -lm
 */

#include "vpn_detect.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cctype>

/* ============================================================
 * 内部宏与辅助
 * ============================================================ */
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

static inline uint32_t u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8)
         | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline uint16_t u16be(const uint8_t *p) {
    return (uint16_t)((p[0]<<8)|p[1]);
}
static inline uint32_t u32be(const uint8_t *p) {
    return (uint32_t)((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]);
}

/* ============================================================
 * 工具函数实现
 * ============================================================ */
double vpn_entropy(const uint8_t *data, int len) {
    if (len <= 0) return 0.0;
    int freq[256];
    int i;
    memset(freq, 0, sizeof(freq));
    for (i = 0; i < len; i++) freq[data[i]]++;
    double H = 0.0;
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            H -= p * log(p) / log(2.0);
        }
    }
    return H;
}

bool vpn_is_tls(const uint8_t *p, int len) {
    if (len < 6) return false;
    uint8_t ct  = p[0];
    uint16_t ver = u16be(p + 1);
    /* Content type: 20=ChangeCipher, 21=Alert, 22=Handshake, 23=AppData */
    if (ct < 20 || ct > 24) return false;
    /* TLS version 0x0300..0x0304 or SSLv2 0x0200 */
    if (ver < 0x0200 || ver > 0x0305) return false;
    /* Record length sanity */
    uint16_t rlen = u16be(p + 3);
    if (rlen > 16384 + 2048) return false; /* TLS_MAX_RECORD_SIZE + overhead */
    return true;
}

bool vpn_is_http(const uint8_t *p, int len) {
    if (len < 8) return false;
    /* HTTP methods or response */
    return (memcmp(p, "GET ",     4) == 0 ||
            memcmp(p, "POST ",    5) == 0 ||
            memcmp(p, "PUT ",     4) == 0 ||
            memcmp(p, "CONNECT ", 8) == 0 ||
            memcmp(p, "HTTP/",    5) == 0);
}

const char *vpn_proto_name(VpnProto p) {
    switch (p) {
    case VPN_WIREGUARD:   return "WireGuard";
    case VPN_OPENVPN:     return "OpenVPN";
    case VPN_SHADOWSOCKS: return "Shadowsocks";
    case VPN_VMESS:       return "VMess";
    case VPN_VLESS:       return "VLESS";
    case VPN_TROJAN:      return "Trojan";
    case VPN_V2RAY:       return "V2Ray";
    case VPN_CLASH:       return "Clash";
    case VPN_PSIPHON:     return "Psiphon";
    case VPN_LANTERN:     return "Lantern";
    case VPN_HYSTERIA:    return "Hysteria/QUIC-VPN";
    default:              return "Unknown";
    }
}
const char *vpn_conf_name(VpnConf c) {
    switch (c) {
    case VPN_CONF_NONE: return "none";
    case VPN_CONF_LOW:  return "low";
    case VPN_CONF_MED:  return "medium";
    case VPN_CONF_HIGH: return "high";
    default:            return "?";
    }
}
const char *vpn_transport_name(VpnTransport t) {
    switch (t) {
    case VPN_TRANS_UDP:    return "UDP";
    case VPN_TRANS_TCP:    return "TCP";
    case VPN_TRANS_TLS:    return "TLS";
    case VPN_TRANS_WS:     return "WebSocket";
    case VPN_TRANS_WSS:    return "WebSocket+TLS";
    case VPN_TRANS_HTTP2:  return "HTTP/2";
    case VPN_TRANS_GRPC:   return "gRPC";
    case VPN_TRANS_QUIC:   return "QUIC";
    case VPN_TRANS_SSH:    return "SSH";
    case VPN_TRANS_MEEK:   return "meek";
    default:               return "unknown";
    }
}

/* ============================================================
 * 辅助：在 payload 中搜索 ASCII 子串（大小写不敏感）
 * ============================================================ */
static const uint8_t *mem_icase(const uint8_t *hay, int hlen,
                                  const char *needle, int nlen) {
    int i, j;
    for (i = 0; i <= hlen - nlen; i++) {
        bool ok = true;
        for (j = 0; j < nlen; j++) {
            if (tolower(hay[i+j]) != tolower((unsigned char)needle[j])) {
                ok = false; break;
            }
        }
        if (ok) return hay + i;
    }
    return NULL;
}

/* 在 HTTP headers 中提取某个 header 的值（不含 CRLF） */
static bool http_header_value(const uint8_t *pay, int len,
                               const char *header_name,
                               char *val_out, int val_max) {
    int hname_len = (int)strlen(header_name);
    const uint8_t *p = pay;
    const uint8_t *end = pay + len;
    while (p < end) {
        /* 找到行 */
        const uint8_t *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;
        int line_len = (int)(line_end - p);
        if (line_len > hname_len + 1) {
            if (mem_icase(p, hname_len + 1, header_name, hname_len) == p) {
                /* check ':' */
                if (p[hname_len] == ':') {
                    const uint8_t *v = p + hname_len + 1;
                    while (v < line_end && (*v == ' ' || *v == '\t')) v++;
                    int vlen = (int)(line_end - v);
                    if (vlen > 0 && v[vlen-1] == '\r') vlen--;
                    int copy = MIN(vlen, val_max - 1);
                    if (copy > 0) memcpy(val_out, v, (size_t)copy);
                    val_out[copy] = '\0';
                    return true;
                }
            }
        }
        p = line_end + 1;
    }
    return false;
}

/* ============================================================
 * WireGuard 检测
 *
 * 协议格式（4 字节 LE 消息类型 + 固定长度）：
 *   Type 1 (Handshake Init)  : 148 bytes
 *   Type 2 (Handshake Resp)  :  92 bytes
 *   Type 3 (Cookie Reply)    :  64 bytes
 *   Type 4 (Data)            :  >= 32 bytes，(len-32)%16 == 0
 * ============================================================ */
VpnConf vpn_detect_wireguard(const uint8_t *p, int len, uint8_t proto) {
    if (proto != 17 || len < 32) return VPN_CONF_NONE;

    uint32_t msg_type = u32le(p);
    switch (msg_type) {
    case WG_MSG_INITIATION:
        return (len == 148) ? VPN_CONF_HIGH : VPN_CONF_NONE;
    case WG_MSG_RESPONSE:
        return (len == 92)  ? VPN_CONF_HIGH : VPN_CONF_NONE;
    case WG_MSG_COOKIE:
        return (len == 64)  ? VPN_CONF_HIGH : VPN_CONF_NONE;
    case WG_MSG_DATA:
        /* data packets: 32 fixed bytes + 16-byte aligned encrypted payload */
        if (len >= 32 && ((len - 32) % 16) == 0)
            return VPN_CONF_HIGH;
        return VPN_CONF_NONE;
    default:
        return VPN_CONF_NONE;
    }
}

/* ============================================================
 * OpenVPN 检测
 *
 * UDP 格式: [opcode|key_id (1B)][session_id (8B)][...]
 * TCP 格式: [len (2B BE)][opcode|key_id (1B)][session_id (8B)][...]
 *
 * 操作码（bits 7:3，值 1-9）:
 *   1=CTRL_RESET_CLI_V1  7=CTRL_RESET_CLI_V2
 *   2=CTRL_RESET_SRV_V1  8=CTRL_RESET_SRV_V2
 *   3=CTRL_SOFT_RESET    9=DATA_V2
 *   4=CTRL_V1            6=DATA_V1
 *   5=ACK_V1
 * ============================================================ */
VpnConf vpn_detect_openvpn(const uint8_t *p, int len, uint8_t proto,
                            bool *is_tcp_out) {
    if (len < 4) return VPN_CONF_NONE;

    const uint8_t *data = p;
    int   dlen = len;
    bool  is_tcp = false;

    /* TCP mode: first 2 bytes = packet length */
    if (proto == 6) {
        uint16_t tcp_pkt_len = u16be(p);
        if (tcp_pkt_len < 3 || (int)tcp_pkt_len + 2 > len) return VPN_CONF_NONE;
        data  = p + 2;
        dlen  = tcp_pkt_len;
        is_tcp = true;
    }
    if (dlen < 2) return VPN_CONF_NONE;

    uint8_t first_byte = data[0];
    uint8_t opcode = (first_byte >> 3) & 0x1F;

    /* Valid opcode range: 1-9 */
    if (opcode < 1 || opcode > 9) return VPN_CONF_NONE;

    if (is_tcp_out) *is_tcp_out = is_tcp;

    /* HARD_RESET packets: highest confidence — require session_id (8B) */
    if ((opcode == OVPN_P_CONTROL_HARD_RESET_CLIENT_V2 ||
         opcode == OVPN_P_CONTROL_HARD_RESET_SERVER_V2 ||
         opcode == OVPN_P_CONTROL_HARD_RESET_CLIENT_V1 ||
         opcode == OVPN_P_CONTROL_HARD_RESET_SERVER_V1) && dlen >= 9) {
        return VPN_CONF_HIGH;
    }

    /* Control packets: medium confidence */
    if (opcode == OVPN_P_CONTROL_V1 || opcode == OVPN_P_ACK_V1) {
        if (dlen >= 9) return VPN_CONF_MED;
    }

    /* Data packets: low confidence (could be many things) */
    if (opcode == OVPN_P_DATA_V1 || opcode == OVPN_P_DATA_V2) {
        /* tls-crypt data packets often appear after handshake */
        return VPN_CONF_LOW;
    }

    return VPN_CONF_LOW;
}

/* ============================================================
 * Shadowsocks 检测
 *
 * AEAD（现代，SIP004）:
 *   Client 首包: [32B salt][2B encrypted_len+16B tag][encrypted_payload+16B tag]
 *   最小 50 bytes（空 payload: 32+2+16+0+16=66），实际有地址：100-200B
 * Stream cipher（旧版）:
 *   Client 首包: [N bytes IV][encrypted_SOCKS5_address+data]
 *   AES-256-CFB: IV=16B, ChaCha20/IETF: nonce=12B
 *
 * 检测策略：
 *   1. 高熵（>7.2 bits/byte）
 *   2. 首包大小在典型范围
 *   3. 无可识别的协议 header
 * ============================================================ */
VpnConf vpn_detect_shadowsocks(const uint8_t *p, int len, uint16_t dport,
                                double *ent_out) {
    if (len < 32) return VPN_CONF_NONE;

    double H = vpn_entropy(p, MIN(len, 128));
    if (ent_out) *ent_out = H;

    /* 低熵 → 明文，不是 Shadowsocks */
    if (H < VPN_ENTROPY_THRESH_SS) return VPN_CONF_NONE;

    /* 排除明确已知协议 */
    if (vpn_is_tls(p, len)) return VPN_CONF_NONE;

    /* AEAD 首包特征：32字节盐 + 18字节密文段（2+16）*/
    /* 首包长度：AEAD 通常 66-250B */
    if (len >= 66 && len <= 400) {
        /* SOCKS5 地址编码后加密，target_len 通常 10-50 bytes */
        /* 所以首包 ≈ 32 + 18 + (10~50+16) = 76-116 bytes 最常见 */
        if (dport == PORT_SS_DEFAULT) return VPN_CONF_HIGH;
        return VPN_CONF_MED;
    }

    /* Stream cipher 首包特征 */
    if (len >= 20 && len <= 600) {
        if (dport == PORT_SS_DEFAULT) return VPN_CONF_MED;
        return VPN_CONF_LOW;
    }

    return VPN_CONF_LOW;
}

/* ============================================================
 * VMess (V2Ray/Xray) 检测
 *
 * 可检测的传输封装：
 *   WebSocket: HTTP Upgrade request/response
 *   gRPC:      HTTP/2 with content-type: application/grpc
 *   HTTP/2:    带有 h2 ALPN 的 TLS
 *   RAW TCP:   高熵，无法与 Shadowsocks 区分 → LOW
 *
 * VMess 自身协议在 TCP/WS 之上完全加密（AES-128-CFB），
 * 无法在不知道 UUID 的情况下确认，仅通过传输层特征判断。
 * ============================================================ */
VpnConf vpn_detect_vmess(const uint8_t *p, int len, VpnTransport *tr_out,
                          char *path_out, int path_max) {
    if (len < 16) return VPN_CONF_NONE;

    /* ---- WebSocket HTTP Upgrade ---- */
    if (vpn_is_http(p, len)) {
        char upgrade_val[64] = {0};
        bool has_upgrade = http_header_value(p, len, "Upgrade",
                                              upgrade_val, sizeof upgrade_val);
        if (has_upgrade && mem_icase((const uint8_t*)upgrade_val,
                                      (int)strlen(upgrade_val),
                                      "websocket", 9)) {
            /* Extract path from first HTTP line */
            if (path_out && path_max > 0) {
                const uint8_t *path_start = p;
                /* skip "GET " or "POST " */
                while (path_start < p+len && *path_start != ' ') path_start++;
                if (*path_start == ' ') path_start++;
                const uint8_t *path_end = path_start;
                while (path_end < p+len && *path_end != ' '
                       && *path_end != '\r') path_end++;
                int plen = (int)(path_end - path_start);
                int copy = MIN(plen, path_max - 1);
                if (copy > 0) memcpy(path_out, path_start, (size_t)copy);
                path_out[copy] = '\0';
            }
            if (tr_out) *tr_out = VPN_TRANS_WS;
            return VPN_CONF_MED;
        }
    }

    /* ---- gRPC (HTTP/2 with grpc content-type) ---- */
    /* HTTP/2 frames start with a 9-byte frame header */
    /* PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n (client preface) */
    if (len >= 24 && memcmp(p, "PRI * HTTP/2.0", 14) == 0) {
        if (tr_out) *tr_out = VPN_TRANS_HTTP2;
        return VPN_CONF_MED;
    }
    /* gRPC content-type in HTTP headers */
    if (vpn_is_http(p, len)) {
        char ct_val[64] = {0};
        if (http_header_value(p, len, "content-type", ct_val, sizeof ct_val)) {
            if (mem_icase((const uint8_t*)ct_val, (int)strlen(ct_val),
                          "application/grpc", 16)) {
                if (tr_out) *tr_out = VPN_TRANS_GRPC;
                return VPN_CONF_MED;
            }
        }
    }

    /* ---- Raw TCP: entropy heuristic (LOW) ---- */
    double H = vpn_entropy(p, MIN(len, 128));
    if (H > VPN_ENTROPY_THRESH && !vpn_is_tls(p, len)) {
        if (tr_out) *tr_out = VPN_TRANS_TCP;
        return VPN_CONF_LOW;
    }

    return VPN_CONF_NONE;
}

/* ============================================================
 * VLESS 检测
 *
 * VLESS 与 VMess 使用相同传输层，协议本身更简洁（无加密开销）。
 * VLESS over WebSocket 的 HTTP upgrade 与 VMess 完全相同。
 * VLESS over TCP 首包结构（明文版，无混淆时）：
 *   [1B version=0][16B UUID][1B addons_len][...][1B cmd][2B port][1B addr_type][addr]
 * 但实际部署几乎总有 TLS 或 XTLS 封装，因此不可见。
 * ============================================================ */
VpnConf vpn_detect_vless(const uint8_t *p, int len, VpnTransport *tr_out) {
    /* 同 VMess：可见的特征只有传输层 */
    VpnConf c = vpn_detect_vmess(p, len, tr_out, NULL, 0);
    /* VLESS 明文 TCP 特征：version=0x00, 然后是 UUID (16B) */
    if (c == VPN_CONF_NONE && len >= 18 && p[0] == 0x00) {
        /* 不能确认 UUID，但作为低置信度标记 */
        double H = vpn_entropy(p + 1, MIN(len - 1, 32));
        if (H > 7.0) {
            if (tr_out) *tr_out = VPN_TRANS_TCP;
            return VPN_CONF_LOW;
        }
    }
    return c;
}

/* ============================================================
 * Trojan 检测
 *
 * Trojan 使用 TLS（通常在 443 端口）伪装成 HTTPS。
 * TLS 握手完成后，首条 Application Data 包含：
 *   hex(SHA224(password))[56B] + CRLF + SOCKS5_CMD + CRLF
 * 由于 TLS 加密，无法直接检测内容。
 *
 * 启发式特征：
 *   1. TLS on port 443/8443（必要但不充分）
 *   2. TLS ClientHello 的 SNI 与实际流量目标不符（需 DNS 对比）
 *   3. 连接建立后很快有双向大流量（隧道特征）
 *   4. 无 HTTP 请求行（区分 Trojan 与普通 HTTPS）
 * ============================================================ */
VpnConf vpn_detect_trojan(const uint8_t *p, int len,
                            uint16_t dport, bool has_tls) {
    if (!has_tls && !vpn_is_tls(p, len)) return VPN_CONF_NONE;

    /* Trojan 通常在 443 或 8443 */
    if (dport != 443 && dport != 8443 && dport != 80) return VPN_CONF_NONE;

    /* 若是 TLS ClientHello，记录为低置信度候选 */
    if (vpn_is_tls(p, len) && p[5] == 0x01 /* ClientHello */ ) {
        return VPN_CONF_LOW;
    }
    /* TLS Application Data，极低置信度 */
    if (vpn_is_tls(p, len) && p[0] == 0x17) {
        return VPN_CONF_LOW;
    }
    return VPN_CONF_NONE;
}

/* ============================================================
 * Psiphon 检测
 *
 * Psiphon 使用多种传输层，以下可被动态检测：
 *
 * 1. OSSH (Obfuscated SSH):
 *    - 随机前缀（16-256 bytes 高熵数据）
 *    - 紧接 SSH banner "SSH-2.0-"（或 SSH-1.99-）
 *    - KEYWORD 通常是 MD5(server_key)[:16]
 *
 * 2. SSH (普通 SSH transport):
 *    - banner: "SSH-2.0-OpenSSH_..." 或特定 Psiphon 版本
 *    - 通常在非 22 端口（443, 80, 8080）
 *
 * 3. meek (HTTP/HTTPS CDN 前置):
 *    - HTTP GET/POST 到 CDN 域名（fronting domain）
 *    - Host 为实际 Psiphon 服务器域名
 *    - X-Psiphon-Address 头部
 *    - User-Agent 包含 "psiphon" 或特定字符串
 *
 * 4. QUIC transport: 无额外特征，依靠 QUIC 检测
 * ============================================================ */
VpnConf vpn_detect_psiphon(const uint8_t *p, int len, uint8_t proto,
                             PsiphonFlowInfo *info) {
    if (len < 4) return VPN_CONF_NONE;

    /* ---- SSH banner（直接可见，非加密） ---- */
    if (len >= 8 && memcmp(p, "SSH-", 4) == 0) {
        if (info) {
            info->is_ssh = true;
            int blen = MIN(len, 127);
            memcpy(info->ssh_banner, p, (size_t)blen);
            info->ssh_banner[blen] = '\0';
        }
        return VPN_CONF_MED; /* SSH on any port could be Psiphon */
    }

    /* ---- OSSH: 随机前缀 + SSH banner ---- */
    /* 搜索 payload 中是否有 "SSH-" 出现在偏移 > 0 */
    if (len > 20) {
        int i;
        double prefix_entropy = 0.0;
        for (i = 1; i <= MIN(len - 4, 256); i++) {
            if (memcmp(p + i, "SSH-", 4) == 0) {
                prefix_entropy = vpn_entropy(p, i);
                if (prefix_entropy > VPN_ENTROPY_THRESH_OSSH && i >= 8) {
                    /* 高熵随机前缀 + SSH-2.0 */
                    if (info) {
                        info->is_ossh = true;
                        info->ossh_prefix_len = (uint8_t)MIN(i, 255);
                        int blen = MIN(len - i, 127);
                        memcpy(info->ssh_banner, p + i, (size_t)blen);
                        info->ssh_banner[blen] = '\0';
                    }
                    return VPN_CONF_HIGH;
                }
            }
        }
    }

    /* ---- meek: HTTP with Psiphon headers ---- */
    if (vpn_is_http(p, len)) {
        char host_val[128] = {0};
        char ua_val[128]   = {0};
        char psiphon_hdr[64] = {0};
        bool has_host = http_header_value(p, len, "Host", host_val, sizeof host_val);
        http_header_value(p, len, "User-Agent", ua_val, sizeof ua_val);
        bool has_psiphon_hdr = http_header_value(p, len, "X-Psiphon-Address",
                                                  psiphon_hdr, sizeof psiphon_hdr);

        if (has_psiphon_hdr) {
            if (info) { info->is_meek = true;
                memcpy(info->meek_host, host_val, sizeof info->meek_host - 1);
                memcpy(info->meek_ua,   ua_val,   sizeof info->meek_ua - 1); }
            return VPN_CONF_HIGH;
        }

        /* User-Agent 包含 "psiphon"（大小写不敏感）*/
        if (mem_icase((const uint8_t*)ua_val, (int)strlen(ua_val), "psiphon", 7)) {
            if (info) { info->is_meek = true;
                memcpy(info->meek_host, host_val, sizeof info->meek_host - 1);
                memcpy(info->meek_ua,   ua_val,   sizeof info->meek_ua - 1); }
            return VPN_CONF_HIGH;
        }

        /* Host 与 CDN 前置域名匹配（常见 meek fronting）*/
        if (has_host) {
            static const char *known_fronts[] = {
                "psiphon", "az668.vo.msecnd.net",
                "d2zfqthxsdq309.cloudfront.net",
                "s3.amazonaws.com", NULL
            };
            int fi;
            for (fi = 0; known_fronts[fi]; fi++) {
                if (mem_icase((const uint8_t*)host_val, (int)strlen(host_val),
                              known_fronts[fi], (int)strlen(known_fronts[fi]))) {
                    if (info) { info->is_meek = true;
                        memcpy(info->meek_host, host_val, sizeof info->meek_host - 1); }
                    return VPN_CONF_MED;
                }
            }
        }
    }

    /* ---- UDP 上的 SSH（Psiphon 的 QUIC transport 不携带 SSH）---- */
    if (proto == 17 && len >= 8 && memcmp(p, "SSH-", 4) == 0) {
        return VPN_CONF_LOW; /* SSH over UDP 很少见 */
    }

    return VPN_CONF_NONE;
}

/* ============================================================
 * Lantern 检测
 *
 * Lantern 历史上使用过多种协议，现主要：
 *
 * 1. lampshade (TCP):
 *    - 自定义混淆层，首字节为消息类型
 *    - INIT_MSG (0x00) 或 DATA_MSG (0x01) 等
 *    - 高熵随机化，头部有魔术标识
 *    lampshade 头（8字节）:
 *      [2B frame_length][1B msg_type][1B padding_len][4B seq_num]
 *
 * 2. OQUIC (基于 Google QUIC 的变体, UDP):
 *    - QUIC initial packet 结构，但有 Lantern 特定字段
 *
 * 3. domain-fronting over HTTPS:
 *    - Host 与 SNI 不一致
 *    - 特定 CDN 域名
 *
 * 4. flashlight HTTP/HTTPS:
 *    - X-Lantern-* headers
 * ============================================================ */
VpnConf vpn_detect_lantern(const uint8_t *p, int len, uint8_t proto,
                             LanternFlowInfo *info) {
    if (len < 8) return VPN_CONF_NONE;

    /* ---- HTTP with Lantern headers ---- */
    if (vpn_is_http(p, len)) {
        char lantern_hdr[64] = {0};
        if (http_header_value(p, len, "X-Lantern-Version",
                               lantern_hdr, sizeof lantern_hdr) ||
            http_header_value(p, len, "X-Lantern-Auth",
                               lantern_hdr, sizeof lantern_hdr)) {
            return VPN_CONF_HIGH;
        }
        /* Lantern 的 CONNECT 请求 */
        if (memcmp(p, "CONNECT ", 8) == 0) {
            char ua[128] = {0};
            http_header_value(p, len, "User-Agent", ua, sizeof ua);
            if (mem_icase((const uint8_t*)ua, (int)strlen(ua), "lantern", 7))
                return VPN_CONF_HIGH;
        }
    }

    /* ---- lampshade (TCP): 2B frame_len + 1B type (0-3) + 1B pad_len ---- */
    if (proto == 6 && len >= 8) {
        uint16_t frame_len = u16be(p);
        uint8_t  msg_type  = p[2];
        /* lampshade 消息类型: 0=Init, 1=Data, 2=Ack, 3=Rst, 4=WindowSize */
        if (msg_type <= 4 &&
            (int)frame_len >= 8 && (int)frame_len <= len + 64) {
            double H = vpn_entropy(p + 8, MIN(len - 8, 64));
            if (H > VPN_ENTROPY_THRESH_OSSH) {
                if (info) { info->is_lampshade = true; info->lamp_msg_type = msg_type; }
                return VPN_CONF_MED;
            }
        }
    }

    /* ---- OQUIC (UDP): Lantern 使用定制 QUIC，首字节高熵 ---- */
    if (proto == 17 && len >= 16) {
        uint8_t b0 = p[0];
        /* OQUIC 首字节：QUIC long header 形式但 version 字段定制 */
        if ((b0 & 0x80) && (b0 & 0x40)) {
            uint32_t ver = u32be(p + 1);
            /* Lantern OQUIC 使用非标准 version */
            if (ver != 0x00000001 && ver != 0x6b3343cf &&
                (ver & 0xff000000) != 0xff000000) {
                double H = vpn_entropy(p, MIN(len, 64));
                if (H > VPN_ENTROPY_THRESH) {
                    if (info) info->is_oquic = true;
                    return VPN_CONF_MED;
                }
            }
        }
    }

    return VPN_CONF_NONE;
}

/* ============================================================
 * Clash 检测
 *
 * Clash 本身是代理客户端，其"协议"体现在：
 * 1. 本地 HTTP/SOCKS 代理端口（7890/7891）的流量
 * 2. HTTP 请求中包含 "Clash" User-Agent
 * 3. Clash 管理 API（localhost:9090）的 RESTful 流量
 * 4. 出站使用 Shadowsocks/VMess/VLESS/Trojan（不额外标记）
 * ============================================================ */
VpnConf vpn_detect_clash(const uint8_t *p, int len,
                           uint16_t sport, uint16_t dport) {
    /* 已知 Clash 本地代理端口 */
    if (dport == PORT_CLASH_HTTP || dport == PORT_CLASH_SOCKS ||
        sport == PORT_CLASH_HTTP || sport == PORT_CLASH_SOCKS) {
        if (vpn_is_http(p, len) || len >= 3) return VPN_CONF_MED;
    }
    /* 管理 API 端口 9090 */
    if (dport == 9090 || sport == 9090) {
        if (vpn_is_http(p, len)) return VPN_CONF_MED;
    }

    /* HTTP 流量中的 Clash User-Agent */
    if (vpn_is_http(p, len)) {
        char ua[128] = {0};
        char clash_meta[64] = {0};
        http_header_value(p, len, "User-Agent", ua, sizeof ua);
        if (mem_icase((const uint8_t*)ua, (int)strlen(ua), "clash", 5))
            return VPN_CONF_HIGH;
        /* Clash.Meta 的 RESTful API 响应通常含 X-Clash-Version */
        if (http_header_value(p, len, "X-Clash-Version",
                               clash_meta, sizeof clash_meta))
            return VPN_CONF_HIGH;
    }

    /* SOCKS5 代理握手（Clash 混合端口）:
     * [0x05][n_methods][method1]... */
    if (len >= 3 && p[0] == 0x05 && p[1] > 0 && p[1] <= 10 &&
        (int)p[1] + 2 <= len) {
        /* 对比 dst_port */
        if (dport == PORT_CLASH_MIXED || dport == PORT_CLASH_SOCKS)
            return VPN_CONF_MED;
    }

    return VPN_CONF_NONE;
}

/* ============================================================
 * Hysteria / QUIC-based VPN 检测
 *
 * Hysteria 和 Hysteria2 是基于 QUIC 的 VPN 工具，特征：
 *   - UDP 上的标准 QUIC 协议（v1 或 v2）
 *   - 使用非 443 端口（443 可能是普通 HTTPS/3）
 *   - Initial 包固定 1200 字节（QUIC 规范中的最小填充）
 *   - Long Header (0x80|0x40) + 4字节 version + DCID + SCID
 *   - Short Header 后续数据包（加密，无法解密）
 *
 * V2Ray QUIC transport 也具有相同 QUIC 外形，同样可检测。
 * ============================================================ */
VpnConf vpn_detect_hysteria(const uint8_t *p, int len, uint8_t proto,
                              uint16_t sport, uint16_t dport,
                              HysteriaFlowInfo *info) {
    if (proto != 17 || len < 20) return VPN_CONF_NONE;

    uint8_t b0 = p[0];

    /* QUIC Long Header: bit7=1 (Header Form), bit6=1 (Fixed Bit) */
    if ((b0 & 0xC0) == 0xC0) {
        uint32_t ver = u32be(p + 1);
        /* 已知 QUIC 版本 */
        bool is_quic_v1 = (ver == QUIC_VER_1);
        bool is_quic_v2 = (ver == QUIC_VER_2);
        /* QUIC draft 版本: 0xff00xxxx */
        bool is_quic_draft = ((ver & 0xff000000u) == 0xff000000u);
        /* Version Negotiation: ver=0 */
        bool is_vn = (ver == 0);

        if (!is_quic_v1 && !is_quic_v2 && !is_quic_draft && !is_vn)
            return VPN_CONF_NONE;

        /* 解析 DCID / SCID */
        if (len < 7) return VPN_CONF_NONE;
        uint8_t dcid_len = p[5];
        if (dcid_len > 20 || (int)(6 + dcid_len + 1) > len) return VPN_CONF_NONE;
        uint8_t scid_len = p[6 + dcid_len];
        if ((int)(6 + dcid_len + 1 + scid_len) > len) return VPN_CONF_NONE;

        /* 获取 Long Header packet type (bits 5-4) */
        uint8_t pkt_type = (b0 >> 4) & 0x3;  /* 0=Initial,1=0-RTT,2=Handshake,3=Retry */

        bool is_initial   = (pkt_type == 0);
        bool is_handshake = (pkt_type == 2);

        /* Initial 包 + 1200 字节：Hysteria 的强特征 */
        if (is_initial && len == 1200) {
            if (info) {
                info->is_quic = true;
                info->quic_version = ver;
                info->dcid_len = (uint8_t)MIN(dcid_len, 20);
                memcpy(info->dcid, p + 6, info->dcid_len);
                info->scid_len = (uint8_t)MIN(scid_len, 20);
                if (scid_len > 0)
                    memcpy(info->scid, p + 7 + dcid_len, info->scid_len);
                info->init_pkt_cnt++;
                info->is_non_443 = (dport != 443 && sport != 443);
            }
            /* 非 443 端口 → 强烈 VPN 指标 */
            if (dport != 443 && sport != 443 &&
                dport != 8443 && sport != 8443)
                return VPN_CONF_HIGH;
            return VPN_CONF_MED;
        }

        /* Handshake 包 */
        if (is_handshake) {
            if (info) { info->is_quic = true; info->saw_handshake = true; }
            if (dport != 443 && sport != 443) return VPN_CONF_MED;
            return VPN_CONF_LOW;
        }

        /* 其他 Long Header */
        if (dport != 443 && sport != 443) return VPN_CONF_MED;
        return VPN_CONF_LOW;
    }

    /* QUIC Short Header: bit7=0 (Header Form=Short), bit6=1 (Fixed Bit) */
    if ((b0 & 0xC0) == 0x40) {
        /* Short header → data packet (无版本号无法确认是 QUIC，仅低置信度) */
        if (info) { info->is_quic = true; info->data_pkt_cnt++; }
        if (dport != 443 && sport != 443) return VPN_CONF_LOW;
        return VPN_CONF_NONE;
    }

    return VPN_CONF_NONE;
}

/* ============================================================
 * 主入口：单包无状态检测
 * 按置信度优先级依次检测，返回最高置信度结果。
 * ============================================================ */
VpnResult vpn_detect_packet(const uint8_t *payload, int len,
                              uint8_t ip_proto,
                              uint16_t sport, uint16_t dport) {
    VpnResult r;
    memset(&r, 0, sizeof r);
    r.proto      = VPN_UNKNOWN;
    r.confidence = VPN_CONF_NONE;
    r.transport  = VPN_TRANS_UNKNOWN;
    r.entropy    = vpn_entropy(payload, MIN(len, 128));

    if (!payload || len <= 0) return r;

    VpnConf c;
    bool tcp_flag = false;
    VpnTransport tr = VPN_TRANS_UNKNOWN;
    char path[128] = {0};

    /* 1. WireGuard (UDP, highest confidence when matched) */
    c = vpn_detect_wireguard(payload, len, ip_proto);
    if (c > r.confidence) {
        r.proto = VPN_WIREGUARD; r.confidence = c;
        r.transport = VPN_TRANS_UDP;
        snprintf(r.detail, sizeof r.detail,
                 "WireGuard msg_type=%u len=%d", u32le(payload), len);
    }

    /* 2. OpenVPN */
    c = vpn_detect_openvpn(payload, len, ip_proto, &tcp_flag);
    if (c > r.confidence) {
        uint8_t opc = 0;
        if (ip_proto == 6 && len >= 3) opc = (payload[2] >> 3) & 0x1F;
        else if (len >= 1)             opc = (payload[0] >> 3) & 0x1F;
        r.proto = VPN_OPENVPN; r.confidence = c;
        r.transport = tcp_flag ? VPN_TRANS_TCP : VPN_TRANS_UDP;
        snprintf(r.detail, sizeof r.detail,
                 "OpenVPN opcode=%u %s", opc, tcp_flag ? "TCP" : "UDP");
    }

    /* 3. Hysteria / QUIC-based VPN (UDP + QUIC long header + non-443) */
    {
        HysteriaFlowInfo hys; memset(&hys, 0, sizeof hys);
        c = vpn_detect_hysteria(payload, len, ip_proto, sport, dport, &hys);
        if (c > r.confidence) {
            r.proto = VPN_HYSTERIA; r.confidence = c;
            r.transport = VPN_TRANS_QUIC;
            snprintf(r.detail, sizeof r.detail,
                     "QUIC-VPN ver=0x%08x port=%u dcid_len=%u init_padded=%s",
                     hys.quic_version, dport, hys.dcid_len,
                     (len == 1200) ? "yes" : "no");
        }
    }

    /* 4. Psiphon (OSSH first — high confidence) */
    {
        PsiphonFlowInfo psi; memset(&psi, 0, sizeof psi);
        c = vpn_detect_psiphon(payload, len, ip_proto, &psi);
        if (c > r.confidence) {
            r.proto = VPN_PSIPHON; r.confidence = c;
            r.transport = psi.is_meek ? VPN_TRANS_MEEK :
                          (psi.is_ossh ? VPN_TRANS_SSH : VPN_TRANS_SSH);
            snprintf(r.detail, sizeof r.detail,
                     "Psiphon %s banner='%.40s'",
                     psi.is_ossh ? "OSSH" : psi.is_meek ? "meek" : "SSH",
                     psi.ssh_banner[0] ? psi.ssh_banner : psi.meek_host);
        }
    }

    /* 4. Lantern */
    {
        LanternFlowInfo lan; memset(&lan, 0, sizeof lan);
        c = vpn_detect_lantern(payload, len, ip_proto, &lan);
        if (c > r.confidence) {
            r.proto = VPN_LANTERN; r.confidence = c;
            r.transport = lan.is_oquic ? VPN_TRANS_QUIC : VPN_TRANS_TCP;
            snprintf(r.detail, sizeof r.detail, "Lantern %s",
                     lan.is_lampshade ? "lampshade" : lan.is_oquic ? "OQUIC" : "HTTP");
        }
    }

    /* 5. Clash */
    c = vpn_detect_clash(payload, len, sport, dport);
    if (c > r.confidence) {
        r.proto = VPN_CLASH; r.confidence = c;
        r.transport = VPN_TRANS_TCP;
        snprintf(r.detail, sizeof r.detail, "Clash proxy port=%u", dport);
    }

    /* 6. VMess (V2Ray) */
    c = vpn_detect_vmess(payload, len, &tr, path, sizeof path);
    if (c > r.confidence) {
        r.proto = VPN_VMESS; r.confidence = c; r.transport = tr;
        snprintf(r.detail, sizeof r.detail, "VMess/%s path='%s'",
                 vpn_transport_name(tr), path);
    }

    /* 7. VLESS (V2Ray) */
    c = vpn_detect_vless(payload, len, &tr);
    if (c > r.confidence) {
        r.proto = VPN_VLESS; r.confidence = c; r.transport = tr;
        snprintf(r.detail, sizeof r.detail, "VLESS/%s", vpn_transport_name(tr));
    }

    /* 8. Shadowsocks (Clash/SSR) */
    {
        double ent = 0.0;
        c = vpn_detect_shadowsocks(payload, len, dport, &ent);
        if (c > r.confidence) {
            r.proto = VPN_SHADOWSOCKS; r.confidence = c;
            r.transport = (ip_proto == 17) ? VPN_TRANS_UDP : VPN_TRANS_TCP;
            snprintf(r.detail, sizeof r.detail,
                     "Shadowsocks entropy=%.2f len=%d", ent, len);
        }
    }

    /* 9. Trojan (lowest priority — needs flow context) */
    {
        bool has_tls = vpn_is_tls(payload, len);
        c = vpn_detect_trojan(payload, len, dport, has_tls);
        if (c > r.confidence) {
            r.proto = VPN_TROJAN; r.confidence = c;
            r.transport = VPN_TRANS_TLS;
            snprintf(r.detail, sizeof r.detail, "Trojan/TLS port=%u", dport);
        }
    }

    return r;
}

/* ============================================================
 * 流状态：初始化
 * ============================================================ */
void vpn_flow_init(VpnFlow *f, uint16_t sport, uint16_t dport,
                    uint8_t ip_proto) {
    memset(f, 0, sizeof *f);
    f->src_port  = sport;
    f->dst_port  = dport;
    f->ip_proto  = ip_proto;
    f->proto    = VPN_UNKNOWN;

    /* 已知 VPN 端口预标记 */
    f->on_known_vpn_port = (dport == PORT_WIREGUARD   ||
                             dport == PORT_OPENVPN_UDP  ||
                             dport == PORT_SS_DEFAULT   ||
                             sport == PORT_WIREGUARD    ||
                             sport == PORT_OPENVPN_UDP);
}

/* ============================================================
 * 流状态：更新（每包调用）
 * ============================================================ */
void vpn_flow_update(VpnFlow *f, const uint8_t *payload, int len,
                      bool is_fwd, double ts) {
    if (!payload || len <= 0) return;

    /* 时间戳 */
    if (f->n_pkts == 0) f->first_ts = ts;
    f->last_ts = ts;

    /* 包计数 */
    f->n_pkts++;
    if (is_fwd) f->n_fwd_pkts++; else f->n_bwd_pkts++;

    /* 包长序列 */
    if (f->n_pkts <= 16)
        f->pkt_len_seq[f->n_pkts - 1] = (uint16_t)len;

    /* 熵统计 */
    double H = vpn_entropy(payload, MIN(len, 128));
    f->entropy_sum += H;
    f->entropy_cnt++;

    /* TLS / HTTP 标记 */
    if (vpn_is_tls(payload, len)) f->has_tls = true;
    if (vpn_is_http(payload, len)) f->has_http = true;

    /* ---- WireGuard ---- */
    if (f->proto == VPN_UNKNOWN || f->proto == VPN_WIREGUARD) {
        VpnConf c = vpn_detect_wireguard(payload, len, f->ip_proto);
        if (c > VPN_CONF_NONE) {
            uint32_t msg_type = u32le(payload);
            f->wg.seen_types |= (uint8_t)(1 << (msg_type - 1));
            if (msg_type == WG_MSG_INITIATION) {
                f->wg.sender_index = u32le(payload + 4);
                memcpy(f->wg.peer_pub_key, payload + 8, 32);
            }
            if (msg_type == WG_MSG_RESPONSE)
                f->wg.receiver_index = u32le(payload + 4);
            if (msg_type == WG_MSG_DATA) f->wg.data_pkt_cnt++;
            if ((f->wg.seen_types & 0x03) == 0x03) f->wg.handshake_done = true;
            if (c > f->confidence) {
                f->proto = VPN_WIREGUARD;
                f->confidence = c;
                f->transport  = VPN_TRANS_UDP;
            }
        }
    }

    /* ---- OpenVPN ---- */
    if (f->proto == VPN_UNKNOWN || f->proto == VPN_OPENVPN) {
        bool is_tcp = false;
        VpnConf c = vpn_detect_openvpn(payload, len, f->ip_proto, &is_tcp);
        if (c > VPN_CONF_NONE) {
            const uint8_t *dp = is_tcp ? payload + 2 : payload;
            uint8_t opc = (dp[0] >> 3) & 0x1F;
            f->ovpn.seen_opcodes |= (uint8_t)(1 << (opc - 1));
            if (f->ovpn.first_opcode == 0) f->ovpn.first_opcode = opc;
            if (opc == OVPN_P_CONTROL_HARD_RESET_CLIENT_V2) f->ovpn.saw_reset_client = true;
            if (opc == OVPN_P_CONTROL_HARD_RESET_SERVER_V2) f->ovpn.saw_reset_server = true;
            if (len > 9 && f->ovpn.saw_reset_client && is_fwd)
                memcpy(f->ovpn.session_id, dp + 1, 8);
            f->ovpn.is_tcp = is_tcp;
            if (c > f->confidence) {
                f->proto = VPN_OPENVPN;
                f->confidence = c;
                f->transport  = is_tcp ? VPN_TRANS_TCP : VPN_TRANS_UDP;
            }
        }
    }

    /* ---- Hysteria / QUIC-VPN ---- */
    {
        HysteriaFlowInfo hys; memset(&hys, 0, sizeof hys);
        VpnConf c = vpn_detect_hysteria(payload, len, f->ip_proto,
                                         f->src_port, f->dst_port, &hys);
        if (c > f->confidence) {
            f->proto = VPN_HYSTERIA; f->confidence = c;
            f->transport = VPN_TRANS_QUIC;
        }
        /* 累积流级别 QUIC 统计 */
        if (hys.is_quic) {
            f->hysteria.is_quic = true;
            f->hysteria.quic_version = hys.quic_version;
            f->hysteria.init_pkt_cnt  += hys.init_pkt_cnt;
            f->hysteria.data_pkt_cnt  += hys.data_pkt_cnt;
            if (hys.saw_handshake) f->hysteria.saw_handshake = true;
            if (hys.dcid_len > 0 && f->hysteria.dcid_len == 0) {
                f->hysteria.dcid_len = hys.dcid_len;
                memcpy(f->hysteria.dcid, hys.dcid, hys.dcid_len);
            }
            f->hysteria.is_non_443 = (f->dst_port != 443 && f->src_port != 443);
        }
    }

    /* ---- Psiphon ---- */
    {
        PsiphonFlowInfo psi; memset(&psi, 0, sizeof psi);
        VpnConf c = vpn_detect_psiphon(payload, len, f->ip_proto, &psi);
        if (c > f->confidence) {
            f->proto = VPN_PSIPHON; f->confidence = c;
            f->transport = psi.is_meek ? VPN_TRANS_MEEK : VPN_TRANS_SSH;
            f->psiphon = psi;
        }
    }

    /* ---- Lantern ---- */
    {
        LanternFlowInfo lan; memset(&lan, 0, sizeof lan);
        VpnConf c = vpn_detect_lantern(payload, len, f->ip_proto, &lan);
        if (c > f->confidence) {
            f->proto = VPN_LANTERN; f->confidence = c;
            f->transport = lan.is_oquic ? VPN_TRANS_QUIC : VPN_TRANS_TCP;
            f->lantern = lan;
        }
    }

    /* ---- Clash ---- */
    {
        VpnConf c = vpn_detect_clash(payload, len, f->src_port, f->dst_port);
        if (c > f->confidence) {
            f->proto = VPN_CLASH; f->confidence = c;
            f->transport = VPN_TRANS_TCP;
        }
    }

    /* ---- VMess ---- */
    {
        VpnTransport tr = VPN_TRANS_UNKNOWN;
        char path[128] = {0};
        VpnConf c = vpn_detect_vmess(payload, len, &tr, path, sizeof path);
        if (c > f->confidence) {
            f->proto = VPN_VMESS; f->confidence = c; f->transport = tr;
            f->vmess.is_websocket = (tr == VPN_TRANS_WS || tr == VPN_TRANS_WSS);
            f->vmess.is_grpc      = (tr == VPN_TRANS_GRPC);
            f->vmess.is_http2     = (tr == VPN_TRANS_HTTP2);
            memcpy(f->vmess.http_path, path, sizeof f->vmess.http_path - 1);
        }
    }

    /* ---- VLESS ---- */
    {
        VpnTransport tr = VPN_TRANS_UNKNOWN;
        VpnConf c = vpn_detect_vless(payload, len, &tr);
        if (c > f->confidence) {
            f->proto = VPN_VLESS; f->confidence = c; f->transport = tr;
        }
    }

    /* ---- Shadowsocks ---- */
    {
        double ent = 0.0;
        VpnConf c = vpn_detect_shadowsocks(payload, len, f->dst_port, &ent);
        if (c > f->confidence) {
            f->proto = VPN_SHADOWSOCKS; f->confidence = c;
            f->transport = (f->ip_proto == 17) ? VPN_TRANS_UDP : VPN_TRANS_TCP;
            f->ss.entropy = ent;
            f->ss.first_pkt_len = (uint16_t)len;
            if (len >= 32) memcpy(f->ss.salt, payload, 32);
        }
    }

    /* ---- Trojan（最低优先级，仅在其他未识别时） ---- */
    if (f->proto == VPN_UNKNOWN || f->proto == VPN_TROJAN) {
        VpnConf c = vpn_detect_trojan(payload, len, f->dst_port, f->has_tls);
        if (c > f->confidence) {
            f->proto = VPN_TROJAN; f->confidence = c;
            f->transport = VPN_TRANS_TLS;
        }
    }
}

/* ============================================================
 * 流结果输出
 * ============================================================ */
void vpn_flow_result(const VpnFlow *f, VpnResult *r) {
    if (!r) return;
    r->proto      = f->proto;
    r->confidence = f->confidence;
    r->transport  = f->transport;
    r->entropy    = f->entropy_cnt > 0 ? f->entropy_sum / f->entropy_cnt : 0.0;
    snprintf(r->detail, sizeof r->detail, "%.191s", f->detail);
}

void vpn_flow_emit(const VpnFlow *f, FILE *fp) {
    if (!fp) return;
    double duration = f->last_ts - f->first_ts;
    double avg_ent  = f->entropy_cnt > 0 ? f->entropy_sum / f->entropy_cnt : 0.0;

    fprintf(fp,
        "=== VPN FLOW ===\n"
        "  Proto     : %-15s  Confidence: %s\n"
        "  Transport : %s\n"
        "  Ports     : sport=%u  dport=%u  ip_proto=%u\n"
        "  Packets   : total=%u  fwd=%u  bwd=%u\n"
        "  Time      : %.6f — %.6f  (%.3f ms)\n"
        "  Avg.Entropy: %.3f bits/byte  HasTLS=%d  HasHTTP=%d\n",
        vpn_proto_name(f->proto), vpn_conf_name(f->confidence),
        vpn_transport_name(f->transport),
        f->src_port, f->dst_port, f->ip_proto,
        f->n_pkts, f->n_fwd_pkts, f->n_bwd_pkts,
        f->first_ts, f->last_ts, duration * 1000.0,
        avg_ent, f->has_tls, f->has_http);

    /* 包长序列 */
    int show = MIN(f->n_pkts, 16);
    fprintf(fp, "  PktLen seq:");
    int i;
    for (i = 0; i < show; i++) fprintf(fp, " %u", f->pkt_len_seq[i]);
    fprintf(fp, "\n");

    /* 协议特定详情 */
    switch (f->proto) {
    case VPN_WIREGUARD:
        fprintf(fp, "  WireGuard: seen_types=0x%02x  handshake_done=%d"
                    "  data_pkts=%u\n",
                f->wg.seen_types, f->wg.handshake_done, f->wg.data_pkt_cnt);
        if (f->wg.peer_pub_key[0] || f->wg.peer_pub_key[1]) {
            fprintf(fp, "    Ephemeral pubkey: %02x%02x%02x%02x...\n",
                    f->wg.peer_pub_key[0], f->wg.peer_pub_key[1],
                    f->wg.peer_pub_key[2], f->wg.peer_pub_key[3]);
        }
        break;
    case VPN_OPENVPN:
        fprintf(fp, "  OpenVPN: first_opcode=%u  seen_opcodes=0x%02x  TCP=%d\n"
                    "    reset_cli=%d  reset_srv=%d\n",
                f->ovpn.first_opcode, f->ovpn.seen_opcodes, f->ovpn.is_tcp,
                f->ovpn.saw_reset_client, f->ovpn.saw_reset_server);
        break;
    case VPN_SHADOWSOCKS:
        fprintf(fp, "  Shadowsocks: entropy=%.3f  first_pkt_len=%u\n"
                    "    salt(hex): %02x%02x%02x%02x...\n",
                f->ss.entropy, f->ss.first_pkt_len,
                f->ss.salt[0], f->ss.salt[1], f->ss.salt[2], f->ss.salt[3]);
        break;
    case VPN_VMESS:
    case VPN_VLESS:
    case VPN_V2RAY:
        fprintf(fp, "  VMess/VLESS: ws=%d  grpc=%d  h2=%d  path='%s'\n",
                f->vmess.is_websocket, f->vmess.is_grpc, f->vmess.is_http2,
                f->vmess.http_path);
        break;
    case VPN_PSIPHON:
        fprintf(fp, "  Psiphon: ossh=%d  meek=%d  ssh=%d\n"
                    "    banner='%s'  meek_host='%s'\n",
                f->psiphon.is_ossh, f->psiphon.is_meek, f->psiphon.is_ssh,
                f->psiphon.ssh_banner, f->psiphon.meek_host);
        break;
    case VPN_LANTERN:
        fprintf(fp, "  Lantern: lampshade=%d  oquic=%d  msg_type=0x%02x\n",
                f->lantern.is_lampshade, f->lantern.is_oquic,
                f->lantern.lamp_msg_type);
        break;
    case VPN_HYSTERIA: {
        const HysteriaFlowInfo *h = &f->hysteria;
        fprintf(fp, "  Hysteria/QUIC-VPN: quic_ver=0x%08x  non_443=%d\n"
                    "    init_pkts=%u  data_pkts=%u  handshake=%d\n",
                h->quic_version, h->is_non_443,
                h->init_pkt_cnt, h->data_pkt_cnt, h->saw_handshake);
        if (h->dcid_len > 0) {
            fprintf(fp, "    DCID(%u): ", h->dcid_len);
            for (int di = 0; di < h->dcid_len; di++) fprintf(fp, "%02x", h->dcid[di]);
            fprintf(fp, "\n");
        }
        break;
    }
    default:
        break;
    }
    fprintf(fp, "---\n\n");
}
