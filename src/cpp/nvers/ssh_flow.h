/**
 * ssh_flow.h  ——  SSH 协议深度字段解析（Header-Only）
 *
 * 标准：RFC 4253 (SSH Transport Layer Protocol)
 *       RFC 4254 (SSH Connection Protocol)
 *       RFC 4252 (SSH Authentication Protocol)
 *       RFC 4250 (SSH Assigned Numbers)
 *
 * 解析层次：
 *   1. Banner     → 版本协议/软件/OS注释
 *   2. KEXINIT    → 双方各8个算法 name-list
 *   3. KEX msgs   → ECDH/DH/DH-GEX 参数
 *   4. NEWKEYS    → 加密建立时刻
 *   5. 后加密     → 包计数、重协商检测
 *   6. 断连       → reason code + description
 *
 * 提取的元信息（完整列表）：
 *   ─ Banner ─
 *   protocol_version  (2.0 / 1.99 / 1.5 / 1.3)
 *   software_version  (OpenSSH_8.9 / Dropbear_2022.82 / etc.)
 *   banner_comment    (Ubuntu-3ubuntu0.3 / etc.)
 *   ─ KEXINIT（客户端 / 服务端各一份）─
 *   kex_algos, host_key_algos
 *   enc_c2s, enc_s2c, mac_c2s, mac_s2c
 *   comp_c2s, comp_s2c, lang_c2s, lang_s2c
 *   first_kex_follows, cookie (hex)
 *   ─ 协商算法（取双方 name-list 的首个交集）─
 *   neg_kex, neg_host_key, neg_enc_c2s, neg_enc_s2c
 *   neg_mac_c2s, neg_mac_s2c, neg_comp_c2s, neg_comp_s2c
 *   ─ 密钥交换类型 ─
 *   kex_type  (ecdh / dh-group / dh-gex)
 *   dh_gex_min / dh_gex_n / dh_gex_max
 *   host_key_type (ssh-rsa / ecdsa-sha2-nistp256 / ssh-ed25519 / etc.)
 *   host_key_len (bytes)
 *   ─ 状态 & 时序 ─
 *   state, c_newkeys, s_newkeys
 *   ts_banner_ms, ts_kexinit_ms, ts_newkeys_ms (相对流首包)
 *   rekey_count
 *   ─ 包统计 ─
 *   pkts_pre_enc, pkts_post_enc, total_pkts
 *   bytes_pre_enc, bytes_post_enc
 *   ─ Service / Auth ─
 *   service_requested (ssh-userauth / ssh-connection)
 *   auth_method_hint  (publickey / password / keyboard-interactive)
 *   auth_username
 *   ─ Channel ─
 *   chan_session_cnt, chan_x11_cnt, chan_fwd_cnt, chan_direct_cnt
 *   ─ 断连 ─
 *   disconnect_reason, disconnect_desc
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <algorithm>

/* ============================================================
 * SSH 消息类型常量
 * ============================================================ */
#define SSH_MSG_DISCONNECT          1u
#define SSH_MSG_SERVICE_REQUEST     5u
#define SSH_MSG_SERVICE_ACCEPT      6u
#define SSH_MSG_KEXINIT            20u
#define SSH_MSG_NEWKEYS            21u
#define SSH_MSG_KEX_DH_GEX_REQ    34u
#define SSH_MSG_KEX_DH_GEX_GROUP  31u
#define SSH_MSG_KEX_DH_GEX_INIT   32u
#define SSH_MSG_KEX_DH_GEX_REPLY  33u
#define SSH_MSG_KEXECDH_INIT       30u
#define SSH_MSG_KEXECDH_REPLY      31u
#define SSH_MSG_USERAUTH_REQUEST   50u
#define SSH_MSG_USERAUTH_FAILURE   51u
#define SSH_MSG_USERAUTH_SUCCESS   52u
#define SSH_MSG_USERAUTH_PK_OK     60u
#define SSH_MSG_GLOBAL_REQUEST     80u
#define SSH_MSG_CHANNEL_OPEN       90u
#define SSH_MSG_CHANNEL_REQUEST    98u

/* ============================================================
 * SSH 断连原因码
 * ============================================================ */
static inline const char *ssh_disconnect_reason(uint32_t code) {
    switch (code) {
    case 1:  return "HOST_NOT_ALLOWED_TO_CONNECT";
    case 2:  return "PROTOCOL_ERROR";
    case 3:  return "KEY_EXCHANGE_FAILED";
    case 4:  return "RESERVED";
    case 5:  return "MAC_ERROR";
    case 6:  return "COMPRESSION_ERROR";
    case 7:  return "SERVICE_NOT_AVAILABLE";
    case 8:  return "PROTOCOL_VERSION_NOT_SUPPORTED";
    case 9:  return "HOST_KEY_NOT_VERIFIABLE";
    case 10: return "CONNECTION_LOST";
    case 11: return "BY_APPLICATION";
    case 12: return "TOO_MANY_CONNECTIONS";
    case 13: return "AUTH_CANCELLED_BY_USER";
    case 14: return "NO_MORE_AUTH_METHODS_AVAILABLE";
    case 15: return "ILLEGAL_USER_NAME";
    default: return "UNKNOWN";
    }
}

/* ============================================================
 * 快速识别：是否为 SSH（Banner 以 "SSH-" 开头）
 * ============================================================ */
static inline bool detect_ssh(const uint8_t *payload, int len) {
    return len >= 4 && memcmp(payload, "SSH-", 4) == 0;
}

/* ============================================================
 * 内部辅助：读取 SSH string（uint32 len + bytes）
 * 返回消耗字节数，-1=失败
 * ============================================================ */
static inline int ssh__read_str(const uint8_t *p, int rem,
                                 char *out, int outsz) {
    if (rem < 4) return -1;
    uint32_t slen = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
                    ((uint32_t)p[2]<<8)|p[3];
    if ((int)slen > rem - 4 || slen > 4096u) return -1;
    int cp = (int)slen < outsz - 1 ? (int)slen : outsz - 1;
    memcpy(out, p + 4, (size_t)cp);
    out[cp] = '\0';
    return 4 + (int)slen;
}

/* ============================================================
 * KEXINIT 解析结果（一侧）
 * ============================================================ */
struct SshKexInit {
    char cookie_hex[33];          /* 16 字节随机 cookie → hex               */
    char kex_algos[384];          /* key exchange algorithms                 */
    char host_key_algos[256];     /* server host key algorithms              */
    char enc_c2s[256];            /* encryption c→s                         */
    char enc_s2c[256];            /* encryption s→c                         */
    char mac_c2s[256];            /* mac c→s                                */
    char mac_s2c[256];            /* mac s→c                                */
    char comp_c2s[64];            /* compression c→s                        */
    char comp_s2c[64];            /* compression s→c                        */
    char lang_c2s[64];            /* languages c→s                          */
    char lang_s2c[64];            /* languages s→c                          */
    bool first_kex_follows;
    bool parsed;

    /* 从有效载荷解析 KEXINIT（跳过类型字节后的部分） */
    bool parse(const uint8_t *payload, int plen) {
        if (plen < 17) return false;
        /* cookie (16 bytes → hex) */
        for (int i = 0; i < 16; i++)
            snprintf(cookie_hex + 2*i, 3, "%02x", payload[i]);
        cookie_hex[32] = '\0';

        const uint8_t *p = payload + 16;
        int rem = plen - 16;
        int adv;

        auto read = [&](char *out, int outsz) -> bool {
            adv = ssh__read_str(p, rem, out, outsz);
            if (adv < 0) return false;
            p += adv; rem -= adv; return true;
        };

        if (!read(kex_algos,    sizeof kex_algos))   return false;
        if (!read(host_key_algos, sizeof host_key_algos)) return false;
        if (!read(enc_c2s,      sizeof enc_c2s))     return false;
        if (!read(enc_s2c,      sizeof enc_s2c))     return false;
        if (!read(mac_c2s,      sizeof mac_c2s))     return false;
        if (!read(mac_s2c,      sizeof mac_s2c))     return false;
        if (!read(comp_c2s,     sizeof comp_c2s))    return false;
        if (!read(comp_s2c,     sizeof comp_s2c))    return false;
        if (!read(lang_c2s,     sizeof lang_c2s))    return false;
        if (!read(lang_s2c,     sizeof lang_s2c))    return false;
        if (rem >= 1) first_kex_follows = (p[0] != 0);
        parsed = true;
        return true;
    }
};

/* ============================================================
 * 算法协商：取两个 name-list 第一个公共条目
 * ============================================================ */
static inline void ssh_negotiate(const char *client_list,
                                  const char *server_list,
                                  char *out, int outsz) {
    out[0] = '\0';
    if (!client_list[0] || !server_list[0]) return;
    /* 遍历 client_list 中每个条目 */
    char tmp[128];
    const char *cp = client_list;
    while (*cp) {
        const char *comma = strchr(cp, ',');
        int elen = comma ? (int)(comma - cp) : (int)strlen(cp);
        if (elen > 0 && elen < (int)sizeof tmp) {
            memcpy(tmp, cp, (size_t)elen); tmp[elen] = '\0';
            /* 检查是否在 server_list 中 */
            const char *sp = server_list;
            while (*sp) {
                const char *sc = strchr(sp, ',');
                int slen = sc ? (int)(sc - sp) : (int)strlen(sp);
                if (slen == elen && memcmp(sp, tmp, (size_t)elen) == 0) {
                    int cp2 = elen < outsz-1 ? elen : outsz-1;
                    memcpy(out, tmp, (size_t)cp2); out[cp2] = '\0';
                    return;
                }
                sp = sc ? sc + 1 : sp + slen;
            }
        }
        cp = comma ? comma + 1 : cp + elen;
    }
}

/* ============================================================
 * SSH 流记录
 * ============================================================ */
struct SshFlowRecord {

    /* ---- Banner ---- */
    char  cli_proto_ver[8];       /* "2.0", "1.99", "1.5"                  */
    char  cli_software[64];       /* "OpenSSH_8.9", "Dropbear_2022.82"     */
    char  cli_comment[64];        /* "Ubuntu-3ubuntu0.3"                   */
    char  srv_proto_ver[8];
    char  srv_software[64];
    char  srv_comment[64];

    /* ---- KEXINIT（双侧）---- */
    SshKexInit cli_kex;           /* 客户端发出的 KEXINIT                  */
    SshKexInit srv_kex;           /* 服务端发出的 KEXINIT                  */

    /* ---- 协商算法 ---- */
    char neg_kex[96];             /* 已协商: kex algorithm                 */
    char neg_host_key[64];        /* 已协商: host key algorithm            */
    char neg_enc_c2s[64];
    char neg_enc_s2c[64];
    char neg_mac_c2s[64];
    char neg_mac_s2c[64];
    char neg_comp_c2s[32];
    char neg_comp_s2c[32];

    /* ---- KEX 类型 ---- */
    enum KexType : uint8_t { KEX_UNKNOWN=0, KEX_ECDH=1, KEX_DH_GROUP=2, KEX_DH_GEX=3 };
    KexType kex_type;
    uint32_t dh_gex_min;          /* DH-GEX: minimum group size (bits)     */
    uint32_t dh_gex_n;            /* DH-GEX: preferred group size          */
    uint32_t dh_gex_max;          /* DH-GEX: maximum group size            */
    char  host_key_type[64];      /* 服务端主机密钥类型（来自KEX reply）   */
    uint32_t host_key_len;        /* 服务端主机密钥字节长度                */

    /* ---- 加密握手状态 ---- */
    enum State : uint8_t {
        S_INIT=0, S_BANNER=1, S_KEXINIT=2,
        S_KEX=3, S_NEWKEYS=4, S_ENCRYPTED=5
    };
    State   state;
    bool    cli_newkeys;          /* 客户端已发 NEWKEYS                    */
    bool    srv_newkeys;          /* 服务端已发 NEWKEYS                    */
    uint16_t rekey_count;         /* 重新密钥协商次数                      */

    /* ---- 时序（相对首包，毫秒）---- */
    double  ts_first;
    double  ts_banner_cli;        /* 客户端 Banner 到达时刻                */
    double  ts_banner_srv;
    double  ts_kexinit_cli;       /* 客户端 KEXINIT 到达时刻               */
    double  ts_kexinit_srv;
    double  ts_newkeys;           /* NEWKEYS 完成时刻                      */

    /* ---- 包/字节统计 ---- */
    uint32_t pkts_total;
    uint32_t pkts_pre_enc;        /* 加密前（含握手）                      */
    uint32_t pkts_post_enc;       /* 加密后                                */
    uint64_t bytes_pre_enc;
    uint64_t bytes_post_enc;

    /* ---- Service / Auth ---- */
    char  service_requested[32];  /* "ssh-userauth" / "ssh-connection"     */
    char  auth_username[64];      /* 用户名（MSG_USERAUTH_REQUEST）        */
    char  auth_service[32];       /* 认证目标服务                          */
    char  auth_method[32];        /* "password" / "publickey" / "gssapi"   */
    uint8_t auth_attempts;        /* 认证尝试次数                          */
    bool    auth_success;

    /* ---- 通道 ---- */
    uint16_t chan_session_cnt;    /* channel type "session"                */
    uint16_t chan_x11_cnt;        /* channel type "x11"                   */
    uint16_t chan_fwd_cnt;        /* channel type "forwarded-tcpip"       */
    uint16_t chan_direct_cnt;     /* channel type "direct-tcpip"          */

    /* ---- 断连 ---- */
    uint32_t disconnect_reason;
    char     disconnect_desc[64];

    /* ============================================================
     * 初始化
     * ============================================================ */
    void init() noexcept {
        memset(this, 0, sizeof *this);
        state = S_INIT;
        ts_first = ts_banner_cli = ts_banner_srv = -1.0;
        ts_kexinit_cli = ts_kexinit_srv = ts_newkeys = -1.0;
    }

    /* ============================================================
     * 解析 Banner 行（"SSH-version-software comment\r\n"）
     * ============================================================ */
    void _parse_banner(const uint8_t *p, int len, bool is_client, double ts) {
        /* 跳过 "SSH-" */
        if (len < 4 || memcmp(p, "SSH-", 4) != 0) return;
        char buf[256];
        int blen = std::min(len, 255);
        memcpy(buf, p, (size_t)blen); buf[blen] = '\0';
        /* Strip \r\n */
        for (int i = blen-1; i >= 0 && (buf[i]=='\r'||buf[i]=='\n'); i--) buf[i]='\0';

        char *ver = buf + 4;               /* after "SSH-" */
        char *dash = strchr(ver, '-');
        if (!dash) return;
        *dash = '\0';
        char *soft = dash + 1;
        char *sp = strchr(soft, ' ');
        char *comment = sp ? sp + 1 : (char*)"";
        if (sp) *sp = '\0';

        char *proto  = is_client ? cli_proto_ver  : srv_proto_ver;
        char *sw     = is_client ? cli_software   : srv_software;
        char *comm   = is_client ? cli_comment    : srv_comment;
        double *tsp  = is_client ? &ts_banner_cli : &ts_banner_srv;

        snprintf(proto, 8,   "%s", ver);
        snprintf(sw,   64,   "%s", soft);
        snprintf(comm, 64,   "%s", comment);
        *tsp = ts;
        if (state == S_INIT) state = S_BANNER;
    }

    /* ============================================================
     * 解析 SSH 二进制包头（RFC4253: 4+1+payload+pad+mac）
     * 返回 payload 指针和长度；len 必须是 TCP payload 长度
     * ============================================================ */
    static const uint8_t *_parse_pkt(const uint8_t *data, int len,
                                      int *payload_len) {
        if (len < 5) return nullptr;
        uint32_t pkt_len = ((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|
                           ((uint32_t)data[2]<<8)|data[3];
        /* 合理性检查：1 ≤ pkt_len ≤ 35000 */
        if (pkt_len < 1 || pkt_len > 35000) return nullptr;
        if (4 + (int)pkt_len > len) return nullptr; /* 包不完整 */
        uint8_t pad = data[4];
        if (pad >= pkt_len) return nullptr;
        *payload_len = (int)pkt_len - (int)pad - 1;
        if (*payload_len < 1) return nullptr;
        return data + 5;
    }

    /* ============================================================
     * 每包处理
     * @param data       TCP payload 起始指针
     * @param len        TCP payload 长度
     * @param is_client  true = 客户端→服务端方向
     * @param ts         绝对时间戳（秒）
     * ============================================================ */
    void process_pkt(const uint8_t *data, int len,
                     bool is_client, double ts) noexcept {
        if (len <= 0 || !data) return;
        if (ts_first < 0.0) ts_first = ts;
        pkts_total++;

        /* ---- Banner（文本行，以 SSH- 开头）---- */
        if (len >= 4 && memcmp(data, "SSH-", 4) == 0) {
            _parse_banner(data, len, is_client, ts);
            pkts_pre_enc++;
            bytes_pre_enc += (uint64_t)len;
            return;
        }

        /* ---- 二进制包（握手或加密）---- */
        bool enc = (cli_newkeys && srv_newkeys);
        if (enc) {
            pkts_post_enc++;
            bytes_post_enc += (uint64_t)len;
        } else {
            pkts_pre_enc++;
            bytes_pre_enc += (uint64_t)len;
        }

        /* 不尝试解析加密内容（NEWKEYS 后） */
        if (enc) return;

        /* 一个 TCP payload 可能包含多个 SSH 包 */
        const uint8_t *ptr = data;
        int rem = len;
        while (rem >= 5) {
            int pay_len = 0;
            const uint8_t *pay = _parse_pkt(ptr, rem, &pay_len);
            if (!pay || pay_len < 1) break;

            uint8_t msg_type = pay[0];
            const uint8_t *msg = pay + 1;
            int mlen = pay_len - 1;

            switch (msg_type) {
            case SSH_MSG_KEXINIT: {
                if (is_client) {
                    if (!cli_kex.parsed) {
                        cli_kex.parse(msg, mlen);
                        if (ts_kexinit_cli < 0.0) ts_kexinit_cli = ts;
                    }
                } else {
                    if (!srv_kex.parsed) {
                        srv_kex.parse(msg, mlen);
                        if (ts_kexinit_srv < 0.0) ts_kexinit_srv = ts;
                    }
                }
                if (state < S_KEXINIT) state = S_KEXINIT;
                /* 尝试协商 */
                if (cli_kex.parsed && srv_kex.parsed && !neg_kex[0]) {
                    ssh_negotiate(cli_kex.kex_algos,   srv_kex.kex_algos,   neg_kex,      sizeof neg_kex);
                    ssh_negotiate(cli_kex.host_key_algos, srv_kex.host_key_algos, neg_host_key, sizeof neg_host_key);
                    ssh_negotiate(cli_kex.enc_c2s,     srv_kex.enc_c2s,     neg_enc_c2s,  sizeof neg_enc_c2s);
                    ssh_negotiate(cli_kex.enc_s2c,     srv_kex.enc_s2c,     neg_enc_s2c,  sizeof neg_enc_s2c);
                    ssh_negotiate(cli_kex.mac_c2s,     srv_kex.mac_c2s,     neg_mac_c2s,  sizeof neg_mac_c2s);
                    ssh_negotiate(cli_kex.mac_s2c,     srv_kex.mac_s2c,     neg_mac_s2c,  sizeof neg_mac_s2c);
                    ssh_negotiate(cli_kex.comp_c2s,    srv_kex.comp_c2s,    neg_comp_c2s, sizeof neg_comp_c2s);
                    ssh_negotiate(cli_kex.comp_s2c,    srv_kex.comp_s2c,    neg_comp_s2c, sizeof neg_comp_s2c);
                    /* 推断 KEX 类型 */
                    if (strstr(neg_kex, "ecdh") || strstr(neg_kex, "curve"))
                        kex_type = KEX_ECDH;
                    else if (strstr(neg_kex, "gex"))
                        kex_type = KEX_DH_GEX;
                    else if (strstr(neg_kex, "diffie-hellman"))
                        kex_type = KEX_DH_GROUP;
                }
                break;
            }
            case SSH_MSG_KEX_DH_GEX_REQ: {
                kex_type = KEX_DH_GEX;
                if (mlen >= 12) {
                    dh_gex_min = ((uint32_t)msg[0]<<24)|((uint32_t)msg[1]<<16)|((uint32_t)msg[2]<<8)|msg[3];
                    dh_gex_n   = ((uint32_t)msg[4]<<24)|((uint32_t)msg[5]<<16)|((uint32_t)msg[6]<<8)|msg[7];
                    dh_gex_max = ((uint32_t)msg[8]<<24)|((uint32_t)msg[9]<<16)|((uint32_t)msg[10]<<8)|msg[11];
                }
                if (state < S_KEX) state = S_KEX;
                break;
            }
            case SSH_MSG_KEXECDH_INIT:
                if (kex_type == KEX_UNKNOWN) kex_type = KEX_ECDH;
                if (state < S_KEX) state = S_KEX;
                break;
            case SSH_MSG_KEXECDH_REPLY:
            case SSH_MSG_KEX_DH_GEX_REPLY: {
                /* Variable: [host_key_blob][eph_pub_key][sig] */
                if (!is_client && mlen >= 4) {
                    char hk_blob[256];
                    int adv = ssh__read_str(msg, mlen, hk_blob, sizeof hk_blob);
                    if (adv > 0) {
                        /* host_key_blob 首个 SSH string 是算法名 */
                        if ((uint32_t)adv > 4u) {
                            /* hk_blob is already a decoded string; read sub-string */
                            int blen = (int)strlen(hk_blob);
                            if (blen >= 4) {
                                uint32_t algo_len = ((uint8_t)hk_blob[0]<<24)|((uint8_t)hk_blob[1]<<16)|
                                                    ((uint8_t)hk_blob[2]<<8)|(uint8_t)hk_blob[3];
                                int cp = (int)algo_len < 63 ? (int)algo_len : 63;
                                memcpy(host_key_type, hk_blob + 4, (size_t)cp);
                                host_key_type[cp] = '\0';
                            }
                        }
                        /* 原始 host_key_blob 字节数 */
                        uint32_t bloblen = ((uint32_t)msg[0]<<24)|((uint32_t)msg[1]<<16)|
                                           ((uint32_t)msg[2]<<8)|msg[3];
                        host_key_len = bloblen;
                    }
                }
                if (state < S_KEX) state = S_KEX;
                break;
            }
            case SSH_MSG_NEWKEYS:
                if (is_client) { cli_newkeys = true; }
                else           { srv_newkeys = true; }
                if (cli_newkeys && srv_newkeys) {
                    state = S_ENCRYPTED;
                    ts_newkeys = ts;
                } else if (state < S_NEWKEYS) {
                    state = S_NEWKEYS;
                }
                break;
            case SSH_MSG_SERVICE_REQUEST: {
                char svc[32];
                if (ssh__read_str(msg, mlen, svc, sizeof svc) > 0)
                    snprintf(service_requested, sizeof service_requested, "%s", svc);
                break;
            }
            case SSH_MSG_USERAUTH_REQUEST: {
                const uint8_t *p2 = msg; int r2 = mlen;
                int adv;
                char user[64], svc2[32], method[32];
                if ((adv = ssh__read_str(p2, r2, user, sizeof user)) < 0) break;
                p2 += adv; r2 -= adv;
                if ((adv = ssh__read_str(p2, r2, svc2, sizeof svc2)) < 0) break;
                p2 += adv; r2 -= adv;
                if ((adv = ssh__read_str(p2, r2, method, sizeof method)) < 0) break;
                snprintf(auth_username, sizeof auth_username, "%s", user);
                snprintf(auth_service,  sizeof auth_service,  "%s", svc2);
                snprintf(auth_method,   sizeof auth_method,   "%s", method);
                auth_attempts++;
                break;
            }
            case SSH_MSG_USERAUTH_SUCCESS:
                auth_success = true;
                break;
            case SSH_MSG_CHANNEL_OPEN: {
                char chan_type[32];
                if (ssh__read_str(msg, mlen, chan_type, sizeof chan_type) > 0) {
                    if (strcmp(chan_type,"session")==0)          chan_session_cnt++;
                    else if (strcmp(chan_type,"x11")==0)         chan_x11_cnt++;
                    else if (strstr(chan_type,"forwarded"))      chan_fwd_cnt++;
                    else if (strstr(chan_type,"direct"))         chan_direct_cnt++;
                }
                break;
            }
            case SSH_MSG_DISCONNECT: {
                if (mlen >= 4) {
                    disconnect_reason = ((uint32_t)msg[0]<<24)|((uint32_t)msg[1]<<16)|
                                        ((uint32_t)msg[2]<<8)|msg[3];
                }
                char ddesc[64];
                if (ssh__read_str(msg + 4, mlen - 4, ddesc, sizeof ddesc) > 0)
                    snprintf(disconnect_desc, sizeof disconnect_desc, "%s", ddesc);
                break;
            }
            default: break;
            }

            /* 推进到下一个 SSH 包 */
            uint32_t pkt_len = ((uint32_t)ptr[0]<<24)|((uint32_t)ptr[1]<<16)|
                               ((uint32_t)ptr[2]<<8)|ptr[3];
            int advance = 4 + (int)pkt_len;
            if (advance <= 0 || advance > rem) break;
            ptr += advance; rem -= advance;
        }
    }

    /* ============================================================
     * 输出日志（写入 FILE *）
     * ============================================================ */
    void emit_log(FILE *fp, const char *flow_id = "") const {
        static const char *kex_type_name[] = {"unknown","ecdh","dh-group","dh-gex"};
        static const char *state_name[]    = {"INIT","BANNER","KEXINIT","KEX","NEWKEYS","ENCRYPTED"};
        fprintf(fp, "[SSH] %s\n", flow_id);
        fprintf(fp, "  Banner.Client    : SSH-%s-%s %s\n", cli_proto_ver, cli_software, cli_comment);
        fprintf(fp, "  Banner.Server    : SSH-%s-%s %s\n", srv_proto_ver, srv_software, srv_comment);
        fprintf(fp, "  State            : %s  rekey=%u\n", state_name[(int)state], rekey_count);
        fprintf(fp, "  NEWKEYS          : cli=%d srv=%d\n", cli_newkeys, srv_newkeys);
        if (cli_kex.parsed) {
            fprintf(fp, "  CLI.kex_algos    : %s\n", cli_kex.kex_algos);
            fprintf(fp, "  CLI.host_key     : %s\n", cli_kex.host_key_algos);
            fprintf(fp, "  CLI.enc_c2s      : %s\n", cli_kex.enc_c2s);
            fprintf(fp, "  CLI.enc_s2c      : %s\n", cli_kex.enc_s2c);
            fprintf(fp, "  CLI.mac_c2s      : %s\n", cli_kex.mac_c2s);
            fprintf(fp, "  CLI.mac_s2c      : %s\n", cli_kex.mac_s2c);
            fprintf(fp, "  CLI.comp         : %s / %s\n", cli_kex.comp_c2s, cli_kex.comp_s2c);
        }
        if (srv_kex.parsed) {
            fprintf(fp, "  SRV.kex_algos    : %s\n", srv_kex.kex_algos);
            fprintf(fp, "  SRV.host_key     : %s\n", srv_kex.host_key_algos);
            fprintf(fp, "  SRV.enc_c2s      : %s\n", srv_kex.enc_c2s);
            fprintf(fp, "  SRV.enc_s2c      : %s\n", srv_kex.enc_s2c);
        }
        fprintf(fp, "  Negotiated.kex   : %s  type=%s\n", neg_kex, kex_type_name[(int)kex_type]);
        if (kex_type == KEX_DH_GEX)
            fprintf(fp, "  DH-GEX           : min=%u n=%u max=%u\n", dh_gex_min, dh_gex_n, dh_gex_max);
        fprintf(fp, "  Negotiated.enc   : c2s=%s s2c=%s\n", neg_enc_c2s, neg_enc_s2c);
        fprintf(fp, "  Negotiated.mac   : c2s=%s s2c=%s\n", neg_mac_c2s, neg_mac_s2c);
        fprintf(fp, "  Negotiated.comp  : c2s=%s s2c=%s\n", neg_comp_c2s, neg_comp_s2c);
        fprintf(fp, "  HostKey.type     : %s  len=%u bytes\n", host_key_type, host_key_len);
        if (service_requested[0])
            fprintf(fp, "  ServiceRequest   : %s\n", service_requested);
        if (auth_username[0])
            fprintf(fp, "  Auth             : user=%s method=%s attempts=%u success=%d\n",
                    auth_username, auth_method, auth_attempts, auth_success);
        if (chan_session_cnt || chan_x11_cnt || chan_fwd_cnt || chan_direct_cnt)
            fprintf(fp, "  Channels         : session=%u x11=%u fwd=%u direct=%u\n",
                    chan_session_cnt, chan_x11_cnt, chan_fwd_cnt, chan_direct_cnt);
        fprintf(fp, "  Pkts             : pre_enc=%u post_enc=%u total=%u\n",
                pkts_pre_enc, pkts_post_enc, pkts_total);
        fprintf(fp, "  Bytes            : pre_enc=%llu post_enc=%llu\n",
                (unsigned long long)bytes_pre_enc, (unsigned long long)bytes_post_enc);
        if (disconnect_reason)
            fprintf(fp, "  Disconnect       : %u (%s) %s\n", disconnect_reason,
                    ssh_disconnect_reason(disconnect_reason), disconnect_desc);
        fprintf(fp, "\n");
    }
};
