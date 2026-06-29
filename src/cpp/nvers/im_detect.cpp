/**
 * im_detect.cpp  ——  即时通讯应用 / 协议识别实现
 */

#include "im_detect.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cctype>

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

static inline uint16_t u16be(const uint8_t *p) {
    return (uint16_t)((p[0]<<8)|p[1]);
}
static inline uint32_t u32be(const uint8_t *p) {
    return (uint32_t)((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]);
}
static inline uint32_t u32le(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

/* ============================================================
 * 工具函数
 * ============================================================ */
double im_entropy(const uint8_t *data, int len) {
    if (len <= 0) return 0.0;
    int freq[256];
    memset(freq, 0, sizeof(freq));
    for (int i = 0; i < len; i++) freq[data[i]]++;
    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            H -= p * log(p) / log(2.0);
        }
    }
    return H;
}

bool im_is_tls(const uint8_t *p, int len) {
    if (len < 6) return false;
    uint8_t ct = p[0];
    uint16_t ver = u16be(p + 1);
    if (ct < 20 || ct > 24) return false;
    if (ver < 0x0200 || ver > 0x0305) return false;
    uint16_t rlen = u16be(p + 3);
    if (rlen > 16384 + 2048) return false;
    return true;
}

bool im_is_http(const uint8_t *p, int len) {
    if (len < 8) return false;
    return (memcmp(p, "GET ",     4) == 0 ||
            memcmp(p, "POST ",    5) == 0 ||
            memcmp(p, "PUT ",     4) == 0 ||
            memcmp(p, "CONNECT ", 8) == 0 ||
            memcmp(p, "HTTP/",    5) == 0);
}

static const uint8_t *mem_icase(const uint8_t *hay, int hlen,
                                 const char *needle, int nlen) {
    for (int i = 0; i <= hlen - nlen; i++) {
        bool ok = true;
        for (int j = 0; j < nlen; j++) {
            if (tolower(hay[i+j]) != tolower((unsigned char)needle[j])) {
                ok = false; break;
            }
        }
        if (ok) return hay + i;
    }
    return nullptr;
}

static bool str_icase_contains(const char *hay, const char *needle) {
    if (!hay || !needle || !hay[0]) return false;
    int nlen = (int)strlen(needle);
    int hlen = (int)strlen(hay);
    return mem_icase((const uint8_t*)hay, hlen, needle, nlen) != nullptr;
}

const char *im_proto_name(ImProto p) {
    switch (p) {
    case IM_MTPROTO:      return "MTProto";
    case IM_TELEGRAM:     return "Telegram";
    case IM_WHATSAPP:     return "WhatsApp";
    case IM_SIGNAL:       return "Signal";
    case IM_FB_MESSENGER: return "Facebook-Messenger";
    case IM_WECHAT:       return "WeChat";
    case IM_LINE:         return "LINE";
    case IM_VIBER:        return "Viber";
    case IM_XMPP:         return "XMPP";
    case IM_SKYPE:        return "Skype/Teams";
    case IM_DISCORD:      return "Discord";
    case IM_SLACK:        return "Slack";
    case IM_WIRE:         return "Wire";
    case IM_GENERIC:      return "Generic-IM";
    default:              return "Unknown";
    }
}

const char *im_conf_name(ImConf c) {
    switch (c) {
    case IM_CONF_NONE: return "none";
    case IM_CONF_LOW:  return "low";
    case IM_CONF_MED:  return "medium";
    case IM_CONF_HIGH: return "high";
    default:           return "?";
    }
}

const char *im_transport_name(ImTransport t) {
    switch (t) {
    case IM_TRANS_TCP:  return "TCP";
    case IM_TRANS_UDP:  return "UDP";
    case IM_TRANS_TLS:  return "TLS";
    case IM_TRANS_WS:   return "WebSocket";
    case IM_TRANS_WSS:  return "WebSocket+TLS";
    case IM_TRANS_MQTT: return "MQTT";
    case IM_TRANS_QUIC: return "QUIC";
    case IM_TRANS_XMPP: return "XMPP";
    default:            return "unknown";
    }
}

/* ============================================================
 * TLS ClientHello SNI / ALPN 解析（简化版）
 * ============================================================ */
static bool parse_client_hello(const uint8_t *p, int len,
                                char *sni, int sni_max,
                                char *alpn, int alpn_max) {
    if (sni) sni[0] = '\0';
    if (alpn) alpn[0] = '\0';
    if (len < 43) return false;
    if (p[0] != 22) return false; /* Handshake record */
    int rec_len = u16be(p + 3);
    if (4 + rec_len > len) return false;
    const uint8_t *hs = p + 5;
    int hs_rem = rec_len;
    if (hs_rem < 4 || hs[0] != 1) return false; /* ClientHello */
    int hs_len = ((int)hs[1]<<16)|((int)hs[2]<<8)|hs[3];
    if (4 + hs_len > hs_rem) return false;
    const uint8_t *ch = hs + 4;
    int rem = hs_len;
    if (rem < 34) return false;
    ch += 2 + 32; rem -= 2 + 32; /* version + random */
    if (rem < 1) return false;
    int sess_len = ch[0]; ch++; rem--;
    if (rem < sess_len + 2) return false;
    ch += sess_len; rem -= sess_len;
    int cs_len = u16be(ch); ch += 2; rem -= 2;
    if (rem < cs_len + 1) return false;
    ch += cs_len; rem -= cs_len;
    int comp_len = ch[0]; ch++; rem--;
    if (rem < comp_len + 2) return false;
    ch += comp_len; rem -= comp_len;
    if (rem < 2) return false;
    int ext_total = u16be(ch); ch += 2; rem -= 2;
    if (rem < ext_total) ext_total = rem;
    const uint8_t *ext = ch;
    int ext_rem = ext_total;
    while (ext_rem >= 4) {
        uint16_t etype = u16be(ext);
        uint16_t elen  = u16be(ext + 2);
        ext += 4; ext_rem -= 4;
        if ((int)elen > ext_rem) break;
        if (etype == 0 && sni && sni_max > 1) {
            /* server_name extension */
            const uint8_t *ep = ext;
            int er = elen;
            if (er >= 2) {
                /* skip list len */
                ep += 2; er -= 2;
                if (er >= 3 && ep[0] == 0) { /* host_name */
                    int nlen = u16be(ep + 1);
                    if (3 + nlen <= er) {
                        int cp = MIN(nlen, sni_max - 1);
                        memcpy(sni, ep + 3, (size_t)cp);
                        sni[cp] = '\0';
                    }
                }
            }
        }
        if (etype == 16 && alpn && alpn_max > 1) {
            const uint8_t *ep = ext;
            int er = elen;
            if (er >= 2) {
                ep += 2; er -= 2;
                if (er >= 1) {
                    int plen = ep[0];
                    if (1 + plen <= er) {
                        int cp = MIN(plen, alpn_max - 1);
                        memcpy(alpn, ep + 1, (size_t)cp);
                        alpn[cp] = '\0';
                    }
                }
            }
        }
        ext += elen; ext_rem -= elen;
    }
    return sni && sni[0] != '\0';
}

bool im_tls_parse_sni(const uint8_t *p, int len, char *sni, int sni_max) {
    return parse_client_hello(p, len, sni, sni_max, nullptr, 0);
}

bool im_tls_parse_alpn(const uint8_t *p, int len, char *alpn, int alpn_max) {
    return parse_client_hello(p, len, nullptr, 0, alpn, alpn_max);
}

/* ============================================================
 * SNI → 应用映射
 * ============================================================ */
ImConf im_detect_by_sni(const char *sni, ImProto *proto_out, ImConf *conf_out) {
    if (!sni || !sni[0]) return IM_CONF_NONE;
    *proto_out = IM_UNKNOWN;
    *conf_out  = IM_CONF_NONE;

    struct { const char *pat; ImProto proto; ImConf conf; } table[] = {
        /* Telegram */
        {"telegram.org",     IM_TELEGRAM, IM_CONF_HIGH},
        {".telegram.org",    IM_TELEGRAM, IM_CONF_HIGH},
        {"t.me",             IM_TELEGRAM, IM_CONF_HIGH},
        {"telegra.ph",       IM_TELEGRAM, IM_CONF_MED},
        {"tdesktop.com",     IM_TELEGRAM, IM_CONF_MED},
        /* WhatsApp */
        {"whatsapp.net",     IM_WHATSAPP, IM_CONF_HIGH},
        {"whatsapp.com",     IM_WHATSAPP, IM_CONF_HIGH},
        {"wa.me",            IM_WHATSAPP, IM_CONF_MED},
        /* Signal */
        {"signal.org",       IM_SIGNAL,   IM_CONF_HIGH},
        {"whispersystems.org", IM_SIGNAL, IM_CONF_HIGH},
        /* Facebook Messenger */
        {"edge-mqtt.facebook.com", IM_FB_MESSENGER, IM_CONF_HIGH},
        {"mqtt-mini.facebook.com", IM_FB_MESSENGER, IM_CONF_HIGH},
        {"messenger.com",    IM_FB_MESSENGER, IM_CONF_MED},
        /* WeChat */
        {"weixin.qq.com",    IM_WECHAT,   IM_CONF_HIGH},
        {"wx.qq.com",        IM_WECHAT,   IM_CONF_HIGH},
        {"short.weixin.qq.com", IM_WECHAT, IM_CONF_HIGH},
        {"szshort.weixin.qq.com", IM_WECHAT, IM_CONF_HIGH},
        /* LINE */
        {"line.me",          IM_LINE,     IM_CONF_HIGH},
        {"line-apps.com",    IM_LINE,     IM_CONF_HIGH},
        {"legy.line-apps.com", IM_LINE,   IM_CONF_HIGH},
        /* Viber */
        {"viber.com",        IM_VIBER,    IM_CONF_HIGH},
        {"secure.viber.com", IM_VIBER,    IM_CONF_HIGH},
        /* Skype / Teams */
        {"skype.com",        IM_SKYPE,    IM_CONF_HIGH},
        {"teams.microsoft.com", IM_SKYPE, IM_CONF_HIGH},
        {"teams.live.com",   IM_SKYPE,    IM_CONF_MED},
        /* Discord */
        {"discord.com",      IM_DISCORD,  IM_CONF_HIGH},
        {"discord.gg",       IM_DISCORD,  IM_CONF_MED},
        {"discordapp.com",   IM_DISCORD,  IM_CONF_HIGH},
        {"gateway.discord.gg", IM_DISCORD, IM_CONF_HIGH},
        /* Slack */
        {"slack.com",        IM_SLACK,    IM_CONF_HIGH},
        {"slack-msgs.com",   IM_SLACK,    IM_CONF_MED},
        {"wss-primary.slack.com", IM_SLACK, IM_CONF_HIGH},
        /* Wire */
        {"wire.com",         IM_WIRE,     IM_CONF_HIGH},
        {"prod-nginz-https.wire.com", IM_WIRE, IM_CONF_HIGH},
        {nullptr, IM_UNKNOWN, IM_CONF_NONE}
    };

    for (int i = 0; table[i].pat; i++) {
        const char *pat = table[i].pat;
        if (pat[0] == '.') {
            if (str_icase_contains(sni, pat + 1)) {
                *proto_out = table[i].proto;
                *conf_out  = table[i].conf;
                return table[i].conf;
            }
        } else if (str_icase_contains(sni, pat)) {
            *proto_out = table[i].proto;
            *conf_out  = table[i].conf;
            return table[i].conf;
        }
    }
    return IM_CONF_NONE;
}

/* ============================================================
 * Telegram DC IP 段（RFC/社区公开 DC 地址）
 *   91.108.0.0/16, 91.105.192.0/23, 149.154.160.0/20,
 *   185.76.151.0/24, 95.161.76.0/23
 * ============================================================ */
bool im_is_telegram_dc_ip(uint32_t ip) {
    uint8_t a = (uint8_t)((ip >> 24) & 0xff);
    uint8_t b = (uint8_t)((ip >> 16) & 0xff);
    uint8_t c = (uint8_t)((ip >> 8) & 0xff);

    if (a == 91 && b == 108) return true;
    if (a == 91 && b == 105 && c >= 192) return true;
    if (a == 149 && b == 154 && c >= 160 && c < 176) return true;
    if (a == 185 && b == 76 && c == 151) return true;
    if (a == 95 && b == 161 && (c == 76 || c == 77)) return true;
    return false;
}

/* 统计 payload 尾部零字节（Telegram 伪装 TLS 大量 padding） */
static int im_count_tail_zeros(const uint8_t *p, int len, int scan) {
    if (len <= 0) return 0;
    int start = len - MIN(scan, len);
    int z = 0;
    for (int i = start; i < len; i++)
        if (p[i] == 0) z++;
    return z;
}

/* 是否为 TLS ClientHello 记录 */
static bool im_is_tls_client_hello(const uint8_t *p, int len) {
    if (len < 6 || p[0] != 22) return false;
    if (!im_is_tls(p, len)) return false;
    if (len < 6) return false;
    /* handshake header at p[5] */
    return (len >= 6 && p[5] == 1);
}

/**
 * Telegram 伪装 TLS（Fake TLS / obfuscated2）
 * 仅依据报文结构判定，不使用 SNI 域名白/黑名单（避免误伤真实 azure/google 访问）：
 *   - TLS ClientHello + 尾部大量 zero padding（典型 517 字节）
 *   - 目标端口为非标准高端口（MTProxy 常见 13248/50567 等，非 443/8443）
 *   - 或目标 IP 属于 Telegram DC 网段
 */
ImConf im_detect_telegram_fake_tls(const uint8_t *p, int len,
                                    uint32_t server_ip, uint16_t server_port,
                                    MtprotoFlowInfo *info) {
    if (!im_is_tls_client_hello(p, len)) return IM_CONF_NONE;

    int tail_zeros = im_count_tail_zeros(p, len, 160);
    bool padded = (len >= 480 && len <= 600 && tail_zeros >= 50);
    bool dc_ip = im_is_telegram_dc_ip(server_ip);
    bool mtproxy_port = (server_port != 443 && server_port != 8443 &&
                         server_port > 1024);

    if (info) {
        char sni[128];
        if (im_tls_parse_sni(p, len, sni, sizeof sni))
            snprintf(info->tls_sni, sizeof info->tls_sni, "%s", sni);
        if (padded) {
            info->saw_fake_tls = true;
            info->fake_tls_len = (uint16_t)len;
            info->transport_type = 6; /* fake TLS */
        }
    }

    /* 伪装 TLS：padding 结构 + 非标准端口（与 SNI 内容无关） */
    if (padded && mtproxy_port)
        return IM_CONF_HIGH;

    /* 直连 Telegram DC */
    if (dc_ip)
        return IM_CONF_HIGH;

    return IM_CONF_NONE;
}

/* ============================================================
 * MTProto 传输层检测
 * ============================================================ */
ImConf im_detect_mtproto(const uint8_t *p, int len, uint8_t proto,
                          MtprotoFlowInfo *info) {
    if (proto != 6 || len < 1) return IM_CONF_NONE;
    /* TLS 记录层不是 MTProto 明文传输 */
    if (im_is_tls(p, len)) return IM_CONF_NONE;

    /* Abridged: 0xEF */
    if (len >= 1 && p[0] == 0xEF) {
        if (info) {
            info->saw_abridged = true;
            info->transport_type = 1;
        }
        return IM_CONF_HIGH;
    }

    /* Intermediate: 0xEEEEEEEE */
    if (len >= 4 && p[0]==0xEE && p[1]==0xEE && p[2]==0xEE && p[3]==0xEE) {
        if (info) {
            info->saw_intermediate = true;
            info->transport_type = 2;
        }
        return IM_CONF_HIGH;
    }

    /* Padded intermediate: 0xDDDDDDDD */
    if (len >= 4 && p[0]==0xDD && p[1]==0xDD && p[2]==0xDD && p[3]==0xDD) {
        if (info) {
            info->saw_padded = true;
            info->transport_type = 3;
        }
        return IM_CONF_HIGH;
    }

    /* Full: LE length prefix, often small values for auth */
    if (len >= 8) {
        uint32_t le_len = u32le(p);
        if (le_len >= 4 && le_len <= 65536 && (int)(le_len + 4) <= len + 64) {
            /* auth_key_id 8 bytes after length in unencrypted */
            if (info) info->transport_type = 4;
            return IM_CONF_MED;
        }
    }

    /* Obfuscated: 64-byte header（仅 cleartext TCP，且非 HTTP） */
    if (len >= 56 && len <= 128 && !im_is_http(p, len)) {
        double ent = im_entropy(p, MIN(len, 64));
        if (ent > 5.8 && ent < 7.2) {
            if (info) {
                info->saw_obfuscated = true;
                info->transport_type = 5;
            }
            return IM_CONF_LOW; /* 单独 obfuscated 仅 LOW，需与 SNI 组合 */
        }
    }

    return IM_CONF_NONE;
}

/* ============================================================
 * WhatsApp (funXMPP / Noise)
 * ============================================================ */
ImConf im_detect_whatsapp(const uint8_t *p, int len, uint8_t proto,
                           WhatsappFlowInfo *info) {
    if (len < 2) return IM_CONF_NONE;

    /* Noise prologue "WA" + version */
    if (len >= 2 && p[0]=='W' && p[1]=='A') {
        if (info) info->saw_noise = true;
        return IM_CONF_HIGH;
    }

    /* funXMPP binary: token byte 0xF8 (list 8), 0xF9 (list 16), 0xFC (JID), etc. */
    if (proto == 6 && len >= 3) {
        uint8_t b0 = p[0];
        if (b0 == 0xF8 || b0 == 0xF9 || b0 == 0xFA || b0 == 0xFB ||
            b0 == 0xFC || b0 == 0xFD || b0 == 0xFE || b0 == 0xFF) {
            if (info) {
                info->saw_funxmpp = true;
                info->token_byte = b0;
            }
            return IM_CONF_MED;
        }
        /* Secondary token range 0x00-0x235 for dictionary tokens */
        if (b0 < 0xF8 && len >= 4) {
            double ent = im_entropy(p, MIN(len, 32));
            if (ent > 4.0 && ent < 7.5) {
                if (info) info->saw_stanza = true;
                return IM_CONF_LOW;
            }
        }
    }

    return IM_CONF_NONE;
}

/* ============================================================
 * Signal
 * ============================================================ */
ImConf im_detect_signal(const uint8_t *p, int len, SignalFlowInfo *info) {
    (void)info;
    if (len < 8) return IM_CONF_NONE;
    /* Noise pattern + high entropy after handshake */
    if (im_is_tls(p, len)) return IM_CONF_NONE;
    double ent = im_entropy(p, MIN(len, 64));
    if (ent > 6.5 && len >= 32) {
        if (info) info->saw_protobuf = true;
        return IM_CONF_LOW;
    }
    return IM_CONF_NONE;
}

/* ============================================================
 * Facebook Messenger (MQTT)
 * ============================================================ */
ImConf im_detect_messenger(const uint8_t *p, int len, uint8_t proto,
                              MqttImFlowInfo *info) {
    if (len < 2) return IM_CONF_NONE;
    uint8_t fh = p[0];
    uint8_t ptype = (fh >> 4) & 0x0F;
    if (ptype != 1) return IM_CONF_NONE; /* CONNECT only */

    uint32_t rem = 0;
    int mult = 1, ri = 1;
    while (ri < len && ri < 5) {
        rem += (p[ri] & 0x7F) * (uint32_t)mult;
        if (!(p[ri] & 0x80)) { ri++; break; }
        mult *= 128; ri++;
    }
    if (ri + 6 >= len) return IM_CONF_NONE;
    const uint8_t *vh = p + ri;
    int vrem = (int)rem;
    if (vrem < 6) return IM_CONF_NONE;

    uint16_t pname_len = u16be(vh);
    if (pname_len == 4 && memcmp(vh+2, "MQTT", 4) == 0) {
        if (info) {
            info->saw_connect = true;
            info->mqtt_version = vh[6];
        }
        (void)proto;
        return IM_CONF_MED;
    }
    return IM_CONF_NONE;
}

ImConf im_detect_wechat(const uint8_t *p, int len) {
    if (len < 16) return IM_CONF_NONE;
    /* mmtls: 高熵 + 固定头部长度模式（启发式） */
    if (im_is_tls(p, len)) return IM_CONF_NONE;
    double ent = im_entropy(p, MIN(len, 48));
    if (ent > 6.0 && len >= 24 && len <= 4096) return IM_CONF_LOW;
    return IM_CONF_NONE;
}

ImConf im_detect_line(const uint8_t *p, int len) {
    (void)p; (void)len;
    return IM_CONF_NONE; /* 主要靠 SNI */
}

ImConf im_detect_viber(const uint8_t *p, int len) {
    if (len < 4) return IM_CONF_NONE;
    /* Viber binary: 部分版本以 0x00 0x00 开头 + length */
    if (p[0]==0 && p[1]==0 && len >= 8) return IM_CONF_LOW;
    return IM_CONF_NONE;
}

/* ============================================================
 * XMPP
 * ============================================================ */
ImConf im_detect_xmpp(const uint8_t *p, int len, XmppFlowInfo *info) {
    if (len < 5) return IM_CONF_NONE;
    if (memcmp(p, "<?xml", 5) == 0 ||
        (len >= 8 && memcmp(p, "<stream:", 8) == 0) ||
        (len >= 8 && memcmp(p, "<stream ", 8) == 0) ||
        (len >= 14 && mem_icase(p, len, "jabber", 6))) {
        if (info) {
            const char *s = (const char*)p;
            const char *to = strstr(s, "to='");
            if (!to) to = strstr(s, "to=\"");
            if (to && info->stream_to[0]=='\0') {
                to += 4;
                const char *te = strchr(to, to[0]=='\"' ? '\"' : '\'');
                if (te) {
                    int cp = MIN((int)(te-to), 127);
                    memcpy(info->stream_to, to, (size_t)cp);
                    info->stream_to[cp] = '\0';
                }
            }
            if (strstr(s, "urn:ietf:params:xml:ns:xmpp"))
                snprintf(info->xmlns, sizeof info->xmlns, "xmpp");
        }
        return IM_CONF_HIGH;
    }
    if (mem_icase(p, len, "xmlns=\"jabber", 13))
        return IM_CONF_MED;
    return IM_CONF_NONE;
}

/* ============================================================
 * Discord (WebSocket Upgrade)
 * ============================================================ */
ImConf im_detect_discord(const uint8_t *p, int len, uint16_t dport) {
    if (!im_is_http(p, len)) return IM_CONF_NONE;
    if (mem_icase(p, len, "Upgrade: websocket", 18) ||
        mem_icase(p, len, "discord", 7)) {
        (void)dport;
        return IM_CONF_MED;
    }
    if (mem_icase(p, len, "gateway.discord", 15))
        return IM_CONF_HIGH;
    return IM_CONF_NONE;
}

/* HTTP header 提取 */
static bool http_header_value(const uint8_t *pay, int len,
                               const char *header_name,
                               char *val_out, int val_max) {
    int hname_len = (int)strlen(header_name);
    const uint8_t *p = pay;
    const uint8_t *end = pay + len;
    while (p < end) {
        const uint8_t *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;
        int line_len = (int)(line_end - p);
        if (line_len > hname_len + 1) {
            if (mem_icase(p, hname_len + 1, header_name, hname_len) == p &&
                p[hname_len] == ':') {
                const uint8_t *vs = p + hname_len + 1;
                while (vs < end && (*vs == ' ' || *vs == '\t')) vs++;
                const uint8_t *ve = vs;
                while (ve < end && *ve != '\r' && *ve != '\n') ve++;
                int cp = MIN((int)(ve - vs), val_max - 1);
                if (cp > 0) memcpy(val_out, vs, (size_t)cp);
                val_out[cp] = '\0';
                return true;
            }
        }
        p = line_end + 1;
    }
    return false;
}

/* ============================================================
 * 单包无状态检测
 * ============================================================ */
ImResult im_detect_packet(const uint8_t *payload, int len,
                           uint8_t ip_proto,
                           uint16_t sport, uint16_t dport) {
    ImResult r;
    memset(&r, 0, sizeof r);
    r.entropy = im_entropy(payload, MIN(len, 256));

    if (len <= 0) return r;

    MtprotoFlowInfo  mt;
    WhatsappFlowInfo wa;
    XmppFlowInfo     xm;
    MqttImFlowInfo   mq;
    memset(&mt, 0, sizeof mt);
    memset(&wa, 0, sizeof wa);
    memset(&xm, 0, sizeof xm);
    memset(&mq, 0, sizeof mq);

    ImConf c;

    c = im_detect_mtproto(payload, len, ip_proto, &mt);
    if (c >= IM_CONF_MED) {
        r.proto = IM_MTPROTO; r.confidence = c; r.transport = IM_TRANS_TCP;
        snprintf(r.detail, sizeof r.detail, "MTProto transport type=%u", mt.transport_type);
        return r;
    }

    c = im_detect_xmpp(payload, len, &xm);
    if (c >= IM_CONF_MED) {
        r.proto = IM_XMPP; r.confidence = c; r.transport = IM_TRANS_XMPP;
        snprintf(r.detail, sizeof r.detail, "XMPP stream to=%.64s", xm.stream_to);
        return r;
    }

    c = im_detect_whatsapp(payload, len, ip_proto, &wa);
    if (c >= IM_CONF_MED) {
        r.proto = IM_WHATSAPP; r.confidence = c;
        r.transport = wa.saw_noise ? IM_TRANS_TCP : IM_TRANS_TCP;
        snprintf(r.detail, sizeof r.detail, "WhatsApp funxmpp/noise token=0x%02x", wa.token_byte);
        return r;
    }

    c = im_detect_messenger(payload, len, ip_proto, &mq);
    if (c >= IM_CONF_MED) {
        r.proto = IM_FB_MESSENGER; r.confidence = c; r.transport = IM_TRANS_MQTT;
        snprintf(r.detail, sizeof r.detail, "MQTT CONNECT v%u", mq.mqtt_version);
        return r;
    }

    c = im_detect_discord(payload, len, dport);
    if (c >= IM_CONF_MED) {
        r.proto = IM_DISCORD; r.confidence = c; r.transport = IM_TRANS_WS;
        snprintf(r.detail, sizeof r.detail, "Discord WebSocket upgrade");
        return r;
    }

    if (im_is_tls(payload, len)) {
        char sni[128];
        if (im_tls_parse_sni(payload, len, sni, sizeof sni)) {
            ImProto sp; ImConf sc;
            if (im_detect_by_sni(sni, &sp, &sc) >= IM_CONF_MED) {
                r.proto = sp; r.confidence = sc; r.transport = IM_TRANS_TLS;
                snprintf(r.detail, sizeof r.detail, "TLS SNI=%.120s", sni);
                return r;
            }
        }
    }

    if (im_is_http(payload, len)) {
        char host[128], ua[128];
        if (http_header_value(payload, len, "Host", host, sizeof host)) {
            ImProto sp; ImConf sc;
            if (im_detect_by_sni(host, &sp, &sc) >= IM_CONF_MED) {
                r.proto = sp; r.confidence = sc; r.transport = IM_TRANS_TCP;
                snprintf(r.detail, sizeof r.detail, "HTTP Host=%.120s", host);
                return r;
            }
        }
        if (http_header_value(payload, len, "User-Agent", ua, sizeof ua)) {
            if (str_icase_contains(ua, "Telegram")) {
                r.proto = IM_TELEGRAM; r.confidence = IM_CONF_MED;
                r.transport = IM_TRANS_TCP;
                snprintf(r.detail, sizeof r.detail, "UA=%.120s", ua);
                return r;
            }
            if (str_icase_contains(ua, "WhatsApp")) {
                r.proto = IM_WHATSAPP; r.confidence = IM_CONF_MED;
                r.transport = IM_TRANS_TCP;
                snprintf(r.detail, sizeof r.detail, "UA=%.120s", ua);
                return r;
            }
        }
    }

    /* 端口启发 */
    uint16_t dp = dport, sp = sport;
    if (dp == IM_PORT_XMPP || sp == IM_PORT_XMPP ||
        dp == IM_PORT_WA_ALT1 || dp == IM_PORT_WA_ALT2) {
        if (r.entropy > IM_ENTROPY_THRESH) {
            r.proto = IM_GENERIC; r.confidence = IM_CONF_LOW;
            r.transport = (ip_proto == 17) ? IM_TRANS_UDP : IM_TRANS_TCP;
            snprintf(r.detail, sizeof r.detail, "IM port %u high-entropy", dp);
        }
    }

    (void)sp;
    return r;
}

/* ============================================================
 * 流级别检测
 * ============================================================ */
void im_flow_init(ImFlow *f, uint16_t sport, uint16_t dport, uint8_t ip_proto) {
    memset(f, 0, sizeof *f);
    f->src_port = sport;
    f->dst_port = dport;
    f->ip_proto = ip_proto;
}

void im_flow_set_server(ImFlow *f, uint32_t server_ip, uint16_t server_port) {
    if (!f || server_ip == 0) return;
    if (f->server_ip == 0) {
        f->server_ip = server_ip;
        f->server_port = server_port;
    }
}

static void im_flow_set_best(ImFlow *f, ImProto proto, ImConf conf,
                               ImTransport tr, const char *detail) {
    if (conf > f->confidence || (conf == f->confidence && proto != IM_UNKNOWN)) {
        f->proto = proto;
        f->confidence = conf;
        f->transport = tr;
        if (detail)
            snprintf(f->detail, sizeof f->detail, "%.255s", detail);
    }
}

void im_flow_update(ImFlow *f, const uint8_t *payload, int len,
                    bool is_fwd, double ts) {
    if (!f || len <= 0 || !payload) return;

    f->n_pkts++;
    if (is_fwd) f->n_fwd_pkts++; else f->n_bwd_pkts++;
    if (f->first_ts <= 0.0) f->first_ts = ts;
    f->last_ts = ts;

    double ent = im_entropy(payload, MIN(len, 256));
    f->entropy_sum += ent;
    f->entropy_cnt++;

    if (im_is_tls(payload, len)) {
        f->has_tls = true;
        char sni[128], alpn[32];
        if (im_tls_parse_sni(payload, len, sni, sizeof sni)) {
            f->tls.saw_client_hello = true;
            if (!f->tls.sni[0]) snprintf(f->tls.sni, sizeof f->tls.sni, "%s", sni);
            ImProto sp; ImConf sc;
            if (im_detect_by_sni(sni, &sp, &sc) >= IM_CONF_MED) {
                im_flow_set_best(f, sp, sc, IM_TRANS_TLS,
                                 f->detail[0] ? f->detail : sni);
                if (sp == IM_TELEGRAM || sp == IM_MTPROTO)
                    snprintf(f->mtproto.tls_sni, sizeof f->mtproto.tls_sni, "%s", sni);
                if (sp == IM_WHATSAPP)
                    snprintf(f->whatsapp.tls_sni, sizeof f->whatsapp.tls_sni, "%s", sni);
                if (sp == IM_SIGNAL)
                    snprintf(f->signal.tls_sni, sizeof f->signal.tls_sni, "%s", sni);
            }
        }
        if (im_tls_parse_alpn(payload, len, alpn, sizeof alpn) && !f->tls.alpn[0])
            snprintf(f->tls.alpn, sizeof f->tls.alpn, "%s", alpn);

        /* Telegram 伪装 TLS（MTProxy obfuscated2） */
        if (im_is_tls_client_hello(payload, len)) {
            ImConf tgc = im_detect_telegram_fake_tls(payload, len,
                f->server_ip, f->server_port, &f->mtproto);
            if (tgc >= IM_CONF_MED) {
                char detail[192];
                snprintf(detail, sizeof detail,
                         "Telegram fake-TLS SNI=%s ch_len=%u port=%u",
                         f->mtproto.tls_sni[0] ? f->mtproto.tls_sni : "?",
                         f->mtproto.fake_tls_len, f->server_port);
                im_flow_set_best(f, IM_TELEGRAM, tgc, IM_TRANS_TLS, detail);
            }
        }
    }

    if (im_is_http(payload, len)) {
        f->has_http = true;
        char host[128], ua[128];
        if (http_header_value(payload, len, "Host", host, sizeof host) && !f->http_host[0])
            snprintf(f->http_host, sizeof f->http_host, "%s", host);
        if (http_header_value(payload, len, "User-Agent", ua, sizeof ua) && !f->http_ua[0])
            snprintf(f->http_ua, sizeof f->http_ua, "%s", ua);
        if (mem_icase(payload, len, "Upgrade: websocket", 18) ||
            mem_icase(payload, len, "Sec-WebSocket", 13))
            f->has_websocket = true;
    }

    /* Telegram DC IP（无 SNI 时兜底） */
    if (f->server_ip && im_is_telegram_dc_ip(f->server_ip) &&
        f->confidence < IM_CONF_MED) {
        im_flow_set_best(f, IM_TELEGRAM, IM_CONF_MED, IM_TRANS_TCP,
                         "Telegram DC IP range");
    }

    /* MTProto（跳过已识别 TLS 的应用层密文） */
    if (!f->has_tls && !im_is_tls(payload, len)) {
        ImConf c = im_detect_mtproto(payload, len, f->ip_proto, &f->mtproto);
        if (c >= IM_CONF_HIGH) {
            im_flow_set_best(f, IM_MTPROTO, IM_CONF_HIGH, IM_TRANS_TCP,
                             "MTProto transport signature");
        }
    }

    /* XMPP */
    ImConf c = im_detect_xmpp(payload, len, &f->xmpp);
    if (c >= IM_CONF_HIGH)
        im_flow_set_best(f, IM_XMPP, IM_CONF_HIGH, IM_TRANS_XMPP, "XMPP stream");

    /* WhatsApp binary */
    c = im_detect_whatsapp(payload, len, f->ip_proto, &f->whatsapp);
    if (c >= IM_CONF_HIGH)
        im_flow_set_best(f, IM_WHATSAPP, IM_CONF_HIGH, IM_TRANS_TCP, "WhatsApp Noise/funXMPP");
    else if (c >= IM_CONF_MED)
        im_flow_set_best(f, IM_WHATSAPP, IM_CONF_MED, IM_TRANS_TCP, "WhatsApp binary frame");

    /* MQTT Messenger */
    c = im_detect_messenger(payload, len, f->ip_proto, &f->mqtt);
    if (c >= IM_CONF_MED) {
        im_flow_set_best(f, IM_FB_MESSENGER, IM_CONF_MED, IM_TRANS_MQTT, "MQTT CONNECT");
        if (f->tls.sni[0])
            snprintf(f->mqtt.tls_sni, sizeof f->mqtt.tls_sni, "%s", f->tls.sni);
    }

    /* Discord WS */
    c = im_detect_discord(payload, len, f->dst_port);
    if (c >= IM_CONF_MED)
        im_flow_set_best(f, IM_DISCORD, c, IM_TRANS_WS, "Discord WebSocket");

    /* HTTP Host / UA 补充 */
    if (f->http_host[0]) {
        ImProto sp; ImConf sc;
        if (im_detect_by_sni(f->http_host, &sp, &sc) >= IM_CONF_MED)
            im_flow_set_best(f, sp, sc, IM_TRANS_TCP, f->http_host);
    }
    if (f->http_ua[0]) {
        if (str_icase_contains(f->http_ua, "Telegram"))
            im_flow_set_best(f, IM_TELEGRAM, IM_CONF_MED, IM_TRANS_TCP, f->http_ua);
        else if (str_icase_contains(f->http_ua, "WhatsApp"))
            im_flow_set_best(f, IM_WHATSAPP, IM_CONF_MED, IM_TRANS_TCP, f->http_ua);
        else if (str_icase_contains(f->http_ua, "Discord"))
            im_flow_set_best(f, IM_DISCORD, IM_CONF_MED, IM_TRANS_WSS, f->http_ua);
    }

    /* TLS SNI 二次确认 Telegram */
    if (f->tls.sni[0]) {
        ImProto sp; ImConf sc;
        if (im_detect_by_sni(f->tls.sni, &sp, &sc) >= IM_CONF_MED)
            im_flow_set_best(f, sp, sc, IM_TRANS_TLS, f->tls.sni);
    }

    /* MTProto + Telegram SNI 组合 → HIGH Telegram */
    if ((f->mtproto.saw_abridged || f->mtproto.saw_intermediate ||
         f->mtproto.saw_padded) &&
        (str_icase_contains(f->tls.sni, "telegram") ||
         str_icase_contains(f->mtproto.tls_sni, "telegram"))) {
        im_flow_set_best(f, IM_TELEGRAM, IM_CONF_HIGH, IM_TRANS_TLS,
                         "MTProto + Telegram SNI");
    }

    /* 流级：WhatsApp SNI + 高熵 */
    if (f->whatsapp.tls_sni[0] && f->entropy_cnt > 0) {
        im_flow_set_best(f, IM_WHATSAPP, IM_CONF_HIGH, IM_TRANS_TLS, f->whatsapp.tls_sni);
    }

    /* Signal SNI */
    if (f->signal.tls_sni[0])
        im_flow_set_best(f, IM_SIGNAL, IM_CONF_HIGH, IM_TRANS_TLS, f->signal.tls_sni);

    /* WeChat 启发（SNI 已覆盖；无 SNI 时 mmtls 熵） */
    if (f->proto == IM_UNKNOWN && f->has_tls && !f->tls.sni[0]) {
        c = im_detect_wechat(payload, len);
        if (c >= IM_CONF_LOW && (f->dst_port == 443 || f->src_port == 443))
            im_flow_set_best(f, IM_WECHAT, IM_CONF_LOW, IM_TRANS_TLS, "possible mmtls");
    }

    /* Viber */
    c = im_detect_viber(payload, len);
    if (c >= IM_CONF_LOW && str_icase_contains(f->tls.sni, "viber"))
        im_flow_set_best(f, IM_VIBER, IM_CONF_HIGH, IM_TRANS_TLS, f->tls.sni);

    /* 单包结果兜底 */
    if (f->proto == IM_UNKNOWN) {
        ImResult pr = im_detect_packet(payload, len, f->ip_proto, f->src_port, f->dst_port);
        if (pr.proto != IM_UNKNOWN)
            im_flow_set_best(f, pr.proto, pr.confidence, pr.transport, pr.detail);
    }
}

void im_flow_result(const ImFlow *f, ImResult *r) {
    memset(r, 0, sizeof *r);
    if (!f) return;
    r->proto = f->proto;
    r->confidence = f->confidence;
    r->transport = f->transport;
    r->entropy = f->entropy_cnt > 0 ? f->entropy_sum / f->entropy_cnt : 0.0;
    snprintf(r->detail, sizeof r->detail, "%.191s", f->detail);
}

void im_flow_emit(const ImFlow *f, FILE *fp) {
    if (!f || !fp || f->proto == IM_UNKNOWN) return;

    fprintf(fp, "=== IM Flow Detected ===\n");
    fprintf(fp, "  Protocol     : %s\n", im_proto_name(f->proto));
    fprintf(fp, "  Confidence   : %s\n", im_conf_name(f->confidence));
    fprintf(fp, "  Transport    : %s\n", im_transport_name(f->transport));
    fprintf(fp, "  L4           : %s  ports %u → %u\n",
            f->ip_proto == 6 ? "TCP" : "UDP", f->src_port, f->dst_port);
    fprintf(fp, "  Packets      : %u (fwd=%u bwd=%u)\n",
            f->n_pkts, f->n_fwd_pkts, f->n_bwd_pkts);
    fprintf(fp, "  Duration     : %.3f s\n", f->last_ts - f->first_ts);
    if (f->detail[0])
        fprintf(fp, "  Detail       : %s\n", f->detail);

    if (f->tls.sni[0])
        fprintf(fp, "  TLS.SNI      : %s\n", f->tls.sni);
    if (f->tls.alpn[0])
        fprintf(fp, "  TLS.ALPN     : %s\n", f->tls.alpn);
    if (f->http_host[0])
        fprintf(fp, "  HTTP.Host    : %s\n", f->http_host);
    if (f->http_ua[0])
        fprintf(fp, "  HTTP.UA      : %.120s\n", f->http_ua);
    if (f->has_websocket)
        fprintf(fp, "  WebSocket    : yes\n");

    switch (f->proto) {
    case IM_MTPROTO:
    case IM_TELEGRAM:
        fprintf(fp, "  [MTProto/TG] abridged=%d intermediate=%d padded=%d obfuscated=%d\n",
                f->mtproto.saw_abridged, f->mtproto.saw_intermediate,
                f->mtproto.saw_padded, f->mtproto.saw_obfuscated);
        fprintf(fp, "  [MTProto/TG] fake_tls=%d ch_len=%u type=%u\n",
                f->mtproto.saw_fake_tls,
                f->mtproto.fake_tls_len, f->mtproto.transport_type);
        if (f->mtproto.tls_sni[0])
            fprintf(fp, "  [MTProto/TG] tls_sni=%s\n", f->mtproto.tls_sni);
        if (f->server_ip)
            fprintf(fp, "  [MTProto/TG] server=%u.%u.%u.%u:%u dc_ip=%d\n",
                    (f->server_ip>>24)&0xff,(f->server_ip>>16)&0xff,
                    (f->server_ip>>8)&0xff,f->server_ip&0xff,
                    f->server_port, im_is_telegram_dc_ip(f->server_ip));
        break;
    case IM_WHATSAPP:
        fprintf(fp, "  [WhatsApp] funxmpp=%d noise=%d token=0x%02x\n",
                f->whatsapp.saw_funxmpp, f->whatsapp.saw_noise, f->whatsapp.token_byte);
        break;
    case IM_XMPP:
        fprintf(fp, "  [XMPP] to=%s xmlns=%s\n", f->xmpp.stream_to, f->xmpp.xmlns);
        break;
    case IM_FB_MESSENGER:
        fprintf(fp, "  [Messenger] mqtt_connect=%d version=%u\n",
                f->mqtt.saw_connect, f->mqtt.mqtt_version);
        break;
    default:
        break;
    }
    fprintf(fp, "\n");
}
