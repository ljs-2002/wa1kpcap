/**
 * quic_flow.h  ——  QUIC 协议检测与字段提取（Header-Only）
 *
 * 标准：RFC 9000 (QUIC v1)、RFC 9369 (QUIC v2)、常见 draft 版本
 * 传输层：UDP（典型端口 443/80，但任意端口均可）
 *
 * 不依赖解密，基于明文可见字段（Long Header）提取：
 *   版本号（v1/v2/draft-xx/Version-Negotiation）
 *   包类型（Initial / 0-RTT / Handshake / Retry / Short-Header）
 *   Destination Connection ID 和 Source Connection ID（长度+前20字节）
 *   Token（Initial 包中的地址验证 token）
 *   Retry Integrity Tag（16 字节）
 *   Version Negotiation 包中的支持版本列表
 *   Short Header 特征（固定位、spin 位、key phase）
 *   每流包统计（按类型）
 *   QUIC varint 解码工具函数
 *
 * 注：CRYPTO frame 内的 TLS ClientHello/ServerHello（含 SNI、ALPN、
 *     quic_transport_parameters 扩展）需要 QUIC Initial 层的 AEAD 解密，
 *     实现复杂度较高，本 header 预留字段但不解密；如需解密请参考
 *     RFC 9001 §5 并使用 OpenSSL EVP_AEAD_CTX。
 */
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>

// ============================================================
// QUIC 版本号
// ============================================================
static constexpr uint32_t QUIC_VERSION_1         = 0x00000001U;
static constexpr uint32_t QUIC_VERSION_2         = 0x6b3343cfU; // RFC 9369
static constexpr uint32_t QUIC_VERSION_NEGOT     = 0x00000000U; // Version Negotiation
static constexpr uint32_t QUIC_VERSION_DRAFT_BASE= 0xff000000U; // draft-xx base
// Draft versions: 0xff000001 (draft-01) ... 0xff00001d (draft-29)
// FB experimental: 0xfaceb001, 0xfaceb002, ...
static constexpr uint32_t QUIC_VERSION_FB_EXP    = 0xfaceb001U;

static inline bool quic_is_draft(uint32_t v) {
    return (v & 0xff000000U) == 0xff000000U && v != QUIC_VERSION_NEGOT;
}
static inline bool quic_is_known(uint32_t v) {
    return v == QUIC_VERSION_1 || v == QUIC_VERSION_2 || quic_is_draft(v)
        || (v >> 16) == 0xfaceU;  // FB MVFST (0xfaceb001, 0xfaceb002, ...)
}

static inline const char* quic_version_name(uint32_t v) {
    if (v == QUIC_VERSION_NEGOT)  return "Version-Negotiation";
    if (v == QUIC_VERSION_1)      return "QUIC-v1(RFC9000)";
    if (v == QUIC_VERSION_2)      return "QUIC-v2(RFC9369)";
    if (quic_is_draft(v)) {
        static char buf[24];
        snprintf(buf, sizeof buf, "draft-%02u", (unsigned)(v & 0xFF));
        return buf;
    }
    if ((v >> 16) == 0xfaceU) return "FB-MVFST";
    static char buf[16];
    snprintf(buf, sizeof buf, "0x%08x", v);
    return buf;
}

// ============================================================
// Long Header 包类型（QUIC v1）
// ============================================================
static constexpr uint8_t QUIC_LONG_INITIAL   = 0x00; // bits[5:4] = 00
static constexpr uint8_t QUIC_LONG_0RTT      = 0x01; // bits[5:4] = 01
static constexpr uint8_t QUIC_LONG_HANDSHAKE = 0x02; // bits[5:4] = 10
static constexpr uint8_t QUIC_LONG_RETRY     = 0x03; // bits[5:4] = 11

static inline const char* quic_pkt_type_name(uint8_t t, bool is_long) {
    if (!is_long) return "1-RTT(Short)";
    switch (t & 0x03) {
    case QUIC_LONG_INITIAL:   return "Initial";
    case QUIC_LONG_0RTT:      return "0-RTT";
    case QUIC_LONG_HANDSHAKE: return "Handshake";
    case QUIC_LONG_RETRY:     return "Retry";
    default:                  return "Unknown";
    }
}

// ============================================================
// QUIC Frame 类型（部分，用于 CRYPTO frame 识别）
// ============================================================
static constexpr uint8_t QUIC_FRAME_PADDING  = 0x00;
static constexpr uint8_t QUIC_FRAME_PING     = 0x01;
static constexpr uint8_t QUIC_FRAME_ACK      = 0x02;
static constexpr uint8_t QUIC_FRAME_CRYPTO   = 0x06;
static constexpr uint8_t QUIC_FRAME_STREAM   = 0x08; // 0x08..0x0F

// ============================================================
// QUIC 可变长度整数（varint）解码
// ============================================================
// 返回值，*consumed 设为消耗字节数（0 表示解码失败）
static inline uint64_t quic_varint(const uint8_t* p, const uint8_t* end,
                                    int* consumed) noexcept {
    if (p >= end) { *consumed = 0; return 0; }
    uint8_t first = *p;
    int bytes = 1 << ((first >> 6) & 3); // 1, 2, 4, 8
    if (p + bytes > end) { *consumed = 0; return 0; }
    *consumed = bytes;
    uint64_t val = (uint64_t)(first & 0x3F);
    for (int i = 1; i < bytes; i++)
        val = (val << 8) | p[i];
    return val;
}

// ============================================================
// QUIC Transport Parameter IDs（RFC 9000 §18.2）
// ============================================================
static inline const char* quic_tp_name(uint64_t id) {
    switch (id) {
    case 0x00: return "original_destination_connection_id";
    case 0x01: return "max_idle_timeout";
    case 0x02: return "stateless_reset_token";
    case 0x03: return "max_udp_payload_size";
    case 0x04: return "initial_max_data";
    case 0x05: return "initial_max_stream_data_bidi_local";
    case 0x06: return "initial_max_stream_data_bidi_remote";
    case 0x07: return "initial_max_stream_data_uni";
    case 0x08: return "initial_max_streams_bidi";
    case 0x09: return "initial_max_streams_uni";
    case 0x0a: return "ack_delay_exponent";
    case 0x0b: return "max_ack_delay";
    case 0x0c: return "disable_active_migration";
    case 0x0d: return "preferred_address";
    case 0x0e: return "active_connection_id_limit";
    case 0x0f: return "initial_source_connection_id";
    case 0x10: return "retry_source_connection_id";
    case 0x20: return "max_datagram_frame_size";   // RFC 9221
    case 0x3127: return "google_quic_version_info";
    case 0x4752: return "google_connection_options";
    case 0xff73db: return "version_information";   // RFC 9368
    default:   return nullptr;
    }
}

// ============================================================
// QUIC Transport Parameter（从 TLS extension 中提取，无需解密
// 当使用 quic_transport_parameters TLS extension time=0x39 时可见）
// ============================================================
struct QuicTransportParam {
    uint64_t id;
    uint64_t value;   // 数值型参数的值（其他类型为0）
    uint8_t  raw[20]; // 原始 value 字节（前20字节）
    uint8_t  raw_len;
};

// ============================================================
// QUIC 流特征记录
// ============================================================
struct QuicFlowRecord {
    bool     is_quic;

    // ---- 版本信息 ----
    uint32_t version;           // 首包观察到的版本号
    bool     is_v1, is_v2;

    // ---- 连接 ID ----
    uint8_t  first_dcid[20];    // 首包目标连接ID（原始字节）
    uint8_t  first_dcid_len;
    uint8_t  first_scid[20];    // 首包源连接ID（仅Long Header有）
    uint8_t  first_scid_len;
    bool     has_scid;

    // ---- 包类型已见标记 ----
    bool     seen_initial;
    bool     seen_0rtt;
    bool     seen_handshake;
    bool     seen_retry;
    bool     seen_version_neg;
    bool     seen_short;

    // ---- 包计数（按类型）----
    uint32_t n_initial, n_0rtt, n_handshake, n_retry, n_short, n_total;

    // ---- Version Negotiation 支持版本列表 ----
    uint32_t sup_versions[16];
    int      n_sup_versions;

    // ---- Retry Token（地址验证令牌）----
    uint8_t  retry_token[64];   // 首个 Retry 包中的 token
    uint8_t  retry_token_len;
    uint8_t  retry_integrity[16]; // Retry Integrity Tag（16字节）
    bool     has_retry;

    // ---- Initial Token（Client Initial 的地址验证 token）----
    uint8_t  initial_token[64];
    uint8_t  initial_token_len;
    bool     has_initial_token;

    // ---- Transport Parameters（如未加密可见时提取）----
    QuicTransportParam tparams[24];
    int                n_tparams;

    // ---- 时间戳 ----
    double   first_ts, last_ts;

    void init() noexcept {
        memset(this, 0, sizeof(*this));
    }

    // 解析 transport parameters 字节流（TLS extension value）
    void parse_transport_params(const uint8_t* p, int len) {
        const uint8_t* end = p + len;
        while (p < end && n_tparams < 24) {
            int c1, c2;
            uint64_t id  = quic_varint(p, end, &c1); if (!c1) break; p += c1;
            uint64_t vlen= quic_varint(p, end, &c2); if (!c2) break; p += c2;
            if (p + vlen > end) break;

            QuicTransportParam& tp = tparams[n_tparams++];
            tp.id  = id;
            tp.raw_len = (vlen < 20) ? (uint8_t)vlen : 20;
            memcpy(tp.raw, p, tp.raw_len);

            // 解码数值型参数
            int cv;
            tp.value = (vlen > 0) ? quic_varint(p, p + (int)vlen, &cv) : 0;

            p += vlen;
        }
    }

    // 处理单个 QUIC UDP payload
    void process_pkt(const uint8_t* pay, int len, bool /*is_fwd*/, double ts) {
        if (len < 6) return;
        if (first_ts == 0.0) first_ts = ts;
        last_ts = ts;
        n_total++;

        uint8_t first_byte = pay[0];
        bool is_long = (first_byte & 0x80) != 0;

        if (!is_long) {
            // ---- Short Header ----
            // Must have Fixed Bit = 1 (bit 6)
            if (!(first_byte & 0x40)) return;
            if (!is_quic && n_total == 1) return; // 首包不确认是 Short Header
            is_quic = true;
            seen_short = true;
            n_short++;
            return;
        }

        // ---- Long Header ----
        // Fixed Bit（bit 6）必须为 1
        if (!(first_byte & 0x40)) return;

        if (len < 7) return;
        uint32_t ver = (uint32_t)((pay[1]<<24)|(pay[2]<<16)|(pay[3]<<8)|pay[4]);

        // Version Negotiation (version=0)
        if (ver == QUIC_VERSION_NEGOT) {
            is_quic        = true;
            seen_version_neg = true;
            // DCID len
            if (len < 6) return;
            uint8_t dcid_len = pay[5]; if (5+1+dcid_len >= len) return;
            uint8_t scid_len = pay[6+dcid_len]; if (7+dcid_len+scid_len > len) return;
            // Supported versions
            const uint8_t* vp  = pay + 7 + dcid_len + scid_len;
            const uint8_t* end = pay + len;
            while (vp + 4 <= end && n_sup_versions < 16) {
                sup_versions[n_sup_versions++] = (uint32_t)((vp[0]<<24)|(vp[1]<<16)|(vp[2]<<8)|vp[3]);
                vp += 4;
            }
            return;
        }

        // 检查版本是否合理
        if (!quic_is_known(ver)) return;

        is_quic = true;
        if (!version) {
            version = ver;
            is_v1   = (ver == QUIC_VERSION_1);
            is_v2   = (ver == QUIC_VERSION_2);
        }

        // DCID
        if (len < 6) return;
        uint8_t dcid_len = pay[5];
        if (dcid_len > 20 || 6 + dcid_len >= len) return;
        const uint8_t* dcid_ptr = pay + 6;
        if (!first_dcid_len) {
            first_dcid_len = dcid_len;
            memcpy(first_dcid, dcid_ptr, dcid_len);
        }

        // SCID
        const uint8_t* p = dcid_ptr + dcid_len;
        if (p >= pay + len) return;
        uint8_t scid_len = *p++; // 1 byte
        if (scid_len > 20 || p + scid_len > pay + len) return;
        if (!has_scid && scid_len > 0) {
            first_scid_len = scid_len;
            memcpy(first_scid, p, scid_len);
            has_scid = true;
        }
        p += scid_len;

        uint8_t pkt_type = (first_byte >> 4) & 0x03;

        if (pkt_type == QUIC_LONG_RETRY) {
            seen_retry = true; n_retry++;
            if (!has_retry) {
                // Retry Token = bytes until last 16 (integrity tag)
                int remaining = (int)(pay + len - p) - 16;
                if (remaining > 0) {
                    retry_token_len = (remaining < 64) ? (uint8_t)remaining : 64;
                    memcpy(retry_token, p, retry_token_len);
                }
                // Last 16 bytes = integrity tag
                if (len >= 16)
                    memcpy(retry_integrity, pay + len - 16, 16);
                has_retry = true;
            }
            return;
        }

        if (pkt_type == QUIC_LONG_INITIAL) {
            seen_initial = true; n_initial++;
            // Token (varint length + bytes)
            if (p < pay + len && !has_initial_token) {
                int c;
                uint64_t tok_len = quic_varint(p, pay + len, &c);
                if (c > 0 && tok_len > 0) {
                    p += c;
                    if (p + tok_len <= pay + len) {
                        initial_token_len = (tok_len < 64) ? (uint8_t)tok_len : 64;
                        memcpy(initial_token, p, initial_token_len);
                        has_initial_token = true;
                    }
                }
            }
            return;
        }
        if (pkt_type == QUIC_LONG_0RTT)      { seen_0rtt      = true; n_0rtt++;      }
        if (pkt_type == QUIC_LONG_HANDSHAKE)  { seen_handshake = true; n_handshake++; }
    }

    static void bytes_to_hex(const uint8_t* b, int n, char* out, int out_len) {
        int pos = 0;
        for (int i = 0; i < n && pos + 2 < out_len; i++)
            pos += snprintf(out + pos, out_len - pos, "%02x", b[i]);
    }

    void emit_log(FILE* f) const {
        if (!is_quic) { fprintf(f, "[QUIC] 非 QUIC 流\n"); return; }
        fprintf(f, "=== QUIC FLOW ===\n");
        fprintf(f, "  Version: %s (0x%08x)\n", quic_version_name(version), version);
        fprintf(f, "  Packets: total=%u  Initial=%u  0-RTT=%u  Handshake=%u"
                   "  Retry=%u  Short=%u  VerNeg=%d\n",
                n_total, n_initial, n_0rtt, n_handshake, n_retry, n_short, seen_version_neg);

        if (first_dcid_len > 0) {
            char hex[48] = {}; bytes_to_hex(first_dcid, first_dcid_len, hex, sizeof hex);
            fprintf(f, "  DCID (%u bytes): %s\n", first_dcid_len, hex);
        }
        if (has_scid && first_scid_len > 0) {
            char hex[48] = {}; bytes_to_hex(first_scid, first_scid_len, hex, sizeof hex);
            fprintf(f, "  SCID (%u bytes): %s\n", first_scid_len, hex);
        }

        if (has_initial_token && initial_token_len > 0) {
            char hex[132] = {}; bytes_to_hex(initial_token, initial_token_len, hex, sizeof hex);
            fprintf(f, "  Initial Token (%u bytes): %s\n", initial_token_len, hex);
        }
        if (has_retry) {
            char hex[132] = {}; bytes_to_hex(retry_token, retry_token_len, hex, sizeof hex);
            fprintf(f, "  Retry Token (%u bytes): %s\n", retry_token_len, hex);
            char itag[40] = {}; bytes_to_hex(retry_integrity, 16, itag, sizeof itag);
            fprintf(f, "  Retry Integrity Tag: %s\n", itag);
        }

        if (seen_version_neg && n_sup_versions > 0) {
            fprintf(f, "  Version Negotiation — Supported (%d):", n_sup_versions);
            for (int i = 0; i < n_sup_versions; i++)
                fprintf(f, " %s", quic_version_name(sup_versions[i]));
            fprintf(f, "\n");
        }

        if (n_tparams > 0) {
            fprintf(f, "  Transport Parameters (%d):\n", n_tparams);
            for (int i = 0; i < n_tparams; i++) {
                const QuicTransportParam& tp = tparams[i];
                const char* name = quic_tp_name(tp.id);
                if (name)
                    fprintf(f, "    %-48s = %llu\n", name, (unsigned long long)tp.value);
                else
                    fprintf(f, "    tp_0x%04llx                                        = %llu\n",
                            (unsigned long long)tp.id, (unsigned long long)tp.value);
            }
        }
        fprintf(f, "  Flow time: %.6f — %.6f  (%.3f ms)\n",
                first_ts, last_ts, (last_ts - first_ts) * 1000.0);
        fprintf(f, "---\n");
    }
};

// ============================================================
// 快速检测：UDP payload 是否可能是 QUIC
// ============================================================
static inline bool detect_quic(const uint8_t* pay, int len) {
    if (len < 6) return false;
    uint8_t b0 = pay[0];
    // Fixed bit (bit 6) must be 1 for both Long and Short
    if (!(b0 & 0x40)) return false;
    if (b0 & 0x80) {
        // Long header: check version
        uint32_t ver = (uint32_t)((pay[1]<<24)|(pay[2]<<16)|(pay[3]<<8)|pay[4]);
        return quic_is_known(ver) || ver == QUIC_VERSION_NEGOT;
    }
    // Short header: Fixed bit = 1 is necessary but not sufficient without connection context
    return true; // optimistic
}
