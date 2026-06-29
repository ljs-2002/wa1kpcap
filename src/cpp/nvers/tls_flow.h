/**
 * tls_flow.h  ——  TLS 流字段信息结构体（Header-Only）
 *
 * 覆盖字段：
 *   版本（记录层 + 握手层 + Supported Versions 扩展）
 *   密码套件（客户端报价列表 + 服务端选定值）
 *   握手消息序列（ClientHello/ServerHello/Certificate/SKE/CKE/…）
 *   X.509 证书（Subject/Issuer/Serial/Validity/SAN/指纹/签名算法/公钥）
 *   TLS 扩展（SNI、ALPN、Heartbeat、ECH、ESNI、Session Ticket、
 *             Extended Master Secret、Early Data、OCSP Stapling、SCT、
 *             Supported Groups、Signature Algorithms、Key Share、PSK 等）
 *   JA3 / JA3S 指纹原始串
 *   密钥交换（ECDHE/DHE 曲线、公钥长度）
 *   流量统计（各类型 Record 计数、字节数）
 *   TCP 保活（零载荷 ACK 计数）
 *
 * 依赖：仅 C++ 标准库 + arpa/inet.h
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ostream>
#include <arpa/inet.h>

#include "json_log.h"

// ============================================================
// TLS 常量
// ============================================================

// Content Type (Record Layer)
static constexpr uint8_t TLS_CT_CHANGE_CIPHER_SPEC = 20;
static constexpr uint8_t TLS_CT_ALERT              = 21;
static constexpr uint8_t TLS_CT_HANDSHAKE          = 22;
static constexpr uint8_t TLS_CT_APP_DATA           = 23;
static constexpr uint8_t TLS_CT_HEARTBEAT          = 24;

// Handshake Type
static constexpr uint8_t TLS_HS_CLIENT_HELLO        = 1;
static constexpr uint8_t TLS_HS_SERVER_HELLO        = 2;
static constexpr uint8_t TLS_HS_NEW_SESSION_TICKET  = 4;
static constexpr uint8_t TLS_HS_ENCRYPTED_EXT      = 8;
static constexpr uint8_t TLS_HS_CERTIFICATE        = 11;
static constexpr uint8_t TLS_HS_SERVER_KEY_EXCHANGE = 12;
static constexpr uint8_t TLS_HS_CERT_REQUEST       = 13;
static constexpr uint8_t TLS_HS_SERVER_HELLO_DONE  = 14;
static constexpr uint8_t TLS_HS_CERT_VERIFY        = 15;
static constexpr uint8_t TLS_HS_CLIENT_KEY_EXCHANGE = 16;
static constexpr uint8_t TLS_HS_FINISHED           = 20;

// Extension Type
static constexpr uint16_t TLS_EXT_SNI                = 0x0000;
static constexpr uint16_t TLS_EXT_MAX_FRAGMENT       = 0x0001;
static constexpr uint16_t TLS_EXT_STATUS_REQUEST     = 0x0005; // OCSP
static constexpr uint16_t TLS_EXT_SUPPORTED_GROUPS   = 0x000a;
static constexpr uint16_t TLS_EXT_EC_POINT_FORMATS   = 0x000b;
static constexpr uint16_t TLS_EXT_SIG_ALGOS          = 0x000d;
static constexpr uint16_t TLS_EXT_HEARTBEAT          = 0x000f;
static constexpr uint16_t TLS_EXT_ALPN               = 0x0010;
static constexpr uint16_t TLS_EXT_SCT                = 0x0012; // Signed Cert Timestamps
static constexpr uint16_t TLS_EXT_ENCRYPT_THEN_MAC   = 0x0016;
static constexpr uint16_t TLS_EXT_EXTENDED_MASTER    = 0x0017;
static constexpr uint16_t TLS_EXT_SESSION_TICKET     = 0x0023;
static constexpr uint16_t TLS_EXT_EARLY_DATA         = 0x002a;
static constexpr uint16_t TLS_EXT_SUPPORTED_VERSIONS = 0x002b;
static constexpr uint16_t TLS_EXT_COOKIE             = 0x002c;
static constexpr uint16_t TLS_EXT_PSK_KE_MODES       = 0x002d;
static constexpr uint16_t TLS_EXT_KEY_SHARE          = 0x0033;
static constexpr uint16_t TLS_EXT_RENEGOTIATION_INFO = 0xff01;
static constexpr uint16_t TLS_EXT_ESNI              = 0xffce; // deprecated
static constexpr uint16_t TLS_EXT_ECH_OUTER         = 0xfe0d; // RFC 9180
static constexpr uint16_t TLS_EXT_ECH_DRAFT         = 0xff02;

// ============================================================
// GREASE 值检测（JA3 规范：排除 GREASE 占位符）
// ============================================================
inline bool tls_is_grease(uint16_t v) noexcept {
    return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

// ============================================================
// 名称映射
// ============================================================
inline const char* tls_version_name(uint16_t v) noexcept {
    switch (v) {
    case 0x0200: return "SSL 2.0";
    case 0x0300: return "SSL 3.0";
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    default:     return "Unknown";
    }
}

inline const char* tls_cipher_name(uint16_t c) noexcept {
    switch (c) {
    // TLS 1.3
    case 0x1301: return "TLS_AES_128_GCM_SHA256";
    case 0x1302: return "TLS_AES_256_GCM_SHA384";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    case 0x1304: return "TLS_AES_128_CCM_SHA256";
    case 0x1305: return "TLS_AES_128_CCM_8_SHA256";
    // RSA
    case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
    case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
    case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
    case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
    case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
    // ECDHE-RSA
    case 0xC013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
    case 0xC014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
    case 0xC027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    case 0xC028: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
    case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    // ECDHE-ECDSA
    case 0xC009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
    case 0xC00A: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
    case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    // DHE
    case 0x0033: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
    case 0x0039: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
    case 0x009E: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0x009F: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0xCCAA: return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    // Weak / Legacy
    case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5";
    case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA";
    case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
    case 0xC011: return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
    case 0xC012: return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
    case 0x00FF: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
    case 0x5600: return "TLS_FALLBACK_SCSV";
    default:     return nullptr;
    }
}

inline std::string tls_cipher_str(uint16_t c) {
    const char* n = tls_cipher_name(c);
    char buf[32]; snprintf(buf, sizeof(buf), "0x%04X", c);
    return n ? std::string(n) + " (" + buf + ")" : buf;
}

inline const char* tls_ext_name(uint16_t e) noexcept {
    switch (e) {
    case 0x0000: return "sni";
    case 0x0001: return "max_fragment_length";
    case 0x0005: return "status_request(OCSP)";
    case 0x000a: return "supported_groups";
    case 0x000b: return "ec_point_formats";
    case 0x000d: return "signature_algorithms";
    case 0x000f: return "heartbeat";
    case 0x0010: return "alpn";
    case 0x0012: return "sct";
    case 0x0016: return "encrypt_then_mac";
    case 0x0017: return "extended_master_secret";
    case 0x0023: return "session_ticket";
    case 0x002a: return "early_data";
    case 0x002b: return "supported_versions";
    case 0x002c: return "cookie";
    case 0x002d: return "psk_key_exchange_modes";
    case 0x0033: return "key_share";
    case 0xff01: return "renegotiation_info";
    case 0xffce: return "esni";
    case 0xfe0d: return "ech";
    case 0xff02: return "ech_draft";
    default:     return nullptr;
    }
}

inline std::string tls_ext_str(uint16_t e) {
    const char* n = tls_ext_name(e);
    if (n) return n;
    char buf[12]; snprintf(buf, sizeof(buf), "ext_0x%04x", e);
    return buf;
}

inline const char* tls_group_name(uint16_t g) noexcept {
    switch (g) {
    case 0x0017: return "secp256r1(P-256)";
    case 0x0018: return "secp384r1(P-384)";
    case 0x0019: return "secp521r1(P-521)";
    case 0x001d: return "x25519";
    case 0x001e: return "x448";
    case 0x0100: return "ffdhe2048";
    case 0x0101: return "ffdhe3072";
    default:     return nullptr;
    }
}

// ============================================================
// X.509 证书信息
// ============================================================
struct CertInfo {
    std::string subject_cn, subject_c, subject_st, subject_l, subject_o;
    std::string issuer_cn,  issuer_c,  issuer_st,  issuer_l,  issuer_o;
    std::string serial_hex;
    std::string not_before, not_after;
    std::string sig_alg;
    std::string pub_key_alg;
    int         pub_key_bits = 0;
    std::vector<std::string> sans;
    std::string sha1_fingerprint; // 证书 DER 的 SHA-1 指纹
    int         version = 1;      // X.509 版本（1/2/3）
    bool        is_ca   = false;  // BasicConstraints CA:TRUE
};

// ============================================================
// TLS 流完整信息
// ============================================================
struct TLSFlowInfo {
    // --- 流标识 ---
    char   flow_id[96] = {};
    char   src_ip[INET_ADDRSTRLEN] = {};
    char   dst_ip[INET_ADDRSTRLEN] = {};
    uint16_t src_port = 0, dst_port = 0;
    uint8_t  proto    = 0;
    double   first_ts = 0.0, last_ts = 0.0;

    // --- TLS 版本 ---
    uint16_t record_version    = 0; // 记录层版本（首次见到）
    uint16_t handshake_version = 0; // ClientHello/ServerHello 握手版本
    uint16_t negotiated_version= 0; // supported_versions 扩展中协商的版本

    // --- 握手状态 ---
    bool has_client_hello      = false;
    bool has_server_hello      = false;
    bool has_certificate       = false;
    bool has_server_key_exch   = false;
    bool has_server_hello_done = false;
    bool has_client_key_exch   = false;
    bool has_new_session_ticket= false;
    bool has_change_cipher_spec= false;
    bool has_finished          = false;
    bool handshake_complete    = false;

    // --- 密码套件 ---
    uint16_t              cipher_selected = 0;
    std::vector<uint16_t> ciphers_offered;   // ClientHello

    // --- Session ---
    std::string session_id_hex;
    uint8_t     compression_method = 0;
    bool        session_resumed    = false;

    // --- 扩展标志 ---
    bool has_sni            = false;
    bool has_alpn           = false;
    bool has_heartbeat      = false;
    bool has_ech            = false;
    bool has_esni           = false;
    bool has_session_ticket = false;
    bool has_ext_master_sec = false;
    bool has_early_data     = false;
    bool has_ocsp_stapling  = false;
    bool has_sct            = false;
    bool has_encrypt_then_mac = false;
    bool has_renegotiation_info = false;

    // --- SNI ---
    std::string sni;

    // --- ALPN ---
    std::string              alpn_selected;
    std::vector<std::string> alpn_offered;

    // --- Heartbeat ---
    uint8_t heartbeat_mode = 0; // 1=peer_allowed, 2=peer_not_allowed

    // --- ECH / ESNI ---
    std::string ech_raw_hex;   // ECH extension 原始数据（前16字节）

    // --- 扩展列表（JA3 使用） ---
    std::vector<uint16_t> extensions_seen;      // 所有 extensions（含两方向）
    std::vector<uint16_t> client_extensions;    // ClientHello 中的扩展
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t>  ec_point_formats;
    std::vector<uint16_t> supported_versions;
    std::vector<uint16_t> sig_algorithms;
    std::vector<uint16_t> key_share_groups;
    std::vector<uint8_t>  psk_ke_modes;

    // --- JA3 / JA3S ---
    std::string ja3_raw;  // 原始字符串（MD5 之前）
    std::string ja3;      // MD5 指纹
    std::string ja3s_raw;
    std::string ja3s;

    // --- 证书链 ---
    std::vector<CertInfo> certs;

    // --- 密钥交换 ---
    std::string ke_type;    // "ECDHE" / "DHE" / "RSA" / "ECDH"
    uint16_t    ke_curve  = 0;   // named curve
    int         ke_pubkey_bytes = 0;
    std::string ke_sig_alg;

    // --- 流量统计 ---
    uint32_t cnt_handshake  = 0;
    uint32_t cnt_app_data   = 0;
    uint32_t cnt_ccs        = 0;
    uint32_t cnt_alert      = 0;
    uint32_t cnt_heartbeat  = 0;
    uint64_t bytes_app_data = 0;
    uint64_t bytes_total    = 0;
    uint32_t pkt_total      = 0;

    // --- TCP 保活 ---
    uint32_t tcp_keepalive_cnt = 0; // 零载荷 ACK 包计数

    // --- Alert 信息 ---
    uint8_t alert_level = 0, alert_desc = 0;
};

// ============================================================
// 工具：构建 JA3 / JA3S 原始字符串
// ============================================================
inline std::string build_ja3_raw(uint16_t version,
                                  const std::vector<uint16_t>& ciphers,
                                  const std::vector<uint16_t>& exts,
                                  const std::vector<uint16_t>& groups,
                                  const std::vector<uint8_t>&  ec_pts)
{
    auto join16 = [](const std::vector<uint16_t>& v, bool skip_grease) -> std::string {
        std::string s;
        for (auto x : v) {
            if (skip_grease && tls_is_grease(x)) continue;
            if (!s.empty()) s += '-';
            s += std::to_string(x);
        }
        return s;
    };
    auto join8 = [](const std::vector<uint8_t>& v) -> std::string {
        std::string s;
        for (auto x : v) { if (!s.empty()) s += '-'; s += std::to_string(x); }
        return s;
    };
    return std::to_string(version) + ',' +
           join16(ciphers, true)    + ',' +
           join16(exts, true)       + ',' +
           join16(groups, true)     + ',' +
           join8(ec_pts);
}

inline std::string build_ja3s_raw(uint16_t version,
                                   uint16_t cipher,
                                   const std::vector<uint16_t>& exts)
{
    std::string s = std::to_string(version) + ',' + std::to_string(cipher) + ',';
    bool first = true;
    for (auto e : exts) {
        if (tls_is_grease(e)) continue;
        if (!first) s += '-';
        s += std::to_string(e);
        first = false;
    }
    return s;
}

// ============================================================
// 工具：格式化十六进制字符串
// ============================================================
inline std::string bytes_to_hex(const uint8_t* p, size_t n, char sep = ':') {
    static const char H[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i && sep) s += sep;
        s += H[(p[i]>>4)&0xf];
        s += H[p[i]&0xf];
    }
    return s;
}

// ============================================================
// 输出 JSON Lines（每流一行，含 X509 / 密码套件 / 扩展等）
// ============================================================
inline void emit_tls_json(std::ostream& o, const TLSFlowInfo& f,
                          const char* pcap_file) {
    o << std::fixed << std::setprecision(6);
    o << "{\"file\":";
    json_esc_os(o, pcap_file);
    o << ",\"flow_id\":";
    json_esc_os(o, f.flow_id);
    o << ",";
    json_five_tuple_os(o, f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.proto);
    o << ",\"first_ts\":" << f.first_ts << ",\"last_ts\":" << f.last_ts;

    o << ",\"tls\":{";
    o << "\"record_version\":" << f.record_version
      << ",\"record_version_name\":";
    json_esc_os(o, f.record_version ? tls_version_name(f.record_version) : "");
    o << ",\"handshake_version\":" << f.handshake_version
      << ",\"handshake_version_name\":";
    json_esc_os(o, f.handshake_version ? tls_version_name(f.handshake_version) : "");
    o << ",\"negotiated_version\":" << f.negotiated_version
      << ",\"negotiated_version_name\":";
    json_esc_os(o, f.negotiated_version ? tls_version_name(f.negotiated_version) : "");

    o << ",\"handshake\":{"
      << "\"client_hello\":" << (f.has_client_hello ? "true" : "false")
      << ",\"server_hello\":" << (f.has_server_hello ? "true" : "false")
      << ",\"certificate\":" << (f.has_certificate ? "true" : "false")
      << ",\"server_key_exchange\":" << (f.has_server_key_exch ? "true" : "false")
      << ",\"server_hello_done\":" << (f.has_server_hello_done ? "true" : "false")
      << ",\"client_key_exchange\":" << (f.has_client_key_exch ? "true" : "false")
      << ",\"new_session_ticket\":" << (f.has_new_session_ticket ? "true" : "false")
      << ",\"change_cipher_spec\":" << (f.has_change_cipher_spec ? "true" : "false")
      << ",\"finished\":" << (f.has_finished ? "true" : "false")
      << ",\"complete\":" << (f.handshake_complete ? "true" : "false")
      << "}";

    o << ",\"cipher_selected\":";
    if (f.cipher_selected) {
        o << "{\"id\":" << f.cipher_selected << ",\"name\":";
        json_esc_os(o, tls_cipher_str(f.cipher_selected));
        o << "}";
    } else {
        o << "null";
    }

    o << ",\"ciphers_offered\":[";
    for (size_t i = 0; i < f.ciphers_offered.size(); i++) {
        if (i) o << ',';
        uint16_t c = f.ciphers_offered[i];
        o << "{\"id\":" << c << ",\"name\":";
        json_esc_os(o, tls_cipher_str(c));
        o << "}";
    }
    o << "]";

    o << ",\"session_id\":";
    json_esc_os(o, f.session_id_hex);
    o << ",\"session_resumed\":" << (f.session_resumed ? "true" : "false")
      << ",\"compression_method\":" << (unsigned)f.compression_method;

    o << ",\"sni\":";
    json_esc_os(o, f.sni);
    o << ",\"alpn_selected\":";
    json_esc_os(o, f.alpn_selected);
    o << ",\"alpn_offered\":[";
    for (size_t i = 0; i < f.alpn_offered.size(); i++) {
        if (i) o << ',';
        json_esc_os(o, f.alpn_offered[i]);
    }
    o << "]";

    o << ",\"ja3_raw\":";
    json_esc_os(o, f.ja3_raw);
    o << ",\"ja3\":";
    json_esc_os(o, f.ja3);
    o << ",\"ja3s_raw\":";
    json_esc_os(o, f.ja3s_raw);
    o << ",\"ja3s\":";
    json_esc_os(o, f.ja3s);

    o << ",\"extensions\":{"
      << "\"sni\":" << (f.has_sni ? "true" : "false")
      << ",\"alpn\":" << (f.has_alpn ? "true" : "false")
      << ",\"heartbeat\":" << (f.has_heartbeat ? "true" : "false")
      << ",\"heartbeat_mode\":" << (unsigned)f.heartbeat_mode
      << ",\"ech\":" << (f.has_ech ? "true" : "false")
      << ",\"esni\":" << (f.has_esni ? "true" : "false")
      << ",\"session_ticket\":" << (f.has_session_ticket ? "true" : "false")
      << ",\"extended_master_secret\":" << (f.has_ext_master_sec ? "true" : "false")
      << ",\"early_data\":" << (f.has_early_data ? "true" : "false")
      << ",\"ocsp_stapling\":" << (f.has_ocsp_stapling ? "true" : "false")
      << ",\"sct\":" << (f.has_sct ? "true" : "false")
      << ",\"encrypt_then_mac\":" << (f.has_encrypt_then_mac ? "true" : "false")
      << ",\"renegotiation_info\":" << (f.has_renegotiation_info ? "true" : "false")
      << ",\"ech_raw_prefix\":";
    json_esc_os(o, f.ech_raw_hex);
    o << ",\"client_ext_ids\":[";
    for (size_t i = 0; i < f.client_extensions.size(); i++) {
        if (i) o << ',';
        o << f.client_extensions[i];
    }
    o << "],\"ext_ids_seen\":[";
    for (size_t i = 0; i < f.extensions_seen.size(); i++) {
        if (i) o << ',';
        o << f.extensions_seen[i];
    }
    o << "],\"supported_groups\":[";
    for (size_t i = 0; i < f.supported_groups.size(); i++) {
        if (i) o << ',';
        uint16_t g = f.supported_groups[i];
        o << "{\"id\":" << g << ",\"name\":";
        const char* gn = tls_group_name(g);
        json_esc_os(o, gn ? gn : "");
        o << "}";
    }
    o << "],\"supported_versions\":[";
    for (size_t i = 0; i < f.supported_versions.size(); i++) {
        if (i) o << ',';
        uint16_t v = f.supported_versions[i];
        o << "{\"id\":" << v << ",\"name\":";
        json_esc_os(o, tls_version_name(v));
        o << "}";
    }
    o << "],\"signature_algorithms\":[";
    for (size_t i = 0; i < f.sig_algorithms.size(); i++) {
        if (i) o << ',';
        o << f.sig_algorithms[i];
    }
    o << "],\"ec_point_formats\":[";
    for (size_t i = 0; i < f.ec_point_formats.size(); i++) {
        if (i) o << ',';
        o << (unsigned)f.ec_point_formats[i];
    }
    o << "],\"key_share_groups\":[";
    for (size_t i = 0; i < f.key_share_groups.size(); i++) {
        if (i) o << ',';
        o << f.key_share_groups[i];
    }
    o << "],\"psk_ke_modes\":[";
    for (size_t i = 0; i < f.psk_ke_modes.size(); i++) {
        if (i) o << ',';
        o << (unsigned)f.psk_ke_modes[i];
    }
    o << "]}";

    o << ",\"key_exchange\":{"
      << "\"type\":";
    json_esc_os(o, f.ke_type);
    o << ",\"curve_id\":" << f.ke_curve << ",\"curve_name\":";
    const char* kgn = f.ke_curve ? tls_group_name(f.ke_curve) : nullptr;
    json_esc_os(o, kgn ? kgn : "");
    o << ",\"pubkey_bytes\":" << f.ke_pubkey_bytes << ",\"sig_alg\":";
    json_esc_os(o, f.ke_sig_alg);
    o << "}";

    o << ",\"certificates\":[";
    for (size_t i = 0; i < f.certs.size(); i++) {
        if (i) o << ',';
        const auto& c = f.certs[i];
        o << "{\"index\":" << i
          << ",\"subject_cn\":";
        json_esc_os(o, c.subject_cn);
        o << ",\"subject_o\":";
        json_esc_os(o, c.subject_o);
        o << ",\"subject_c\":";
        json_esc_os(o, c.subject_c);
        o << ",\"subject_st\":";
        json_esc_os(o, c.subject_st);
        o << ",\"subject_l\":";
        json_esc_os(o, c.subject_l);
        o << ",\"issuer_cn\":";
        json_esc_os(o, c.issuer_cn);
        o << ",\"issuer_o\":";
        json_esc_os(o, c.issuer_o);
        o << ",\"issuer_c\":";
        json_esc_os(o, c.issuer_c);
        o << ",\"serial\":";
        json_esc_os(o, c.serial_hex);
        o << ",\"not_before\":";
        json_esc_os(o, c.not_before);
        o << ",\"not_after\":";
        json_esc_os(o, c.not_after);
        o << ",\"sig_alg\":";
        json_esc_os(o, c.sig_alg);
        o << ",\"pub_key_alg\":";
        json_esc_os(o, c.pub_key_alg);
        o << ",\"pub_key_bits\":" << c.pub_key_bits
          << ",\"x509_version\":" << c.version
          << ",\"is_ca\":" << (c.is_ca ? "true" : "false")
          << ",\"sha1_fingerprint\":";
        json_esc_os(o, c.sha1_fingerprint);
        o << ",\"san\":[";
        for (size_t j = 0; j < c.sans.size(); j++) {
            if (j) o << ',';
            json_esc_os(o, c.sans[j]);
        }
        o << "]}";
    }
    o << "]";

    o << ",\"stats\":{"
      << "\"records_handshake\":" << f.cnt_handshake
      << ",\"records_app_data\":" << f.cnt_app_data
      << ",\"records_ccs\":" << f.cnt_ccs
      << ",\"records_alert\":" << f.cnt_alert
      << ",\"records_heartbeat\":" << f.cnt_heartbeat
      << ",\"bytes_app_data\":" << f.bytes_app_data
      << ",\"bytes_tls_total\":" << f.bytes_total
      << ",\"tls_payload_pkts\":" << f.pkt_total
      << ",\"tcp_keepalive_cnt\":" << f.tcp_keepalive_cnt
      << ",\"alert_level\":" << (unsigned)f.alert_level
      << ",\"alert_desc\":" << (unsigned)f.alert_desc
      << "}}}";

    o << "\n";
}
