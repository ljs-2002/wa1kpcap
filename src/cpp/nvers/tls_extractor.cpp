/**
 * tls_extractor.cpp  ——  TLS 流字段提取器
 *
 * 功能：
 *   - 逐包解析 TLS 记录层（无需重组 TCP 流：每个 TCP 段内可含多条 TLS 记录）
 *   - 解析 ClientHello / ServerHello / Certificate / ServerKeyExchange /
 *     ClientKeyExchange / NewSessionTicket / ChangeCipherSpec / Alert /
 *     Heartbeat 等握手消息
 *   - 全量提取 TLS 扩展：SNI、ALPN、Heartbeat、ECH、ESNI、Supported Groups、
 *     Supported Versions、Session Ticket、Extended Master Secret、
 *     Key Share、Signature Algorithms、Early Data、OCSP Status Request、
 *     SCT、Encrypt-then-MAC、Renegotiation Info、PSK Key Exchange Modes
 *   - 解析 X.509 DER 证书（Subject/Issuer/Serial/Validity/SAN/公钥信息）
 *   - 计算 JA3 / JA3S 指纹（MD5，GREASE 过滤）
 *   - 计算证书 SHA-1 指纹（使用 OpenSSL）
 *   - TCP 保活包检测（零载荷 ACK）
 *   - 高效流表（unordered_map，双向键查找）
 *   - 输出 JSON Lines（每行一条流的 JSON）
 *
 * 用法：
 *   ./tls_extractor -r <pcap>  [-w <log>]  [-p <port>]
 *   ./tls_extractor -i <iface> [-w <log>]  [-p <port>]
 *
 * 编译：
 *   g++ -O3 -std=c++17 tls_extractor.cpp -lpcap -lssl -lcrypto -o tls_extractor
 */

#include "tls_flow.h"

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <unordered_map>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <getopt.h>
#include <signal.h>

#include "nvers_api.h"

// ============================================================
// 流键（五元组）
// ============================================================
struct FlowKey {
    uint32_t sip = 0, dip = 0;
    uint16_t sp  = 0, dp  = 0;
    uint8_t  proto = 0;
    bool operator==(const FlowKey& o) const noexcept {
        return sip==o.sip && dip==o.dip && sp==o.sp && dp==o.dp && proto==o.proto;
    }
    FlowKey rev() const noexcept {
        FlowKey r; r.sip=dip; r.dip=sip; r.sp=dp; r.dp=sp; r.proto=proto;
        return r;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        auto h = [](uint64_t x) -> uint64_t {
            x ^= x>>33; x *= 0xff51afd7ed558ccdULL;
            x ^= x>>33; x *= 0xc4ceb9fe1a85ec53ULL;
            x ^= x >> 33; return x;
        };
        return (size_t)(h((uint64_t)k.sip|(uint64_t)k.dip<<32)
                      ^ h((uint64_t)k.sp|(uint64_t)k.dp<<16|(uint64_t)k.proto<<32));
    }
};

// ============================================================
// MD5 工具（JA3/JA3S）
// ============================================================
static std::string md5_hex(const std::string& s) {
    unsigned char d[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(s.data()), s.size(), d);
    return bytes_to_hex(d, MD5_DIGEST_LENGTH, 0);
}

static std::string sha1_hex(const uint8_t* data, size_t len) {
    unsigned char d[SHA_DIGEST_LENGTH];
    SHA1(data, len, d);
    return bytes_to_hex(d, SHA_DIGEST_LENGTH, ':');
}

// ============================================================
// 最小 ASN.1 DER 解析器（专为 X.509 证书）
// ============================================================
struct DER {
    const uint8_t* p;
    const uint8_t* e;

    DER(const uint8_t* data, size_t len) : p(data), e(data + len) {}

    bool eof()   const { return p >= e; }
    size_t left() const { return p < e ? (size_t)(e - p) : 0; }

    // 读取 tag + length，返回 content 指针（p 已跳过 content）
    bool tlv(uint8_t& tag, const uint8_t*& val, size_t& vlen) {
        if (eof()) return false;
        tag = *p++;
        if (eof()) return false;
        uint8_t lb = *p++;
        if (lb < 0x80) {
            vlen = lb;
        } else {
            int n = lb & 0x7f;
            if (n < 1 || n > 4 || (size_t)n > left()) return false;
            vlen = 0;
            while (n--) vlen = (vlen << 8) | *p++;
        }
        if (left() < vlen) return false;
        val = p; p += vlen;
        return true;
    }

    // 跳过一个元素
    bool skip() {
        uint8_t t; const uint8_t* v; size_t l;
        return tlv(t, v, l);
    }

    // 保存/恢复位置
    const uint8_t* mark() const { return p; }
    void  rewind(const uint8_t* m) { p = m; }

    // 读取某 tag 的内容（tag 不匹配则回退）
    bool expect(uint8_t etag, const uint8_t*& val, size_t& vlen) {
        const uint8_t* save = p;
        uint8_t t;
        if (!tlv(t, val, vlen)) { p = save; return false; }
        if (t != etag) { p = save; return false; }
        return true;
    }

    // 解析字符串（PrintableString/UTF8String/IA5String/BMPString/...）
    std::string read_string() {
        uint8_t t; const uint8_t* v; size_t l;
        if (!tlv(t, v, l)) return {};
        // BMPString (UTF-16BE) → ASCII 降级
        if (t == 0x1e) {
            std::string s;
            for (size_t i = 0; i + 1 < l; i += 2)
                s += (v[i] == 0 && v[i+1] < 0x80) ? (char)v[i+1] : '?';
            return s;
        }
        std::string s(reinterpret_cast<const char*>(v), l);
        for (auto& c : s) if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7e) c = '?';
        return s;
    }

    // 读取 UTCTime/GeneralizedTime → 可读字符串
    std::string read_time() {
        uint8_t t; const uint8_t* v; size_t l;
        if (!tlv(t, v, l)) return {};
        if (l < 12) return {};
        // UTCTime: YYMMDDHHMMSSZ (13), GeneralizedTime: YYYYMMDDHHMMSSZ (15)
        (void)0; // assume 20xx for UTCTime
        const char* s = reinterpret_cast<const char*>(v);
        if (t == 0x17) { // UTCTime
            char buf[24];
            snprintf(buf, sizeof(buf), "20%.2s-%.2s-%.2s %.2s:%.2s:%.2s UTC",
                     s, s+2, s+4, s+6, s+8, s+10);
            return buf;
        } else { // GeneralizedTime
            char buf[24];
            snprintf(buf, sizeof(buf), "%.4s-%.2s-%.2s %.2s:%.2s:%.2s UTC",
                     s, s+4, s+6, s+8, s+10, s+12);
            return buf;
        }
    }

    // 读取 OID → 返回 DER 内容作为 OID 字节
    bool read_oid_bytes(const uint8_t*& oid_data, size_t& oid_len) {
        const uint8_t* v; size_t l;
        return expect(0x06, v, l) ? (oid_data = v, oid_len = l, true) : false;
    }
};

// OID 比较辅助
static bool oid_eq(const uint8_t* a, size_t al, std::initializer_list<uint8_t> b) {
    if (al != b.size()) return false;
    return std::memcmp(a, b.begin(), al) == 0;
}

// OID → 名称
static const char* oid_to_sig_alg(const uint8_t* oid, size_t len) {
    static const struct { const uint8_t* oid; size_t len; const char* name; } table[] = {
        // sha1WithRSAEncryption
        {(const uint8_t*)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", 9, "sha1WithRSAEncryption"},
        // sha256WithRSAEncryption
        {(const uint8_t*)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", 9, "sha256WithRSAEncryption"},
        // sha384WithRSAEncryption
        {(const uint8_t*)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", 9, "sha384WithRSAEncryption"},
        // sha512WithRSAEncryption
        {(const uint8_t*)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", 9, "sha512WithRSAEncryption"},
        // ecdsa-with-SHA256
        {(const uint8_t*)"\x2a\x86\x48\xce\x3d\x04\x03\x02",     8, "ecdsa-with-SHA256"},
        // ecdsa-with-SHA384
        {(const uint8_t*)"\x2a\x86\x48\xce\x3d\x04\x03\x03",     8, "ecdsa-with-SHA384"},
        // rsaEncryption (public key alg)
        {(const uint8_t*)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 9, "rsaEncryption"},
        // id-ecPublicKey
        {(const uint8_t*)"\x2a\x86\x48\xce\x3d\x02\x01",         7, "id-ecPublicKey"},
        // md5WithRSAEncryption
        {(const uint8_t*)"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", 9, "md5WithRSAEncryption"},
        {nullptr, 0, nullptr}
    };
    for (int i = 0; table[i].oid; ++i)
        if (len == table[i].len && memcmp(oid, table[i].oid, len) == 0)
            return table[i].name;
    return nullptr;
}

// 从 Name SEQUENCE 中提取 RDN 属性值
// CN OID: 55 04 03 | O: 55 04 0a | C: 55 04 06 | ST: 55 04 08 | L: 55 04 07
static std::string extract_rdn_attr(const uint8_t* name_data, size_t name_len,
                                    uint8_t oid2) // 第 3 个 OID 字节区分属性
{
    DER name(name_data, name_len);
    while (!name.eof()) {
        // SEQUENCE OF SET OF SEQUENCE { OID, VALUE }
        uint8_t t; const uint8_t* rdn; size_t rdn_l;
        if (!name.tlv(t, rdn, rdn_l)) break; // should be SET (0x31)
        DER set(rdn, rdn_l);
        while (!set.eof()) {
            uint8_t t2; const uint8_t* atv; size_t atv_l;
            if (!set.tlv(t2, atv, atv_l)) break; // SEQUENCE
            DER seq(atv, atv_l);
            const uint8_t* oid_data; size_t oid_len;
            if (!seq.read_oid_bytes(oid_data, oid_len)) continue;
            // Check: OID = 55 04 XX
            if (oid_len == 3 && oid_data[0] == 0x55 && oid_data[1] == 0x04
                && oid_data[2] == oid2) {
                return seq.read_string();
            }
        }
    }
    return {};
}

// ============================================================
// 解析 SubjectPublicKeyInfo → 返回算法名 + 公钥位数
// ============================================================
static void parse_spki(const uint8_t* spki, size_t spki_len,
                        std::string& alg, int& bits) {
    DER d(spki, spki_len);
    // AlgorithmIdentifier SEQUENCE
    uint8_t t; const uint8_t* alg_seq; size_t alg_seq_l;
    if (!d.tlv(t, alg_seq, alg_seq_l)) return;
    DER a(alg_seq, alg_seq_l);
    const uint8_t* oid; size_t oidl;
    if (a.read_oid_bytes(oid, oidl)) {
        const char* n = oid_to_sig_alg(oid, oidl);
        alg = n ? n : "unknown";
    }
    // BIT STRING containing public key
    const uint8_t* bs; size_t bsl;
    if (!d.expect(0x03, bs, bsl) || bsl < 2) return;
    // For RSA: skip leading 0x00 + SEQUENCE { INTEGER n, INTEGER e }
    const uint8_t* key_data = bs + 1; // skip unused-bits byte
    size_t         key_len  = bsl - 1;
    if (alg.find("rsa") != std::string::npos ||
        alg.find("RSA") != std::string::npos) {
        DER rk(key_data, key_len);
        uint8_t rt; const uint8_t* seq_v; size_t seq_l;
        if (rk.tlv(rt, seq_v, seq_l)) { // SEQUENCE
            DER ms(seq_v, seq_l);
            uint8_t it; const uint8_t* n_v; size_t n_l;
            if (ms.tlv(it, n_v, n_l) && it == 0x02) {
                // strip leading zero byte
                size_t eb = n_l;
                if (eb > 0 && n_v[0] == 0x00) eb--;
                bits = (int)(eb * 8);
            }
        }
    }
}

// ============================================================
// 解析 X.509 DER 证书
// ============================================================
static CertInfo parse_cert_der(const uint8_t* der, size_t len) {
    CertInfo ci;
    ci.sha1_fingerprint = sha1_hex(der, len);

    DER d(der, len);
    // Outer SEQUENCE
    uint8_t t; const uint8_t* tbs_v; size_t tbs_l;
    if (!d.tlv(t, tbs_v, tbs_l) || t != 0x30) return ci;

    DER tbs(tbs_v, tbs_l);

    // TBSCertificate SEQUENCE
    const uint8_t* tbs2_v; size_t tbs2_l;
    if (!tbs.tlv(t, tbs2_v, tbs2_l) || t != 0x30) return ci;
    DER tc(tbs2_v, tbs2_l);

    // Optional: version [0] EXPLICIT
    auto m0 = tc.mark();
    uint8_t ft; const uint8_t* fv; size_t fl;
    if (tc.tlv(ft, fv, fl) && ft == 0xa0) { // context [0]
        DER ver_d(fv, fl);
        const uint8_t* vv; size_t vl;
        if (ver_d.tlv(ft, vv, vl) && ft == 0x02 && vl == 1)
            ci.version = vv[0] + 1;
    } else {
        tc.rewind(m0); // no version field (v1)
    }

    // Serial Number INTEGER
    const uint8_t* serial; size_t serial_l;
    if (tc.expect(0x02, serial, serial_l))
        ci.serial_hex = bytes_to_hex(serial, std::min(serial_l, (size_t)20), ':');

    // Signature AlgorithmIdentifier SEQUENCE
    const uint8_t* sig_seq; size_t sig_seq_l;
    if (tc.expect(0x30, sig_seq, sig_seq_l)) {
        DER sa(sig_seq, sig_seq_l);
        const uint8_t* oid; size_t oidl;
        if (sa.read_oid_bytes(oid, oidl)) {
            const char* n = oid_to_sig_alg(oid, oidl);
            ci.sig_alg = n ? n : bytes_to_hex(oid, oidl, ' ');
        }
    }

    // Issuer Name SEQUENCE OF
    const uint8_t* iss; size_t iss_l;
    if (tc.expect(0x30, iss, iss_l)) {
        ci.issuer_cn = extract_rdn_attr(iss, iss_l, 0x03);
        ci.issuer_o  = extract_rdn_attr(iss, iss_l, 0x0a);
        ci.issuer_c  = extract_rdn_attr(iss, iss_l, 0x06);
        ci.issuer_st = extract_rdn_attr(iss, iss_l, 0x08);
        ci.issuer_l  = extract_rdn_attr(iss, iss_l, 0x07);
    }

    // Validity SEQUENCE
    const uint8_t* val; size_t val_l;
    if (tc.expect(0x30, val, val_l)) {
        DER v(val, val_l);
        ci.not_before = v.read_time();
        ci.not_after  = v.read_time();
    }

    // Subject Name SEQUENCE OF
    const uint8_t* sub; size_t sub_l;
    if (tc.expect(0x30, sub, sub_l)) {
        ci.subject_cn = extract_rdn_attr(sub, sub_l, 0x03);
        ci.subject_o  = extract_rdn_attr(sub, sub_l, 0x0a);
        ci.subject_c  = extract_rdn_attr(sub, sub_l, 0x06);
        ci.subject_st = extract_rdn_attr(sub, sub_l, 0x08);
        ci.subject_l  = extract_rdn_attr(sub, sub_l, 0x07);
    }

    // SubjectPublicKeyInfo SEQUENCE
    const uint8_t* spki; size_t spki_l;
    if (tc.expect(0x30, spki, spki_l))
        parse_spki(spki, spki_l, ci.pub_key_alg, ci.pub_key_bits);

    // Skip optional issuerUniqueID [1] and subjectUniqueID [2]
    while (!tc.eof()) {
        // parse remaining fields (version [0], issuerUID [1], subjectUID [2], extensions [3])
        uint8_t ft2; const uint8_t* fv2; size_t fl2;
        if (!tc.tlv(ft2, fv2, fl2)) break;
        if (ft2 == 0xa3) { // extensions [3] EXPLICIT
            DER exts_outer(fv2, fl2);
            const uint8_t* exts_seq; size_t exts_seq_l;
            if (exts_outer.expect(0x30, exts_seq, exts_seq_l)) {
                DER exts(exts_seq, exts_seq_l);
                while (!exts.eof()) {
                    // Extension ::= SEQUENCE { OID, critical?, OCTET STRING }
                    const uint8_t* ext_seq; size_t ext_seq_l;
                    if (!exts.expect(0x30, ext_seq, ext_seq_l)) break;
                    DER es(ext_seq, ext_seq_l);
                    const uint8_t* eoid; size_t eoid_l;
                    if (!es.read_oid_bytes(eoid, eoid_l)) continue;
                    // optional critical BOOLEAN
                    auto em = es.mark();
                    uint8_t bt; const uint8_t* bv; size_t bl;
                    if (es.tlv(bt, bv, bl) && bt == 0x01) { /* skip */ }
                    else es.rewind(em);
                    // extnValue OCTET STRING
                    const uint8_t* ev; size_t el;
                    if (!es.expect(0x04, ev, el)) continue;

                    // SAN: OID 2.5.29.17 = 55 1d 11
                    if (oid_eq(eoid, eoid_l, {0x55,0x1d,0x11})) {
                        DER san_outer(ev, el);
                        const uint8_t* san_seq; size_t san_seq_l;
                        if (san_outer.expect(0x30, san_seq, san_seq_l)) {
                            DER san(san_seq, san_seq_l);
                            while (!san.eof()) {
                                uint8_t gt; const uint8_t* gv; size_t gl;
                                if (!san.tlv(gt, gv, gl)) break;
                                if (gt == 0x82) { // [2] dNSName
                                    ci.sans.emplace_back(
                                        reinterpret_cast<const char*>(gv), gl);
                                } else if (gt == 0x87 && gl == 4) { // [7] iPAddress
                                    char ip[16];
                                    snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                                             gv[0], gv[1], gv[2], gv[3]);
                                    ci.sans.emplace_back(ip);
                                }
                            }
                        }
                    }
                    // Basic Constraints: OID 2.5.29.19 = 55 1d 13
                    else if (oid_eq(eoid, eoid_l, {0x55,0x1d,0x13})) {
                        DER bc_outer(ev, el);
                        const uint8_t* bc_seq; size_t bc_seq_l;
                        if (bc_outer.expect(0x30, bc_seq, bc_seq_l) && bc_seq_l > 0) {
                            DER bc(bc_seq, bc_seq_l);
                            const uint8_t* bv2; size_t bl2;
                            if (bc.expect(0x01, bv2, bl2) && bl2 == 1)
                                ci.is_ca = (bv2[0] != 0);
                        }
                    }
                }
            }
            break;
        }
    }
    return ci;
}

// ============================================================
// TLS 扩展解析（TLSFlowInfo 填充）
// ============================================================
static void parse_extensions(const uint8_t* ext_data, size_t ext_len,
                              TLSFlowInfo& fi, bool is_client)
{
    if (ext_len < 2) return;
    uint16_t total = (ext_data[0] << 8) | ext_data[1];
    const uint8_t* p = ext_data + 2;
    const uint8_t* e = ext_data + 2 + std::min((size_t)total, ext_len - 2);

    while (p + 4 <= e) {
        uint16_t etype = (p[0] << 8) | p[1];
        uint16_t elen  = (p[2] << 8) | p[3];
        p += 4;
        if (p + elen > e) break;
        const uint8_t* ed = p; p += elen;

        if (!tls_is_grease(etype)) {
            fi.extensions_seen.push_back(etype);
            if (is_client) fi.client_extensions.push_back(etype);
        }

        switch (etype) {
        case TLS_EXT_SNI:
            if (elen >= 5 && ed[2] == 0) { // type=0 (host_name)
                uint16_t nl = (ed[3] << 8) | ed[4];
                if (nl <= elen - 5)
                    fi.sni = std::string(reinterpret_cast<const char*>(ed + 5), nl);
                fi.has_sni = true;
            }
            break;
        case TLS_EXT_ALPN: {
            if (elen < 2) break;
            uint16_t list_len = (ed[0] << 8) | ed[1];
            const uint8_t* ap = ed + 2;
            const uint8_t* ae = ed + 2 + std::min((size_t)list_len, (size_t)(elen - 2));
            fi.has_alpn = true;
            while (ap < ae) {
                uint8_t pl = *ap++;
                if (ap + pl > ae) break;
                std::string proto(reinterpret_cast<const char*>(ap), pl);
                fi.alpn_offered.push_back(proto);
                ap += pl;
            }
            if (!is_client && !fi.alpn_offered.empty())
                fi.alpn_selected = fi.alpn_offered[0];
            break;
        }
        case TLS_EXT_HEARTBEAT:
            fi.has_heartbeat = true;
            if (elen >= 1) fi.heartbeat_mode = ed[0];
            break;
        case TLS_EXT_ECH_OUTER:
        case TLS_EXT_ECH_DRAFT:
            fi.has_ech = true;
            fi.ech_raw_hex = bytes_to_hex(ed, std::min(elen, (uint16_t)16), ':');
            break;
        case TLS_EXT_ESNI:
            fi.has_esni = true;
            break;
        case TLS_EXT_SESSION_TICKET:
            fi.has_session_ticket = true;
            break;
        case TLS_EXT_EXTENDED_MASTER:
            fi.has_ext_master_sec = true;
            break;
        case TLS_EXT_EARLY_DATA:
            fi.has_early_data = true;
            break;
        case TLS_EXT_STATUS_REQUEST:
            fi.has_ocsp_stapling = true;
            break;
        case TLS_EXT_SCT:
            fi.has_sct = true;
            break;
        case TLS_EXT_ENCRYPT_THEN_MAC:
            fi.has_encrypt_then_mac = true;
            break;
        case TLS_EXT_RENEGOTIATION_INFO:
            fi.has_renegotiation_info = true;
            break;
        case TLS_EXT_SUPPORTED_GROUPS:
            if (elen >= 2) {
                uint16_t gl = (ed[0] << 8) | ed[1];
                for (uint16_t i = 2; i + 1 < gl + 2 && i + 1 < elen; i += 2) {
                    uint16_t g = (ed[i] << 8) | ed[i+1];
                    if (!tls_is_grease(g)) fi.supported_groups.push_back(g);
                }
            }
            break;
        case TLS_EXT_EC_POINT_FORMATS:
            if (elen >= 1) {
                uint8_t fl = ed[0];
                for (uint8_t i = 1; i <= fl && i < elen; ++i)
                    fi.ec_point_formats.push_back(ed[i]);
            }
            break;
        case TLS_EXT_SUPPORTED_VERSIONS:
            if (is_client && elen >= 1) {
                uint8_t vl = ed[0];
                for (uint8_t i = 1; i + 1 <= vl && i + 1 < elen; i += 2) {
                    uint16_t v = (ed[i] << 8) | ed[i+1];
                    if (!tls_is_grease(v)) {
                        fi.supported_versions.push_back(v);
                        if (!fi.negotiated_version) fi.negotiated_version = v;
                    }
                }
            } else if (!is_client && elen == 2) {
                fi.negotiated_version = (ed[0] << 8) | ed[1];
            }
            break;
        case TLS_EXT_SIG_ALGOS:
            if (elen >= 2) {
                uint16_t sl = (ed[0] << 8) | ed[1];
                for (uint16_t i = 2; i + 1 < sl + 2 && i + 1 < elen; i += 2)
                    fi.sig_algorithms.push_back((ed[i] << 8) | ed[i+1]);
            }
            break;
        case TLS_EXT_KEY_SHARE:
            if (is_client && elen >= 2) {
                uint16_t ksl = (ed[0] << 8) | ed[1];
                for (uint16_t i = 2; i + 3 < ksl + 2 && i + 3 < elen; ) {
                    uint16_t kg = (ed[i] << 8) | ed[i+1];
                    uint16_t kl = (ed[i+2] << 8) | ed[i+3];
                    if (!tls_is_grease(kg)) fi.key_share_groups.push_back(kg);
                    i += 4 + kl;
                }
            } else if (!is_client && elen >= 4) {
                uint16_t kg = (ed[0] << 8) | ed[1];
                if (!tls_is_grease(kg)) fi.key_share_groups.push_back(kg);
            }
            break;
        case TLS_EXT_PSK_KE_MODES:
            if (elen >= 1) {
                uint8_t ml = ed[0];
                for (uint8_t i = 1; i <= ml && i < elen; ++i)
                    fi.psk_ke_modes.push_back(ed[i]);
            }
            break;
        default: break;
        }
    }
}

// ============================================================
// TLS 握手消息解析
// ============================================================
static void parse_client_hello(const uint8_t* d, size_t len, TLSFlowInfo& fi) {
    if (len < 34) return;
    fi.has_client_hello = true;
    fi.handshake_version = (d[0] << 8) | d[1];
    // random (32 bytes) → d[2..33]
    size_t off = 34;
    // session ID
    if (off >= len) return;
    uint8_t sid_len = d[off++];
    if (off + sid_len > len) return;
    if (sid_len) fi.session_id_hex = bytes_to_hex(d + off, sid_len, 0);
    off += sid_len;
    // cipher suites
    if (off + 2 > len) return;
    uint16_t cs_len = (d[off] << 8) | d[off+1]; off += 2;
    if (off + cs_len > len) return;
    for (uint16_t i = 0; i < cs_len; i += 2) {
        uint16_t c = (d[off+i] << 8) | d[off+i+1];
        if (!tls_is_grease(c)) fi.ciphers_offered.push_back(c);
    }
    off += cs_len;
    // compression methods
    if (off >= len) return;
    uint8_t comp_len = d[off++];
    off += comp_len;
    // extensions
    if (off + 2 <= len)
        parse_extensions(d + off, len - off, fi, true);

    fi.ja3_raw = build_ja3_raw(fi.handshake_version, fi.ciphers_offered,
                               fi.client_extensions, fi.supported_groups,
                               fi.ec_point_formats);
    fi.ja3 = md5_hex(fi.ja3_raw);
}

static void parse_server_hello(const uint8_t* d, size_t len, TLSFlowInfo& fi) {
    if (len < 34) return;
    fi.has_server_hello = true;
    fi.handshake_version = (d[0] << 8) | d[1];
    // random (32)
    size_t off = 34;
    // session ID
    if (off >= len) return;
    uint8_t sid_len = d[off++];
    if (sid_len) {
        if (off + sid_len > len) return;
        fi.session_id_hex = bytes_to_hex(d + off, sid_len, 0);
        // if session_id present and matches previous session → resumed
    }
    off += sid_len;
    if (off + 2 > len) return;
    fi.cipher_selected = (d[off] << 8) | d[off+1]; off += 2;
    if (off >= len) return;
    fi.compression_method = d[off++];

    // server-side extensions for JA3S
    std::vector<uint16_t> server_exts_before = fi.extensions_seen;
    if (off + 2 <= len)
        parse_extensions(d + off, len - off, fi, false);

    // extensions added by ServerHello (diff)
    std::vector<uint16_t> sh_exts;
    for (size_t i = server_exts_before.size(); i < fi.extensions_seen.size(); ++i)
        sh_exts.push_back(fi.extensions_seen[i]);

    fi.ja3s_raw = build_ja3s_raw(fi.handshake_version, fi.cipher_selected, sh_exts);
    fi.ja3s = md5_hex(fi.ja3s_raw);
}

static void parse_certificate(const uint8_t* d, size_t len, TLSFlowInfo& fi) {
    if (len < 3) return;
    fi.has_certificate = true;
    uint32_t list_len = (d[0] << 16) | (d[1] << 8) | d[2];
    size_t off = 3;
    while (off + 3 <= len && off - 3 < list_len) {
        uint32_t cert_len = (d[off] << 16) | (d[off+1] << 8) | d[off+2];
        off += 3;
        if (off + cert_len > len) break;
        if (cert_len > 0) {
            CertInfo ci = parse_cert_der(d + off, cert_len);
            fi.certs.push_back(std::move(ci));
        }
        off += cert_len;
        if (fi.certs.size() >= 3) break; // 最多解析3张证书
    }
}

static void parse_server_key_exchange(const uint8_t* d, size_t len,
                                       TLSFlowInfo& fi, uint16_t cipher)
{
    fi.has_server_key_exch = true;
    // Detect key exchange type from cipher
    uint8_t c_hi = cipher >> 8;
    if (cipher == 0xC011 || cipher == 0xC012 || cipher == 0xC013 || cipher == 0xC014 ||
        (c_hi == 0xC0 && (cipher & 0xff) >= 0x23 && (cipher & 0xff) <= 0x2C) ||
        (c_hi == 0xC0 && (cipher & 0xff) >= 0x2B && (cipher & 0xff) <= 0x30) ||
        cipher == 0xCCA8 || cipher == 0xCCA9) {
        fi.ke_type = "ECDHE";
        if (len >= 4 && d[0] == 3) { // named_curve
            fi.ke_curve = (d[1] << 8) | d[2];
            uint8_t pk_len = d[3];
            fi.ke_pubkey_bytes = pk_len;
        }
    } else if (cipher == 0x0033 || cipher == 0x0039 || cipher == 0x009E || cipher == 0x009F) {
        fi.ke_type = "DHE";
    } else if (len == 0) {
        fi.ke_type = "RSA";  // RSA key exchange has no SKE
    }
    // Signature algorithm for TLS 1.2+
    if (fi.ke_type == "ECDHE" && len > 4 + (size_t)fi.ke_pubkey_bytes + 2) {
        size_t sig_off = 1 + 2 + 1 + fi.ke_pubkey_bytes;
        if (fi.handshake_version >= 0x0303 && sig_off + 2 <= len) {
            uint8_t h_alg = d[sig_off], s_alg = d[sig_off + 1];
            const char* h[] = {"","md5","sha1","sha224","sha256","sha384","sha512"};
            const char* s[] = {"","rsa","dsa","ecdsa"};
            if (h_alg < 7 && s_alg < 4)
                fi.ke_sig_alg = std::string(h[h_alg]) + "_with_" + s[s_alg];
        }
    }
}

// ============================================================
// 流记录（每条 TCP 流对应一条）
// ============================================================
struct TLSFlow {
    TLSFlowInfo info;
    FlowKey     fwd_key;
    bool        emitted = false;
};

// ============================================================
// 全局状态
// ============================================================
struct AppCtx {
    std::unordered_map<FlowKey, TLSFlow, FlowKeyHash> flows;
    std::ostream* out    = nullptr;
    int           filter_port = 0; // 0 = all ports
    bool          live_mode   = false;
    pcap_t*       handle      = nullptr;
    long          total_pkts  = 0;
    long          tls_flows   = 0;
    long          emitted     = 0;
};

static AppCtx* g_ctx = nullptr;
static std::string g_pcap_name;

// ============================================================
// 处理一个 TCP 包载荷中的所有 TLS 记录
// ============================================================
static void process_tls_payload(TLSFlow& flow, bool /*is_fwd*/,
                                 const uint8_t* payload, int pay_len, double ts)
{
    TLSFlowInfo& fi = flow.info;
    fi.pkt_total++;

    int i = 0;
    while (i + 5 <= pay_len) {
        uint8_t  ct      = payload[i];
        uint16_t ver     = ((uint16_t)payload[i+1] << 8) | payload[i+2];
        uint16_t rec_len = ((uint16_t)payload[i+3] << 8) | payload[i+4];
        i += 5;

        if (ct < 20 || ct > 24) break; // 不是有效的 TLS record
        if (ver < 0x0200 || ver > 0x0400) break;
        if (i + rec_len > pay_len) break; // 记录不完整（跨段）

        const uint8_t* rec_data = payload + i;
        i += rec_len;

        // 记录版本（取第一次见到的）
        if (!fi.record_version) fi.record_version = ver;
        fi.bytes_total += 5 + rec_len;

        switch (ct) {
        case TLS_CT_HANDSHAKE: {
            fi.cnt_handshake++;
            // 一条 Handshake 记录可包含多条消息
            int j = 0;
            while (j + 4 <= rec_len) {
                uint8_t  hs_type = rec_data[j];
                uint32_t hs_len  = ((uint32_t)rec_data[j+1] << 16)
                                 | ((uint32_t)rec_data[j+2] << 8)
                                 | rec_data[j+3];
                j += 4;
                if (j + hs_len > (uint32_t)rec_len) break;
                const uint8_t* hd = rec_data + j; j += hs_len;

                switch (hs_type) {
                case TLS_HS_CLIENT_HELLO:
                    parse_client_hello(hd, hs_len, fi);
                    break;
                case TLS_HS_SERVER_HELLO:
                    parse_server_hello(hd, hs_len, fi);
                    break;
                case TLS_HS_CERTIFICATE:
                    parse_certificate(hd, hs_len, fi);
                    break;
                case TLS_HS_SERVER_KEY_EXCHANGE:
                    parse_server_key_exchange(hd, hs_len, fi, fi.cipher_selected);
                    break;
                case TLS_HS_SERVER_HELLO_DONE:
                    fi.has_server_hello_done = true;
                    break;
                case TLS_HS_CLIENT_KEY_EXCHANGE:
                    fi.has_client_key_exch = true;
                    break;
                case TLS_HS_NEW_SESSION_TICKET:
                    fi.has_new_session_ticket = true;
                    break;
                case TLS_HS_FINISHED:
                    fi.has_finished = true;
                    if (fi.has_change_cipher_spec) fi.handshake_complete = true;
                    break;
                default: break;
                }
            }
            break;
        }
        case TLS_CT_APP_DATA:
            fi.cnt_app_data++;
            fi.bytes_app_data += rec_len;
            break;
        case TLS_CT_CHANGE_CIPHER_SPEC:
            fi.cnt_ccs++;
            fi.has_change_cipher_spec = true;
            break;
        case TLS_CT_ALERT:
            fi.cnt_alert++;
            if (rec_len >= 2) { fi.alert_level = rec_data[0]; fi.alert_desc = rec_data[1]; }
            break;
        case TLS_CT_HEARTBEAT:
            fi.cnt_heartbeat++;
            break;
        }
    }
    fi.last_ts = ts;
}

// ============================================================
// libpcap 回调
// ============================================================
static void pcap_cb(u_char* user, const struct pcap_pkthdr* hdr, const uint8_t* pkt) {
    AppCtx* ctx = reinterpret_cast<AppCtx*>(user);
    ctx->total_pkts++;

    if (hdr->caplen < 54) return; // eth(14)+ip(20)+tcp(20)

    // Ethernet + VLAN
    uint16_t eth_type = ntohs(*(const uint16_t*)(pkt + 12));
    const uint8_t* ip_p = pkt + 14;
    uint32_t remain = hdr->caplen - 14;
    while ((eth_type == 0x8100 || eth_type == 0x88a8) && remain >= 4) {
        eth_type = ntohs(*(const uint16_t*)(ip_p + 2));
        ip_p += 4; remain -= 4;
    }
    if (eth_type != 0x0800 || remain < (uint32_t)sizeof(struct iphdr)) return;

    const struct iphdr* iph = (const struct iphdr*)ip_p;
    if (iph->protocol != IPPROTO_TCP) return;
    int ihl = iph->ihl * 4;
    if (ihl < 20 || (uint32_t)ihl > remain) return;

    uint32_t src_ip = iph->saddr, dst_ip = iph->daddr;

    const uint8_t* tp = ip_p + ihl;
    uint32_t tp_rem = remain - ihl;
    if (tp_rem < (uint32_t)sizeof(struct tcphdr)) return;
    const struct tcphdr* tcph = (const struct tcphdr*)tp;

    uint16_t sp = tcph->source, dp = tcph->dest;
    int thdr = tcph->doff * 4;
    if (thdr < 20 || (uint32_t)thdr > tp_rem) return;

    // 端口过滤
    int sport = ntohs(sp), dport = ntohs(dp);
    if (ctx->filter_port && sport != ctx->filter_port && dport != ctx->filter_port)
        return;

    int pay_len = (int)(tp_rem - thdr);
    const uint8_t* payload = tp + thdr;

    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;

    // TCP 保活检测（零载荷 ACK）
    bool is_keepalive = (pay_len == 0 && (tcph->th_flags & 0x10)); // ACK only

    // 流查找
    FlowKey key; key.sip=src_ip; key.dip=dst_ip; key.sp=sp; key.dp=dp; key.proto=6;
    FlowKey rev = key.rev();

    auto it = ctx->flows.find(key);
    bool is_fwd = true;
    if (it == ctx->flows.end()) {
        it = ctx->flows.find(rev);
        if (it != ctx->flows.end()) {
            is_fwd = false;
        } else {
            // 新流
            if (pay_len < 3) { // 必须有 TLS record 雏形才创建流
                // 但先允许建立，后续有 TLS 才处理
                if (pay_len == 0 && !is_keepalive) return;
            }
            TLSFlow f;
            f.fwd_key = key;
            TLSFlowInfo& fi = f.info;
            fi.first_ts = ts; fi.last_ts = ts;
            // 填写流标识
            char ss[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN];
            struct in_addr sa{src_ip}, da{dst_ip};
            inet_ntop(AF_INET, &sa, ss, sizeof(ss));
            inet_ntop(AF_INET, &da, ds, sizeof(ds));
            snprintf(fi.flow_id, sizeof(fi.flow_id),
                     "%s:%d -> %s:%d TCP", ss, sport, ds, dport);
            memcpy(fi.src_ip, ss, sizeof(ss));
            memcpy(fi.dst_ip, ds, sizeof(ds));
            fi.src_port = sp; fi.dst_port = dp; fi.proto = 6;
            ctx->flows[key] = std::move(f);
            it = ctx->flows.find(key);
            ctx->tls_flows++;
        }
    }

    TLSFlow& flow = it->second;
    if (is_keepalive) {
        flow.info.tcp_keepalive_cnt++;
        return;
    }

    if (pay_len >= 5)
        process_tls_payload(flow, is_fwd, payload, pay_len, ts);
    else if (pay_len > 0)
        flow.info.bytes_total += pay_len;
}

// ============================================================
// 信号处理
// ============================================================
static void sig_handler(int) {
    if (g_ctx && g_ctx->handle) pcap_breakloop(g_ctx->handle);
}

// ============================================================
// main
// ============================================================
static void print_usage(const char* p) {
    fprintf(stderr,
        "用法:\n"
        "  %s -r <pcap文件>  [-w <log>] [-p <port>]\n"
        "  %s -i <网卡名>    [-w <log>] [-p <port>]\n"
        "\n"
        "选项:\n"
        "  -r <pcap>   离线 pcap 文件\n"
        "  -i <iface>  在线抓包（需 root）\n"
        "  -w <log>    输出 JSON Lines（默认 tls.log，- 为 stdout）\n"
        "  -p <port>   只处理指定端口（默认 0=全部）\n"
        "  -h          帮助\n",
        p, p);
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_tls(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) { res.exit_code = 1; res.message = "pcap_path required"; return res; }

    std::string output_file = cfg.output_path.empty() ? "tls.log" : cfg.output_path;
    int filter_port = cfg.filter_port;

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!handle) { res.exit_code = 1; res.message = errbuf; return res; }

    g_pcap_name = cfg.pcap_path;
    if (const char* base = strrchr(cfg.pcap_path.c_str(), '/')) g_pcap_name = base + 1;

    struct bpf_program fp;
    std::string bpf_str = (filter_port > 0) ? ("tcp port " + std::to_string(filter_port)) : "tcp";
    if (pcap_compile(handle, &fp, bpf_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    std::ofstream fout;
    std::ostream* out_ptr = nullptr;
    if (output_file == "-") {
        out_ptr = &std::cout;
    } else {
        fout.open(output_file);
        if (!fout) { pcap_close(handle); res.exit_code = 1; res.message = "cannot open output"; return res; }
        out_ptr = &fout;
    }

    AppCtx ctx;
    ctx.out = out_ptr;
    ctx.filter_port = filter_port;
    ctx.live_mode = false;
    ctx.handle = handle;
    g_ctx = &ctx;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    auto t0 = std::chrono::steady_clock::now();
    pcap_loop(handle, 0, pcap_cb, reinterpret_cast<u_char*>(&ctx));
    pcap_close(handle);

    for (auto& [k, flow] : ctx.flows) {
        if (!flow.emitted) {
            emit_tls_json(*out_ptr, flow.info, g_pcap_name.c_str());
            flow.emitted = true;
            ctx.emitted++;
        }
    }
    if (fout.is_open()) fout.close();

    res.elapsed_sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    res.packets = ctx.total_pkts;
    res.flows = ctx.emitted;
    res.message = "ok";
    return res;
}

#ifndef NVERS_LIBRARY
int main(int argc, char* argv[]) {
    std::string pcap_file, iface, output_file = "tls.log";
    int  filter_port = 0;
    bool live_mode   = false;

    int opt;
    while ((opt = getopt(argc, argv, "r:i:w:p:h")) != -1) {
        switch (opt) {
        case 'r': pcap_file = optarg; break;
        case 'i': iface = optarg; live_mode = true; break;
        case 'w': output_file = optarg; break;
        case 'p': filter_port = std::atoi(optarg); break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }
    if (pcap_file.empty() && !live_mode) {
        fprintf(stderr, "错误：请指定 -r <pcap> 或 -i <网卡>\n\n");
        print_usage(argv[0]); return 1;
    }
    if (live_mode) { fprintf(stderr, "库模式仅支持离线 pcap\n"); return 1; }
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    cfg.output_path = output_file;
    cfg.filter_port = filter_port;
    return wa1kpcap::nvers::run_tls(cfg).exit_code;
}
#endif
