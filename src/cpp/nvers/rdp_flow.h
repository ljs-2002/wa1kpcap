/**
 * rdp_flow.h  ——  RDP (Remote Desktop Protocol) 协议检测与字段提取（Header-Only）
 *
 * 协议层次：
 *   TPKT (RFC 1006, port 3389) → X.224 → MCS/T.125 → RDP
 *
 * 支持提取字段：
 *   TPKT 版本确认
 *   X.224 PDU 类型（CR / CC / DT / DR）
 *   RDP Negotiation Request（requested protocols）
 *   RDP Negotiation Response（selected protocol, flags）
 *   RDP Negotiation Failure（reason code）
 *   Cookie / routing token（用户名）
 *   MCS Connect-Initial / Connect-Response 中的 GCC UserData：
 *     客户端：OS 类型、build、键盘布局、显示器信息、客户端名称、宽高
 *     服务端：加密级别、加密方法、服务端证书类型
 *
 * 用法示例（与 pcap 解析框架集成）：
 *   RdpFlowRecord rec;
 *   rec.init();
 *   // 每个 TCP payload 调用：
 *   parse_rdp_pkt(payload, len, is_fwd, rec);
 *   // 流结束时：
 *   rec.emit_log(stdout);
 */
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// ============================================================
// 常量：RDP 协议标识
// ============================================================
// TPKT
static constexpr uint8_t TPKT_VERSION = 3;

// X.224 PDU 类型（高 4 位）
static constexpr uint8_t X224_CR = 0xE0; // Connection Request
static constexpr uint8_t X224_CC = 0xD0; // Connection Confirm
static constexpr uint8_t X224_DR = 0x80; // Disconnect Request
static constexpr uint8_t X224_DT = 0xF0; // Data
static constexpr uint8_t X224_ED = 0x70; // Expedited Data

// RDP Negotiation 类型
static constexpr uint8_t RDP_NEG_REQ     = 0x01;
static constexpr uint8_t RDP_NEG_RSP     = 0x02;
static constexpr uint8_t RDP_NEG_FAILURE = 0x03;

// 请求/选择的协议（requestedProtocols / selectedProtocol）
static constexpr uint32_t PROTOCOL_RDP       = 0x00000000;
static constexpr uint32_t PROTOCOL_SSL       = 0x00000001;
static constexpr uint32_t PROTOCOL_HYBRID    = 0x00000002; // NLA / CredSSP
static constexpr uint32_t PROTOCOL_RDSTLS    = 0x00000004;
static constexpr uint32_t PROTOCOL_HYBRID_EX = 0x00000008; // CredSSP + Early User Auth

// NegRsp flags
static constexpr uint8_t NEG_RSP_EXTENDED_CLIENT_DATA = 0x01;
static constexpr uint8_t NEG_RSP_DYNVC_GFX_PROTOCOL   = 0x02;
static constexpr uint8_t NEG_RSP_NEGRSP_RESERVED      = 0x04;
static constexpr uint8_t NEG_RSP_RESTRICTED_ADMIN      = 0x08;
static constexpr uint8_t NEG_RSP_REDIRECTED_AUTH       = 0x10;

// NegFailure reason codes
static constexpr uint32_t NEG_FAIL_SSL_REQUIRED           = 0x00000001;
static constexpr uint32_t NEG_FAIL_SSL_NOT_ALLOWED        = 0x00000002;
static constexpr uint32_t NEG_FAIL_SSL_CERT_NOT_ON_SERVER = 0x00000003;
static constexpr uint32_t NEG_FAIL_INCONSISTENT_FLAGS     = 0x00000004;
static constexpr uint32_t NEG_FAIL_HYBRID_REQUIRED        = 0x00000005;
static constexpr uint32_t NEG_FAIL_SSL_WITH_USER_AUTH     = 0x00000006;

// MCS/GCC 中的加密方法
static constexpr uint32_t ENCRYPTION_METHOD_NONE   = 0x00000000;
static constexpr uint32_t ENCRYPTION_METHOD_40BIT  = 0x00000001;
static constexpr uint32_t ENCRYPTION_METHOD_128BIT = 0x00000002;
static constexpr uint32_t ENCRYPTION_METHOD_56BIT  = 0x00000008;
static constexpr uint32_t ENCRYPTION_METHOD_FIPS   = 0x00000010;

// 加密级别
static constexpr uint32_t ENCRYPTION_LEVEL_NONE             = 0x00000000;
static constexpr uint32_t ENCRYPTION_LEVEL_LOW              = 0x00000001;
static constexpr uint32_t ENCRYPTION_LEVEL_CLIENT_COMPATIBLE= 0x00000002;
static constexpr uint32_t ENCRYPTION_LEVEL_HIGH             = 0x00000003;
static constexpr uint32_t ENCRYPTION_LEVEL_FIPS             = 0x00000004;

// ============================================================
// 辅助：名称映射
// ============================================================
static inline const char* rdp_protocol_name(uint32_t p) {
    switch (p) {
    case PROTOCOL_RDP:       return "Classic-RDP";
    case PROTOCOL_SSL:       return "TLS";
    case PROTOCOL_HYBRID:    return "CredSSP/NLA";
    case PROTOCOL_RDSTLS:    return "RDSTLS";
    case PROTOCOL_HYBRID_EX: return "CredSSP+EarlyUserAuth";
    default:                 return "Unknown";
    }
}
static inline const char* rdp_enc_method_name(uint32_t m) {
    switch (m) {
    case ENCRYPTION_METHOD_NONE:   return "None";
    case ENCRYPTION_METHOD_40BIT:  return "40-bit RC4";
    case ENCRYPTION_METHOD_128BIT: return "128-bit RC4";
    case ENCRYPTION_METHOD_56BIT:  return "56-bit RC4";
    case ENCRYPTION_METHOD_FIPS:   return "FIPS 140-1 (3DES)";
    default:                       return "Unknown";
    }
}
static inline const char* rdp_enc_level_name(uint32_t l) {
    switch (l) {
    case ENCRYPTION_LEVEL_NONE:              return "None";
    case ENCRYPTION_LEVEL_LOW:               return "Low";
    case ENCRYPTION_LEVEL_CLIENT_COMPATIBLE: return "ClientCompatible";
    case ENCRYPTION_LEVEL_HIGH:              return "High";
    case ENCRYPTION_LEVEL_FIPS:              return "FIPS";
    default:                                 return "Unknown";
    }
}
static inline const char* rdp_neg_fail_name(uint32_t r) {
    switch (r) {
    case NEG_FAIL_SSL_REQUIRED:           return "SSL_REQUIRED";
    case NEG_FAIL_SSL_NOT_ALLOWED:        return "SSL_NOT_ALLOWED";
    case NEG_FAIL_SSL_CERT_NOT_ON_SERVER: return "SSL_CERT_NOT_ON_SERVER";
    case NEG_FAIL_INCONSISTENT_FLAGS:     return "INCONSISTENT_FLAGS";
    case NEG_FAIL_HYBRID_REQUIRED:        return "HYBRID_REQUIRED";
    case NEG_FAIL_SSL_WITH_USER_AUTH:     return "SSL_WITH_USER_AUTH";
    default:                              return "Unknown";
    }
}

// ============================================================
// 快速协议检测（仅检查 TPKT 头 + X.224 类型）
// ============================================================
static inline bool detect_rdp(const uint8_t* p, int len) {
    if (len < 6) return false;
    // TPKT: version=3, reserved=0, length>=6
    if (p[0] != 3 || p[1] != 0) return false;
    uint16_t tlen = (uint16_t)((p[2] << 8) | p[3]);
    if (tlen < 6) return false;
    // X.224: check PDU type byte
    uint8_t pdu = p[5];
    return (pdu == X224_CR || pdu == X224_CC || pdu == X224_DT || pdu == X224_DR);
}

// ============================================================
// RDP 流特征记录
// ============================================================
struct RdpFlowRecord {
    bool    is_rdp;

    // ---- X.224 PDU 类型已见标记 ----
    bool    seen_cr, seen_cc, seen_dt, seen_dr;

    // ---- Connection Request (来自客户端) ----
    char     cookie[128];       // mstshash=USERNAME 或路由 token
    bool     has_cookie;
    uint32_t req_protocols;     // RDP_NEG_REQ.requestedProtocols
    bool     has_neg_req;

    // ---- Connection Confirm (来自服务端) ----
    uint32_t sel_protocol;      // RDP_NEG_RSP.selectedProtocol
    uint8_t  neg_rsp_flags;     // RDP_NEG_RSP.flags
    bool     has_neg_rsp;

    bool     neg_failure;       // 收到 RDP_NEG_FAILURE
    uint32_t failure_reason;    // 失败原因码

    // ---- MCS/GCC 客户端数据（来自 Client MCS Connect-Initial） ----
    uint16_t rdp_version;       // 0x0004=4.0, 0x0005=5.0等（来自CS_CORE）
    uint32_t client_build;      // 客户端构建号
    char     client_name[32];   // 客户端计算机名（UTF-16LE → ASCII 粗提取）
    uint16_t keyboard_type;     // 键盘类型
    uint16_t keyboard_subtype;
    uint16_t keyboard_funckey;
    uint16_t os_major;          // OS 主类型（1=Win32s, 2=Win32, 3=Win32NT…）
    uint16_t os_minor;          // OS 次类型
    uint16_t desktop_width;     // 桌面宽度（像素）
    uint16_t desktop_height;    // 桌面高度
    uint16_t color_depth;       // 色深（8/15/16/24/32 bpp）
    char     client_product_id[32]; // 客户端产品ID
    bool     has_cs_core;

    // ---- MCS/GCC 服务端数据（来自 Server MCS Connect-Response） ----
    uint32_t encryption_method; // 加密方法
    uint32_t encryption_level;  // 加密级别
    uint8_t  server_cert_type;  // 1=proprietary, 2=X.509
    bool     has_sc_security;

    void init() noexcept {
        memset(this, 0, sizeof(*this));
    }

    // ---- 解析 X.224 User Data（GCC 部分简化提取） ----
    // 从 CS_CORE (type=0xC001) 数据块中提取客户端基本信息
    static inline bool parse_cs_core(const uint8_t* data, int len, RdpFlowRecord& r) {
        if (len < 28) return false;
        r.rdp_version     = (uint16_t)((data[1] << 8) | data[0]);  // LE
        r.desktop_width   = (uint16_t)((data[3] << 8) | data[2]);
        r.desktop_height  = (uint16_t)((data[5] << 8) | data[4]);
        r.color_depth     = (uint16_t)((data[7] << 8) | data[6]);
        // Bytes 8..15: sas_sequence, keyboard_layout
        r.client_build    = (uint32_t)((data[17]<<24)|(data[16]<<16)|(data[15]<<8)|data[14]);
        // Bytes 18..33: clientName (UTF-16LE, 16 bytes = 8 chars)
        if (len >= 34) {
            int k = 0;
            for (int i = 18; i < 34 && i+1 < len && k < 15; i += 2) {
                char c = (char)data[i]; // low byte of UTF-16LE
                if (c == 0) break;
                r.client_name[k++] = c;
            }
            r.client_name[15] = '\0';
        }
        if (len >= 42) {
            r.keyboard_type    = (uint16_t)((data[35]<<8)|data[34]);
            r.keyboard_subtype = (uint16_t)((data[37]<<8)|data[36]);
            r.keyboard_funckey = (uint16_t)((data[39]<<8)|data[38]);
        }
        if (len >= 46) {
            r.os_major = (uint16_t)((data[41]<<8)|data[40]);
            r.os_minor = (uint16_t)((data[43]<<8)|data[42]);
        }
        r.has_cs_core = true;
        return true;
    }

    // 从 SC_SECURITY (type=0x0C02) 数据块提取加密信息
    static inline bool parse_sc_security(const uint8_t* data, int len, RdpFlowRecord& r) {
        if (len < 8) return false;
        r.encryption_method = (uint32_t)((data[3]<<24)|(data[2]<<16)|(data[1]<<8)|data[0]);
        r.encryption_level  = (uint32_t)((data[7]<<24)|(data[6]<<16)|(data[5]<<8)|data[4]);
        // server_random_len (bytes 8..11), server_cert_len (12..15)
        if (len >= 16) {
            uint32_t cert_len = (uint32_t)((data[15]<<24)|(data[14]<<16)|(data[13]<<8)|data[12]);
            if (cert_len > 0 && len >= 16 + 36) {
                // certificate structure: first 4 bytes are dwVersion (proprietary=1, X509=2)
                r.server_cert_type = (uint8_t)(data[16 + 32] & 0xFF);
            }
        }
        r.has_sc_security = true;
        return true;
    }

    // 扫描 GCC UserData 块（简化：查找已知 type 魔术值）
    static inline void parse_gcc_userdata(const uint8_t* data, int len, RdpFlowRecord& r) {
        int i = 0;
        while (i + 4 <= len) {
            uint16_t block_type = (uint16_t)((data[i+1]<<8)|data[i]);
            uint16_t block_len  = (uint16_t)((data[i+3]<<8)|data[i+2]);
            if (block_len < 4 || i + block_len > len) break;
            const uint8_t* bd = data + i + 4;
            int blen = (int)block_len - 4;
            switch (block_type) {
            case 0xC001: parse_cs_core(bd, blen, r); break;    // CS_CORE
            case 0x0C02: parse_sc_security(bd, blen, r); break; // SC_SECURITY
            }
            i += block_len;
        }
    }

    // 每个 TCP payload 调用（应在 TCP 重组后调用，或每包尝试解析）
    void process_pkt(const uint8_t* pay, int len, bool /*is_fwd*/) {
        if (len < 6) return;
        // TPKT 检测
        if (pay[0] != TPKT_VERSION || pay[1] != 0) return;
        uint16_t tpkt_len = (uint16_t)((pay[2] << 8) | pay[3]);
        if (tpkt_len < 6 || tpkt_len > (uint16_t)len) return;
        is_rdp = true;

        // X.224 层（偏移4）
        uint8_t li  = pay[4];    // Length Indicator
        if (4 + 1 + li > len) return;
        uint8_t pdu = pay[5];    // PDU type

        if (pdu == X224_CR) {
            seen_cr = true;
            // 用户数据从偏移 4+1+li 开始（li 包含 type 之后的头字节数）
            int ud_off = 4 + 1 + (int)li + 1; // TPKT(4) + LI(1) + header(li bytes include type) + 1 skips to user data
            // 实际: TPKT=4字节, X.224 header = 1(LI)+li字节, user data 从 4+1+li 开始
            ud_off = 4 + 1 + (int)li;
            if (ud_off >= len) return;
            const uint8_t* ud  = pay + ud_off;
            int            udl = len - ud_off;

            // 扫描 cookie（ASCII "Cookie: mstshash=" 或 "Cookie: msts="）
            for (int i = 0; i + 8 < udl; i++) {
                if (ud[i]=='C' && ud[i+1]=='o' && ud[i+2]=='o' && ud[i+3]=='k' &&
                    ud[i+4]=='i' && ud[i+5]=='e' && ud[i+6]==':' && ud[i+7]==' ') {
                    // find \r\n
                    int j = i + 8;
                    int k = 0;
                    while (j < udl && ud[j] != '\r' && k < (int)sizeof(cookie)-1)
                        cookie[k++] = (char)ud[j++];
                    cookie[k] = '\0';
                    has_cookie = true;
                    break;
                }
            }

            // RDP Negotiation Request
            for (int i = 0; i + 7 < udl; i++) {
                if (ud[i] == RDP_NEG_REQ && ud[i+2] == 0x08 && ud[i+3] == 0x00) {
                    req_protocols = (uint32_t)((ud[i+7]<<24)|(ud[i+6]<<16)|(ud[i+5]<<8)|ud[i+4]);
                    has_neg_req   = true;
                    break;
                }
            }

        } else if (pdu == X224_CC) {
            seen_cc = true;
            int ud_off = 4 + 1 + (int)li;
            if (ud_off >= len) return;
            const uint8_t* ud  = pay + ud_off;
            int            udl = len - ud_off;

            // RDP Negotiation Response or Failure
            for (int i = 0; i + 7 < udl; i++) {
                if (ud[i] == RDP_NEG_RSP && ud[i+2] == 0x08 && ud[i+3] == 0x00) {
                    neg_rsp_flags = ud[i+1];
                    sel_protocol  = (uint32_t)((ud[i+7]<<24)|(ud[i+6]<<16)|(ud[i+5]<<8)|ud[i+4]);
                    has_neg_rsp   = true;
                    break;
                }
                if (ud[i] == RDP_NEG_FAILURE && ud[i+2] == 0x08 && ud[i+3] == 0x00) {
                    failure_reason = (uint32_t)((ud[i+7]<<24)|(ud[i+6]<<16)|(ud[i+5]<<8)|ud[i+4]);
                    neg_failure    = true;
                    break;
                }
            }

        } else if (pdu == X224_DT) {
            seen_dt = true;
            // DT PDU: LI bytes + 1(EOT), 偏移 4+1+li+1 到数据
            int data_off = 4 + 1 + (int)li + 1;
            if (data_off >= len) return;
            const uint8_t* data  = pay + data_off;
            int            dlen  = len - data_off;

            // 查找 GCC Conference Create Request/Response 标记
            // GCC CreateConference: BER tag 0x7f65 (conference create request)
            //                        or 0x7f66 (conference create response)
            for (int i = 0; i + 4 < dlen; i++) {
                if ((data[i] == 0x7f && data[i+1] == 0x65) ||  // GCC CCR
                    (data[i] == 0x7f && data[i+1] == 0x66)) {  // GCC CCrsp
                    // userdata in GCC: scan for CS/SC data blocks
                    parse_gcc_userdata(data + i, dlen - i, *this);
                    break;
                }
            }
        } else if (pdu == X224_DR) {
            seen_dr = true;
        }
    }

    void emit_log(FILE* f) const {
        if (!is_rdp) { fprintf(f, "[RDP] 非 RDP 流\n"); return; }
        fprintf(f, "=== RDP FLOW ===\n");
        fprintf(f, "  PDU seen: CR=%d CC=%d DT=%d DR=%d\n",
                seen_cr, seen_cc, seen_dt, seen_dr);

        if (has_cookie)
            fprintf(f, "  Cookie/Username: %s\n", cookie);

        if (has_neg_req) {
            fprintf(f, "  Requested Protocols: 0x%08x", req_protocols);
            if (req_protocols == 0)  fprintf(f, " (Classic-RDP)");
            if (req_protocols & PROTOCOL_SSL)       fprintf(f, " TLS");
            if (req_protocols & PROTOCOL_HYBRID)    fprintf(f, " CredSSP/NLA");
            if (req_protocols & PROTOCOL_RDSTLS)    fprintf(f, " RDSTLS");
            if (req_protocols & PROTOCOL_HYBRID_EX) fprintf(f, " CredSSP+EarlyAuth");
            fprintf(f, "\n");
        }
        if (has_neg_rsp) {
            fprintf(f, "  Selected Protocol: %s (0x%08x)\n",
                    rdp_protocol_name(sel_protocol), sel_protocol);
            fprintf(f, "  NegRsp Flags: 0x%02x", neg_rsp_flags);
            if (neg_rsp_flags & NEG_RSP_EXTENDED_CLIENT_DATA) fprintf(f," ExtClientData");
            if (neg_rsp_flags & NEG_RSP_DYNVC_GFX_PROTOCOL)  fprintf(f," DynVC-GFX");
            if (neg_rsp_flags & NEG_RSP_RESTRICTED_ADMIN)     fprintf(f," RestrictedAdmin");
            if (neg_rsp_flags & NEG_RSP_REDIRECTED_AUTH)      fprintf(f," RedirectedAuth");
            fprintf(f, "\n");
        }
        if (neg_failure) {
            fprintf(f, "  Negotiation FAILED: %s (0x%08x)\n",
                    rdp_neg_fail_name(failure_reason), failure_reason);
        }

        if (has_cs_core) {
            fprintf(f, "  Client Core Data:\n");
            fprintf(f, "    RDP Version : 0x%04x  Build: %u\n", rdp_version, client_build);
            fprintf(f, "    Client Name : %s\n", client_name[0] ? client_name : "(unknown)");
            fprintf(f, "    Desktop     : %ux%u  ColorDepth: %u bpp\n",
                    desktop_width, desktop_height, color_depth);
            fprintf(f, "    OS          : major=%u  minor=%u\n", os_major, os_minor);
            fprintf(f, "    Keyboard    : type=%u  subtype=%u  funckeys=%u\n",
                    keyboard_type, keyboard_subtype, keyboard_funckey);
        }
        if (has_sc_security) {
            fprintf(f, "  Server Security:\n");
            fprintf(f, "    Encryption Method : %s (0x%08x)\n",
                    rdp_enc_method_name(encryption_method), encryption_method);
            fprintf(f, "    Encryption Level  : %s (0x%08x)\n",
                    rdp_enc_level_name(encryption_level), encryption_level);
            if (server_cert_type > 0)
                fprintf(f, "    Certificate Type  : %s\n",
                        server_cert_type == 1 ? "Proprietary" :
                        server_cert_type == 2 ? "X.509" : "Unknown");
        }
        fprintf(f, "---\n");
    }
};
