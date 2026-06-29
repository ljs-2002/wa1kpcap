/**
 * vnc_flow.h  ——  VNC / RFB 协议检测与字段提取（Header-Only）
 *
 * 协议：RFB (Remote Framebuffer Protocol) over TCP，默认端口 5900–5909
 *
 * 支持提取字段：
 *   服务端版本 banner（RFB major.minor）
 *   客户端版本 banner
 *   协议状态机（7 阶段）
 *   安全类型列表（服务端 offer）与客户端选择
 *   VNC Auth：16 字节 challenge
 *   认证结果（OK / Failed / TooMany）及失败原因
 *   ClientInit：shared flag
 *   ServerInit：桌面宽高、像素格式（bpp/depth/big-endian/true-color/RGB max&shift）、服务端名称
 *   各版本兼容（3.3 / 3.7 / 3.8 / 4.1）
 *
 * 注：VNC 是有状态的流协议，本 header 提供逐包状态机跟踪。
 *     调用方需区分方向：is_fwd=true 表示客户端→服务端方向。
 */
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>

// ============================================================
// 常量：安全类型
// ============================================================
static constexpr uint8_t VNC_SEC_INVALID       =  0;
static constexpr uint8_t VNC_SEC_NONE          =  1;
static constexpr uint8_t VNC_SEC_VNC_AUTH      =  2;
static constexpr uint8_t VNC_SEC_RA2           =  5;
static constexpr uint8_t VNC_SEC_RA2NE         =  6;
static constexpr uint8_t VNC_SEC_TIGHT         = 16;
static constexpr uint8_t VNC_SEC_ULTRA         = 17;
static constexpr uint8_t VNC_SEC_TLS           = 18;
static constexpr uint8_t VNC_SEC_VENCRYPT      = 19;
static constexpr uint8_t VNC_SEC_GTK_VNC_SASL  = 20;
static constexpr uint8_t VNC_SEC_MD5_HASH      = 21;
static constexpr uint8_t VNC_SEC_COLIN_DEAN_XVP= 22;
static constexpr uint8_t VNC_SEC_SECURE_TUNNEL = 23;
static constexpr uint8_t VNC_SEC_INTEGRATED_SSH= 24;
static constexpr uint8_t VNC_SEC_APPLE_ARD     = 30;
static constexpr uint8_t VNC_SEC_RSA_AES_128   = 129;
static constexpr uint8_t VNC_SEC_RSA_AES_256   = 130;

static inline const char* vnc_sec_name(uint8_t t) {
    switch (t) {
    case  0: return "Invalid";
    case  1: return "None";
    case  2: return "VNC-Auth";
    case  5: return "RA2";
    case  6: return "RA2ne";
    case 16: return "Tight";
    case 17: return "Ultra";
    case 18: return "TLS";
    case 19: return "VeNCrypt";
    case 20: return "GTK-VNC-SASL";
    case 21: return "MD5-Hash";
    case 22: return "Colin-Dean-xvp";
    case 23: return "SecureTunnel";
    case 24: return "IntegratedSSH";
    case 30: return "Apple-ARD";
    case 129: return "RSA-AES-128-None";
    case 130: return "RSA-AES-256-None";
    default:  { static char buf[16]; snprintf(buf, sizeof buf, "Type%u", t); return buf; }
    }
}

// 认证结果
static constexpr uint32_t VNC_AUTH_OK        = 0;
static constexpr uint32_t VNC_AUTH_FAILED    = 1;
static constexpr uint32_t VNC_AUTH_TOO_MANY  = 2;

// ============================================================
// 协议状态机
// ============================================================
enum VncState : uint8_t {
    VNC_S_INIT           = 0,  // 初始：等待服务端 banner
    VNC_S_SERVER_VERSION = 1,  // 已见服务端 banner，等待客户端 banner
    VNC_S_CLIENT_VERSION = 2,  // 已见客户端 banner
    VNC_S_SEC_OFFER      = 3,  // 等待服务端 security offer
    VNC_S_SEC_CHOICE     = 4,  // 等待客户端 security choice（v3.7/3.8）
    VNC_S_VNC_AUTH       = 5,  // 等待 VNC Auth challenge/response
    VNC_S_AUTH_RESULT    = 6,  // 等待 auth result
    VNC_S_CLIENT_INIT    = 7,  // 等待 ClientInit
    VNC_S_SERVER_INIT    = 8,  // 等待 ServerInit
    VNC_S_ESTABLISHED    = 9,  // 握手完成
    VNC_S_ERROR          = 10, // 解析错误
};

// ============================================================
// VNC 流特征记录
// ============================================================
struct VncFlowRecord {
    bool       is_vnc;
    VncState   state;

    // ---- 版本协商 ----
    char     server_banner[16]; // "RFB 003.008\n"
    char     client_banner[16];
    uint8_t  proto_major;       // 3, 4, ...
    uint8_t  proto_minor;       // 3, 7, 8, 1, ...
    bool     has_server_banner;
    bool     has_client_banner;

    // ---- 安全协商 ----
    uint8_t  sec_types[16];     // 服务端提供的类型列表（v3.7/3.8）
    int      n_sec_types;
    uint8_t  sel_sec_type;      // 客户端选择的类型
    bool     has_sec_offer;
    bool     has_sec_choice;
    // v3.3：服务端直接指定
    uint32_t sec_type_33;       // v3.3 的4字节安全类型字段

    // ---- VNC Auth ----
    uint8_t  vnc_challenge[16]; // 16字节 DES challenge
    bool     has_challenge;
    // response 不记录（隐私）

    // ---- 认证结果 ----
    uint32_t auth_result;       // 0=OK, 1=Failed, 2=TooMany
    bool     auth_failed;
    char     auth_fail_reason[128];
    bool     has_auth_result;

    // ---- ClientInit ----
    bool     shared_flag;
    bool     has_client_init;

    // ---- ServerInit ----
    uint16_t fb_width, fb_height;
    // Pixel format (16 bytes)
    uint8_t  bits_per_pixel;
    uint8_t  depth;
    bool     big_endian_flag;
    bool     true_colour_flag;
    uint16_t red_max, green_max, blue_max;
    uint8_t  red_shift, green_shift, blue_shift;
    // Desktop name
    char     desktop_name[256];
    bool     has_server_init;

    void init() noexcept {
        memset(this, 0, sizeof(*this));
        state = VNC_S_INIT;
    }

    // ---- 检查是否为 RFB banner（服务端首包）----
    static bool is_rfb_banner(const uint8_t* p, int len) {
        // "RFB " + major(3) + "." + minor(3) + "\n"
        // "RFB " (4) + major(3) + "." (1) + minor(3) + "\n" (1) = 12 bytes
        return len >= 12 &&
               p[0]=='R' && p[1]=='F' && p[2]=='B' && p[3]==' ' &&
               (p[7]=='.') && (p[11]=='\n');
    }

    // 解析 major.minor 版本
    static void parse_version(const uint8_t* p, uint8_t& major, uint8_t& minor) {
        // p[4..6] = major ASCII, p[8..10] = minor ASCII
        major = (uint8_t)((p[4]-'0')*100 + (p[5]-'0')*10 + (p[6]-'0'));
        minor = (uint8_t)((p[8]-'0')*100 + (p[9]-'0')*10 + (p[10]-'0'));
    }

    // 主处理函数：每个 TCP payload 调用
    void process_pkt(const uint8_t* pay, int len, bool is_fwd) {
        if (len <= 0 || state == VNC_S_ERROR) return;

        switch (state) {
        case VNC_S_INIT:
            // 期待服务端 banner（server→client）
            if (!is_fwd && is_rfb_banner(pay, len)) {
                memcpy(server_banner, pay, (len < 15 ? len : 15));
                server_banner[15] = '\0';
                parse_version(pay, proto_major, proto_minor);
                has_server_banner = true;
                is_vnc = true;
                state  = VNC_S_SERVER_VERSION;
            }
            break;

        case VNC_S_SERVER_VERSION:
            // 期待客户端 banner（client→server）
            if (is_fwd && is_rfb_banner(pay, len)) {
                memcpy(client_banner, pay, (len < 15 ? len : 15));
                client_banner[15] = '\0';
                has_client_banner = true;
                state = VNC_S_SEC_OFFER;
            }
            break;

        case VNC_S_SEC_OFFER:
            // 期待服务端 security offer（server→client）
            if (!is_fwd) {
                if (proto_major == 3 && proto_minor == 3) {
                    // v3.3: 4-byte security type (big-endian)
                    if (len >= 4) {
                        sec_type_33 = (uint32_t)((pay[0]<<24)|(pay[1]<<16)|(pay[2]<<8)|pay[3]);
                        sel_sec_type = (uint8_t)(sec_type_33 & 0xFF);
                        has_sec_offer = true;
                        // In v3.3, server dictates; no client choice
                        if (sel_sec_type == VNC_SEC_NONE)     state = VNC_S_CLIENT_INIT;
                        else if (sel_sec_type == VNC_SEC_VNC_AUTH) state = VNC_S_VNC_AUTH;
                        else state = VNC_S_AUTH_RESULT;
                    }
                } else {
                    // v3.7/3.8: 1-byte count + N type bytes
                    if (len >= 1) {
                        int n = pay[0];
                        if (n == 0 && proto_minor >= 8 && len >= 5) {
                            // security failure: 4-byte reason length
                            state = VNC_S_ERROR;
                            return;
                        }
                        for (int i = 0; i < n && i+1 < len && i < 16; i++)
                            sec_types[i] = pay[i+1];
                        n_sec_types   = (n < 16 ? n : 16);
                        has_sec_offer = true;
                        state         = VNC_S_SEC_CHOICE;
                    }
                }
            }
            break;

        case VNC_S_SEC_CHOICE:
            // 期待客户端选择（client→server）
            if (is_fwd && len >= 1) {
                sel_sec_type   = pay[0];
                has_sec_choice = true;
                if (sel_sec_type == VNC_SEC_VNC_AUTH)
                    state = VNC_S_VNC_AUTH;
                else if (sel_sec_type == VNC_SEC_NONE)
                    state = (proto_minor >= 8) ? VNC_S_AUTH_RESULT : VNC_S_CLIENT_INIT;
                else
                    state = VNC_S_AUTH_RESULT; // other auth types
            }
            break;

        case VNC_S_VNC_AUTH:
            // 期待服务端 16 字节 DES challenge（server→client）
            if (!is_fwd && len >= 16) {
                memcpy(vnc_challenge, pay, 16);
                has_challenge = true;
                // 下一包：客户端 response（16字节），之后是 auth result
                state = VNC_S_AUTH_RESULT;
            }
            break;

        case VNC_S_AUTH_RESULT:
            // 期待服务端 4 字节结果（server→client）
            if (!is_fwd && len >= 4) {
                auth_result     = (uint32_t)((pay[0]<<24)|(pay[1]<<16)|(pay[2]<<8)|pay[3]);
                has_auth_result = true;
                auth_failed     = (auth_result != VNC_AUTH_OK);
                if (auth_failed && proto_minor >= 8 && len >= 8) {
                    // reason string: 4-byte length + chars
                    uint32_t rlen = (uint32_t)((pay[4]<<24)|(pay[5]<<16)|(pay[6]<<8)|pay[7]);
                    if (rlen > 0 && len >= (int)(8 + rlen)) {
                        int copy = (rlen < sizeof(auth_fail_reason)-1) ? (int)rlen : (int)sizeof(auth_fail_reason)-1;
                        memcpy(auth_fail_reason, pay+8, copy);
                        auth_fail_reason[copy] = '\0';
                    }
                }
                state = auth_failed ? VNC_S_ERROR : VNC_S_CLIENT_INIT;
            }
            break;

        case VNC_S_CLIENT_INIT:
            // 期待客户端 shared flag（client→server）
            if (is_fwd && len >= 1) {
                shared_flag      = (pay[0] != 0);
                has_client_init  = true;
                state            = VNC_S_SERVER_INIT;
            }
            break;

        case VNC_S_SERVER_INIT:
            // 期待服务端 ServerInit（server→client）
            // layout: 2B width + 2B height + 16B pixel_format + 4B name_length + name_bytes
            if (!is_fwd && len >= 24) {
                fb_width  = (uint16_t)((pay[0]<<8)|pay[1]);
                fb_height = (uint16_t)((pay[2]<<8)|pay[3]);
                // pixel format (16 bytes at offset 4)
                bits_per_pixel  = pay[4];
                depth           = pay[5];
                big_endian_flag = (pay[6] != 0);
                true_colour_flag= (pay[7] != 0);
                red_max    = (uint16_t)((pay[8]<<8)|pay[9]);
                green_max  = (uint16_t)((pay[10]<<8)|pay[11]);
                blue_max   = (uint16_t)((pay[12]<<8)|pay[13]);
                red_shift  = pay[14];
                green_shift= pay[15];
                blue_shift = pay[16];
                // name (offset 20: 4B length + chars)
                if (len >= 24) {
                    uint32_t nlen = (uint32_t)((pay[20]<<24)|(pay[21]<<16)|(pay[22]<<8)|pay[23]);
                    if (nlen > 0 && len >= (int)(24 + nlen)) {
                        int copy = (nlen < sizeof(desktop_name)-1) ? (int)nlen : (int)sizeof(desktop_name)-1;
                        memcpy(desktop_name, pay+24, copy);
                        desktop_name[copy] = '\0';
                    }
                }
                has_server_init = true;
                state           = VNC_S_ESTABLISHED;
            }
            break;

        case VNC_S_ESTABLISHED:
            // 握手完成，不再解析 RFB 消息
            break;

        default:
            break;
        }
    }

    void emit_log(FILE* f) const {
        if (!is_vnc) { fprintf(f, "[VNC] 非 VNC 流\n"); return; }
        fprintf(f, "=== VNC / RFB FLOW ===\n");
        fprintf(f, "  State: %d  Protocol: %u.%u\n", (int)state, proto_major, proto_minor);

        if (has_server_banner) fprintf(f, "  Server Banner: %.11s\n", server_banner);
        if (has_client_banner) fprintf(f, "  Client Banner: %.11s\n", client_banner);

        if (has_sec_offer) {
            if (proto_major == 3 && proto_minor == 3) {
                fprintf(f, "  Security (v3.3 forced): %s (%u)\n",
                        vnc_sec_name(sel_sec_type), sec_type_33);
            } else {
                fprintf(f, "  Security Offer (%d types):", n_sec_types);
                for (int i = 0; i < n_sec_types; i++)
                    fprintf(f, " %s(%u)", vnc_sec_name(sec_types[i]), sec_types[i]);
                fprintf(f, "\n");
            }
        }
        if (has_sec_choice)
            fprintf(f, "  Client Selected: %s (%u)\n", vnc_sec_name(sel_sec_type), sel_sec_type);
        if (has_challenge)
            fprintf(f, "  VNC Auth Challenge: %02x%02x%02x%02x...\n",
                    vnc_challenge[0], vnc_challenge[1], vnc_challenge[2], vnc_challenge[3]);
        if (has_auth_result) {
            if (!auth_failed)
                fprintf(f, "  Authentication: OK\n");
            else {
                const char* r = (auth_result==1)?"Failed":(auth_result==2)?"TooMany":"Unknown";
                fprintf(f, "  Authentication: %s", r);
                if (auth_fail_reason[0]) fprintf(f, " (%s)", auth_fail_reason);
                fprintf(f, "\n");
            }
        }
        if (has_client_init)
            fprintf(f, "  Shared Session: %s\n", shared_flag ? "yes" : "no (exclusive)");
        if (has_server_init) {
            fprintf(f, "  Framebuffer: %ux%u\n", fb_width, fb_height);
            fprintf(f, "  Pixel Format: %u bpp  depth=%u  BigEndian=%d  TrueColor=%d\n",
                    bits_per_pixel, depth, big_endian_flag, true_colour_flag);
            if (true_colour_flag)
                fprintf(f, "    R: max=%u shift=%u  G: max=%u shift=%u  B: max=%u shift=%u\n",
                        red_max, red_shift, green_max, green_shift, blue_max, blue_shift);
            if (desktop_name[0])
                fprintf(f, "  Desktop Name: %s\n", desktop_name);
        }
        fprintf(f, "---\n");
    }
};
