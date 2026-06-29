/**
 * vpn_detect.h  ——  广义 VPN 协议识别库（纯 C99，Header Only 声明）
 *
 * 支持识别协议（按可信度从高到低）：
 *   WireGuard        —— UDP，固定 handshake 消息格式，可达 HIGH 置信度
 *   OpenVPN          —— UDP/TCP，opcode 字节 + session-id 结构，HIGH/MED
 *   Shadowsocks      —— 熵分析 + 包长特征（Clash 底层），MED
 *   VMess (V2Ray)    —— WebSocket/gRPC/HTTP2 明文 header，MED；裸 TCP 熵，LOW
 *   VLESS (V2Ray)    —— 同 VMess
 *   Trojan           —— TLS + 首包大小特征，LOW（无密钥无法确认）
 *   Psiphon          —— OSSH（随机前缀+SSH banner）、meek（HTTP CDN 前置）、MED
 *   Lantern          —— lampshade 魔术头、OQUIC 特征，MED
 *   Clash            —— HTTP 代理 header 含 Clash UA / 管理端口特征，MED
 *
 * 用法（配合 libpcap 或任意 pcap 框架）：
 *   // --- 单包无状态检测 ---
 *   VpnResult r = vpn_detect_packet(payload, len, ip_proto, sport, dport);
 *   if (r.proto != VPN_UNKNOWN) printf("%s\n", vpn_proto_name(r.proto));
 *
 *   // --- 流级别有状态检测（更准确）---
 *   VpnFlow flow;
 *   vpn_flow_init(&flow, sport, dport, ip_proto);
 *   vpn_flow_update(&flow, payload, len, is_fwd, ts);
 *   VpnResult r;
 *   vpn_flow_result(&flow, &r);
 *   vpn_flow_emit(&flow, stdout);
 *
 * 编译：
 *   gcc -O2 -std=c99 your_app.c vpn_detect.c -lpcap -lm -o vpn_app
 *   # 或在 C++ 工程中：
 *   g++ -O2 -std=c++17 your_app.cpp vpn_detect.c -lpcap -lm -o vpn_app
 */
#pragma once

#ifdef __cplusplus
#  include <cstdint>
#  include <cstdio>
#else
#  include <stdint.h>
#  include <stdio.h>
#endif
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * 协议 ID
 * ============================================================ */
typedef enum VpnProto {
    VPN_UNKNOWN     = 0,
    VPN_WIREGUARD   = 1,  /* WireGuard (RFC draft)                       */
    VPN_OPENVPN     = 2,  /* OpenVPN UDP/TCP                             */
    VPN_SHADOWSOCKS = 3,  /* Shadowsocks（Clash/SSR 等底层）              */
    VPN_VMESS       = 4,  /* VMess (V2Ray / Xray / Clash Meta)           */
    VPN_VLESS       = 5,  /* VLESS (V2Ray / Xray / Clash Meta)           */
    VPN_TROJAN      = 6,  /* Trojan (TLS 伪装)                           */
    VPN_V2RAY       = 7,  /* V2Ray/Xray 通用（子协议不明）               */
    VPN_CLASH       = 8,  /* Clash / Clash.Meta 代理特征                 */
    VPN_PSIPHON     = 9,  /* Psiphon (OSSH / meek / SSH)                 */
    VPN_LANTERN     = 10, /* Lantern (lampshade / OQUIC)                 */
    VPN_HYSTERIA    = 11, /* Hysteria/Hysteria2 (QUIC over non-443 UDP)  */
    VPN_PROTO_COUNT = 12,
} VpnProto;

/* ============================================================
 * 置信度
 * ============================================================ */
typedef enum VpnConf {
    VPN_CONF_NONE = 0, /* 未识别                                        */
    VPN_CONF_LOW  = 1, /* 统计特征 / 端口启发，误报率较高                */
    VPN_CONF_MED  = 2, /* 协议特征部分匹配                              */
    VPN_CONF_HIGH = 3, /* 明确协议签名，误报率极低                      */
} VpnConf;

/* ============================================================
 * 传输层封装类型
 * ============================================================ */
typedef enum VpnTransport {
    VPN_TRANS_UNKNOWN  = 0,
    VPN_TRANS_UDP      = 1,
    VPN_TRANS_TCP      = 2,
    VPN_TRANS_TLS      = 3,  /* TLS over TCP                            */
    VPN_TRANS_WS       = 4,  /* WebSocket                               */
    VPN_TRANS_WSS      = 5,  /* WebSocket over TLS                      */
    VPN_TRANS_HTTP2    = 6,  /* HTTP/2                                  */
    VPN_TRANS_GRPC     = 7,  /* gRPC over HTTP/2                        */
    VPN_TRANS_QUIC     = 8,  /* QUIC                                    */
    VPN_TRANS_SSH      = 9,  /* SSH tunnel                              */
    VPN_TRANS_MEEK     = 10, /* meek (HTTP CDN 前置)                    */
} VpnTransport;

/* ============================================================
 * WireGuard 消息类型（RFC 9000 draft）
 * ============================================================ */
#define WG_MSG_INITIATION  1u   /* Handshake Initiation, 148 bytes      */
#define WG_MSG_RESPONSE    2u   /* Handshake Response,   92 bytes       */
#define WG_MSG_COOKIE      3u   /* Cookie Reply,         64 bytes       */
#define WG_MSG_DATA        4u   /* Data packet,          >= 32 bytes    */

/* ============================================================
 * OpenVPN 操作码（高 5 位）
 * ============================================================ */
#define OVPN_P_CONTROL_HARD_RESET_CLIENT_V1  1
#define OVPN_P_CONTROL_HARD_RESET_SERVER_V1  2
#define OVPN_P_CONTROL_SOFT_RESET_V1         3
#define OVPN_P_CONTROL_V1                    4
#define OVPN_P_ACK_V1                        5
#define OVPN_P_DATA_V1                       6
#define OVPN_P_CONTROL_HARD_RESET_CLIENT_V2  7
#define OVPN_P_CONTROL_HARD_RESET_SERVER_V2  8
#define OVPN_P_DATA_V2                       9

/* ============================================================
 * 已知 VPN 默认端口（仅作辅助提示）
 * ============================================================ */
#define PORT_WIREGUARD     51820u
#define PORT_OPENVPN_UDP   1194u
#define PORT_OPENVPN_TCP   1194u
#define PORT_SS_DEFAULT    8388u
#define PORT_PSIPHON_SSH   22u    /* Psiphon SSH transport              */
#define PORT_CLASH_HTTP    7890u  /* Clash 本地 HTTP 代理               */
#define PORT_CLASH_SOCKS   7891u  /* Clash 本地 SOCKS5 代理             */
#define PORT_CLASH_MIXED   7890u  /* Clash Mixed port                   */
#define PORT_HYSTERIA      8080u  /* Hysteria common port (可任意)      */

/* QUIC v1/v2 版本号 */
#define QUIC_VER_1         0x00000001u
#define QUIC_VER_2         0x6b3343cfu

/* 熵检测阈值（bits/byte，超过此值视为"高熵随机数据"）
 * 注：128字节随机样本经验熵约 6.0-7.0，真随机数据约 6.5+，
 * 明文协议（HTTP/TLS握手明文）< 5.5。*/
#define VPN_ENTROPY_THRESH      6.0   /* 流量高熵总阈值                  */
#define VPN_ENTROPY_THRESH_SS   6.0   /* Shadowsocks 专用（偏低防漏报）  */
#define VPN_ENTROPY_THRESH_OSSH 4.8   /* OSSH 前缀最低熵（字节数少）     */

/* ============================================================
 * 单次检测结果
 * ============================================================ */
typedef struct VpnResult {
    VpnProto      proto;          /* 识别到的协议                       */
    VpnConf       confidence;     /* 置信度                             */
    VpnTransport  transport;      /* 传输层封装                         */
    double        entropy;        /* 本包 payload 字节熵（bits/byte）   */
    char          detail[192];    /* 人类可读的匹配说明                 */
} VpnResult;

/* ============================================================
 * WireGuard 流信息
 * ============================================================ */
typedef struct WgFlowInfo {
    uint8_t  seen_types;          /* bitmask: bit(type-1)               */
    uint32_t sender_index;        /* type-1 中的 sender index           */
    uint32_t receiver_index;      /* type-2 中的 sender index           */
    uint8_t  peer_pub_key[32];    /* type-1 unencrypted_ephemeral       */
    uint32_t data_pkt_cnt;
    bool     handshake_done;
} WgFlowInfo;

/* ============================================================
 * OpenVPN 流信息
 * ============================================================ */
typedef struct OvpnFlowInfo {
    uint8_t  first_opcode;        /* 首包操作码（1-9）                  */
    uint8_t  seen_opcodes;        /* bitmask of seen opcodes            */
    uint8_t  session_id[8];       /* 客户端 session ID                  */
    bool     saw_reset_client;
    bool     saw_reset_server;
    bool     saw_tls_data;        /* 已见 TLS 数据包                    */
    bool     is_tcp;              /* TCP or UDP mode                    */
} OvpnFlowInfo;

/* ============================================================
 * Shadowsocks 流信息
 * ============================================================ */
typedef struct SsFlowInfo {
    uint8_t  salt[32];            /* AEAD: 前32字节盐值                 */
    bool     is_aead;             /* AEAD or stream cipher              */
    double   entropy;             /* 首包熵                             */
    uint16_t first_pkt_len;       /* 首包大小                           */
} SsFlowInfo;

/* ============================================================
 * VMess / VLESS / V2Ray 流信息
 * ============================================================ */
typedef struct VmessFlowInfo {
    bool     is_websocket;
    bool     is_grpc;
    bool     is_http2;
    char     http_path[128];      /* WebSocket 路径                     */
    char     http_host[128];
    char     grpc_service[128];   /* gRPC 服务名                        */
    double   entropy;
} VmessFlowInfo;

/* ============================================================
 * Psiphon 流信息
 * ============================================================ */
typedef struct PsiphonFlowInfo {
    bool     is_ossh;             /* Obfuscated SSH                     */
    bool     is_meek;             /* meek CDN 前置                      */
    bool     is_ssh;              /* 标准 SSH transport                 */
    char     ssh_banner[128];     /* 截获的 SSH banner                  */
    char     meek_host[128];      /* meek Host 域名                     */
    char     meek_ua[128];        /* User-Agent                         */
    uint8_t  ossh_prefix_len;     /* OSSH 随机前缀字节数                */
} PsiphonFlowInfo;

/* ============================================================
 * Hysteria / QUIC-based VPN 流信息
 * ============================================================ */
typedef struct HysteriaFlowInfo {
    bool     is_quic;             /* 确认为 QUIC 协议                   */
    bool     is_non_443;          /* 非 443 端口（VPN 指标）             */
    uint32_t quic_version;        /* QUIC 版本号                        */
    uint8_t  dcid[20];            /* QUIC Destination Connection ID     */
    uint8_t  dcid_len;
    uint8_t  scid[20];            /* QUIC Source Connection ID          */
    uint8_t  scid_len;
    uint32_t init_pkt_cnt;        /* Initial 包数量                     */
    uint32_t data_pkt_cnt;        /* Short Header（数据）包数量         */
    bool     saw_handshake;       /* 见过 Handshake 包                  */
} HysteriaFlowInfo;

/* ============================================================
 * Lantern 流信息
 * ============================================================ */
typedef struct LanternFlowInfo {
    bool     is_lampshade;        /* lampshade 协议                     */
    bool     is_oquic;            /* OQUIC 变体                         */
    uint8_t  lamp_msg_type;       /* lampshade 消息类型字节             */
} LanternFlowInfo;

/* ============================================================
 * 每流检测状态（有状态流级别检测）
 * ============================================================ */
typedef struct VpnFlow {
    /* 流基本信息 */
    uint8_t  ip_proto;            /* 6=TCP, 17=UDP                      */
    uint16_t src_port, dst_port;
    uint32_t n_pkts;
    uint32_t n_fwd_pkts;
    uint32_t n_bwd_pkts;
    double   first_ts;
    double   last_ts;

    /* 当前最佳识别结果 */
    VpnProto     proto;
    VpnConf      confidence;
    VpnTransport transport;

    /* 各协议子状态 */
    WgFlowInfo       wg;
    OvpnFlowInfo     ovpn;
    SsFlowInfo       ss;
    VmessFlowInfo    vmess;
    PsiphonFlowInfo  psiphon;
    LanternFlowInfo  lantern;
    HysteriaFlowInfo hysteria;

    /* 通用统计 */
    double   entropy_sum;
    int      entropy_cnt;
    uint16_t pkt_len_seq[16];     /* 前16包的包长序列                   */
    bool     has_tls;             /* 本流出现过 TLS ClientHello/record  */
    bool     has_http;            /* 本流出现过 HTTP 明文               */
    bool     on_known_vpn_port;   /* dst_port 命中已知 VPN 端口         */

    char     detail[256];
} VpnFlow;

/* ============================================================
 * 函数声明
 * ============================================================ */

/**
 * 单包无状态检测。
 * @param payload  L4（TCP/UDP）payload 指针
 * @param len      payload 字节数
 * @param ip_proto IP 协议号（6=TCP, 17=UDP）
 * @param sport    源端口（主机字节序）
 * @param dport    目的端口（主机字节序）
 */
VpnResult vpn_detect_packet(const uint8_t *payload, int len,
                             uint8_t ip_proto,
                             uint16_t sport, uint16_t dport);

/** 初始化流状态 */
void vpn_flow_init(VpnFlow *f, uint16_t sport, uint16_t dport, uint8_t ip_proto);

/**
 * 更新流状态（每收到一个 TCP/UDP payload 调用一次）。
 * @param is_fwd  true = 客户端→服务端方向
 * @param ts      绝对时间戳（秒）
 */
void vpn_flow_update(VpnFlow *f, const uint8_t *payload, int len,
                     bool is_fwd, double ts);

/** 将流当前识别结果写入 r（不输出到文件） */
void vpn_flow_result(const VpnFlow *f, VpnResult *r);

/** 以结构化文本输出流信息到 f（如 stdout 或 .log 文件）*/
void vpn_flow_emit(const VpnFlow *f, FILE *fp);

/* ---- 单协议无状态检测函数（可独立调用）---- */
VpnConf vpn_detect_wireguard  (const uint8_t *p, int len, uint8_t proto);
VpnConf vpn_detect_openvpn    (const uint8_t *p, int len, uint8_t proto, bool *is_tcp_out);
VpnConf vpn_detect_shadowsocks(const uint8_t *p, int len, uint16_t dport, double *ent_out);
VpnConf vpn_detect_vmess      (const uint8_t *p, int len, VpnTransport *tr_out, char *path_out, int path_max);
VpnConf vpn_detect_vless      (const uint8_t *p, int len, VpnTransport *tr_out);
VpnConf vpn_detect_trojan     (const uint8_t *p, int len, uint16_t dport, bool has_tls);
VpnConf vpn_detect_psiphon    (const uint8_t *p, int len, uint8_t proto, PsiphonFlowInfo *info_out);
VpnConf vpn_detect_lantern    (const uint8_t *p, int len, uint8_t proto, LanternFlowInfo *info_out);
VpnConf vpn_detect_clash      (const uint8_t *p, int len, uint16_t sport, uint16_t dport);
VpnConf vpn_detect_hysteria   (const uint8_t *p, int len, uint8_t proto,
                                uint16_t sport, uint16_t dport, HysteriaFlowInfo *info_out);

/* ---- 工具函数 ---- */
double      vpn_entropy     (const uint8_t *data, int len);
bool        vpn_is_tls      (const uint8_t *p, int len);
bool        vpn_is_http     (const uint8_t *p, int len);
const char *vpn_proto_name  (VpnProto proto);
const char *vpn_conf_name   (VpnConf conf);
const char *vpn_transport_name(VpnTransport tr);

#ifdef __cplusplus
}
#endif
