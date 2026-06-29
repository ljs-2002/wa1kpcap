/**
 * im_detect.h  ——  即时通讯（IM）应用 / 协议识别库
 *
 * 支持识别（按可信度从高到低）：
 *   MTProto          —— Telegram 传输层签名（0xEF / 0xEEEEEEEE / 0xDDDDDDDD 等）
 *   Telegram         —— TLS SNI / User-Agent / DC 端口组合
 *   WhatsApp         —— funXMPP 二进制帧 + TLS SNI (*.whatsapp.net)
 *   Signal           —— TLS SNI (chat.signal.org) + Noise 握手特征
 *   Facebook Messenger —— MQTT-over-TLS (edge-mqtt.facebook.com)
 *   WeChat           —— mmtls / 微信域名 SNI
 *   LINE             —— line.me / legy.line-apps.com SNI
 *   Viber            —— viber.com SNI + 二进制协议
 *   XMPP             —— Jabber XML 流 (<stream:stream)
 *   Skype/Teams      —— skype.com / teams.microsoft.com SNI
 *   Discord          —— discord.com / gateway WebSocket Upgrade
 *   Slack            —— slack.com / wss-primary SNI
 *   Wire             —— wire.com / prod-nginz-https SNI
 *   Generic IM       —— 高熵 TLS + IM 常见端口，置信度 LOW
 *
 * 用法：
 *   ImResult r = im_detect_packet(payload, len, ip_proto, sport, dport);
 *   ImFlow flow;
 *   im_flow_init(&flow, sport, dport, ip_proto);
 *   im_flow_update(&flow, payload, len, is_fwd, ts);
 *   im_flow_emit(&flow, stdout);
 *
 * 编译：
 *   g++ -O2 -std=c++17 im_detect.cpp -c -lm
 *   g++ -O3 im_extractor.cpp im_detect.cpp -lpcap -lm -o im_extractor
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
 * 协议 / 应用 ID
 * ============================================================ */
typedef enum ImProto {
    IM_UNKNOWN          = 0,
    IM_MTPROTO          = 1,  /* Telegram MTProto 传输层               */
    IM_TELEGRAM         = 2,  /* Telegram 应用（SNI/UA/DC 综合）       */
    IM_WHATSAPP         = 3,  /* WhatsApp (funXMPP / Noise)            */
    IM_SIGNAL           = 4,  /* Signal                                */
    IM_FB_MESSENGER     = 5,  /* Facebook Messenger (MQTT)           */
    IM_WECHAT           = 6,  /* 微信 / WeChat (mmtls)                 */
    IM_LINE             = 7,  /* LINE                                  */
    IM_VIBER            = 8,  /* Viber                                 */
    IM_XMPP             = 9,  /* 通用 XMPP (Jabber)                    */
    IM_SKYPE            = 10, /* Skype / Microsoft Teams               */
    IM_DISCORD          = 11, /* Discord                               */
    IM_SLACK            = 12, /* Slack                                 */
    IM_WIRE             = 13, /* Wire                                  */
    IM_GENERIC          = 14, /* 未细分 IM（TLS+端口启发）             */
    IM_PROTO_COUNT      = 15,
} ImProto;

typedef enum ImConf {
    IM_CONF_NONE = 0,
    IM_CONF_LOW  = 1,
    IM_CONF_MED  = 2,
    IM_CONF_HIGH = 3,
} ImConf;

typedef enum ImTransport {
    IM_TRANS_UNKNOWN = 0,
    IM_TRANS_TCP     = 1,
    IM_TRANS_UDP     = 2,
    IM_TRANS_TLS     = 3,
    IM_TRANS_WS      = 4,
    IM_TRANS_WSS     = 5,
    IM_TRANS_MQTT    = 6,
    IM_TRANS_QUIC    = 7,
    IM_TRANS_XMPP    = 8,
} ImTransport;

/* 常见 IM 端口 */
#define IM_PORT_HTTPS       443u
#define IM_PORT_XMPP        5222u
#define IM_PORT_XMPP_ALT    5223u
#define IM_PORT_WA_ALT1     4244u
#define IM_PORT_WA_ALT2     5242u
#define IM_PORT_TELEGRAM    443u
#define IM_PORT_TELEGRAM2   5222u
#define IM_PORT_MQTT        8883u

#define IM_ENTROPY_THRESH   6.0

/* ============================================================
 * 单次检测结果
 * ============================================================ */
typedef struct ImResult {
    ImProto      proto;
    ImConf       confidence;
    ImTransport  transport;
    double       entropy;
    char         detail[192];
} ImResult;

/* ============================================================
 * MTProto / Telegram 流信息
 * ============================================================ */
typedef struct MtprotoFlowInfo {
    uint8_t  transport_type;   /* 1=abridged 2=intermediate 3=padded 4=full 5=obfuscated */
    bool     saw_abridged;     /* 首字节 0xEF                              */
    bool     saw_intermediate; /* 0xEEEEEEEE                               */
    bool     saw_padded;       /* 0xDDDDDDDD                               */
    bool     saw_obfuscated;   /* 64-byte random obfuscation header        */
    bool     saw_fake_tls;     /* 伪装 TLS ClientHello（MTProxy 特征）     */
    uint16_t fake_tls_len;     /* 伪装 ClientHello 长度（通常 517）        */
    char     tls_sni[128];     /* TLS SNI（若走 TLS）                      */
    char     user_agent[128];
    uint8_t  dc_id_hint;       /* obfuscated header 中可能的 DC id         */
} MtprotoFlowInfo;

/* ============================================================
 * WhatsApp 流信息
 * ============================================================ */
typedef struct WhatsappFlowInfo {
    bool     saw_funxmpp;      /* 二进制 XMPP token 帧                   */
    bool     saw_noise;        /* Noise 握手 ("WA" prologue)             */
    bool     saw_stanza;       /* stanza 结构特征                        */
    char     tls_sni[128];
    uint8_t  token_byte;       /* funXMPP 首 token                       */
} WhatsappFlowInfo;

/* ============================================================
 * Signal 流信息
 * ============================================================ */
typedef struct SignalFlowInfo {
    char     tls_sni[128];
    bool     saw_noise;
    bool     saw_protobuf;     /* 高熵 protobuf 特征                       */
} SignalFlowInfo;

/* ============================================================
 * MQTT Messenger (Facebook) 流信息
 * ============================================================ */
typedef struct MqttImFlowInfo {
    bool     saw_connect;      /* MQTT CONNECT                           */
    char     mqtt_client_id[64];
    char     tls_sni[128];
    uint8_t  mqtt_version;
} MqttImFlowInfo;

/* ============================================================
 * XMPP 流信息
 * ============================================================ */
typedef struct XmppFlowInfo {
    char     stream_to[128];   /* to="domain"                            */
    char     stream_from[128];
    char     xmlns[64];
    bool     saw_starttls;
    bool     saw_auth;
    char     auth_mechanism[32];
} XmppFlowInfo;

/* ============================================================
 * 通用 TLS SNI 流信息（多应用共享）
 * ============================================================ */
typedef struct TlsSniFlowInfo {
    char     sni[128];
    char     alpn[32];
    bool     saw_client_hello;
} TlsSniFlowInfo;

/* ============================================================
 * 每流检测状态
 * ============================================================ */
typedef struct ImFlow {
    uint8_t  ip_proto;
    uint16_t src_port, dst_port;
    uint32_t server_ip;        /* 服务端 IP（用于 DC / MTProxy 判定）      */
    uint16_t server_port;      /* 服务端端口                               */
    uint32_t n_pkts;
    uint32_t n_fwd_pkts, n_bwd_pkts;
    double   first_ts, last_ts;

    ImProto     proto;
    ImConf      confidence;
    ImTransport transport;

    MtprotoFlowInfo  mtproto;
    WhatsappFlowInfo whatsapp;
    SignalFlowInfo   signal;
    MqttImFlowInfo   mqtt;
    XmppFlowInfo     xmpp;
    TlsSniFlowInfo   tls;

    double   entropy_sum;
    int      entropy_cnt;
    bool     has_tls;
    bool     has_http;
    bool     has_websocket;
    char     http_host[128];
    char     http_ua[128];

    char     detail[256];
} ImFlow;

/* ============================================================
 * API
 * ============================================================ */
ImResult im_detect_packet(const uint8_t *payload, int len,
                           uint8_t ip_proto, uint16_t sport, uint16_t dport);

void im_flow_init(ImFlow *f, uint16_t sport, uint16_t dport, uint8_t ip_proto);
/** 设置流的服务端地址（pcap 回调中首包确定） */
void im_flow_set_server(ImFlow *f, uint32_t server_ip, uint16_t server_port);
void im_flow_update(ImFlow *f, const uint8_t *payload, int len,
                    bool is_fwd, double ts);
void im_flow_result(const ImFlow *f, ImResult *r);
void im_flow_emit(const ImFlow *f, FILE *fp);

/* 单协议检测 */
ImConf im_detect_mtproto   (const uint8_t *p, int len, uint8_t proto, MtprotoFlowInfo *info);
ImConf im_detect_telegram_fake_tls(const uint8_t *p, int len,
                                    uint32_t server_ip, uint16_t server_port,
                                    MtprotoFlowInfo *info);
bool   im_is_telegram_dc_ip(uint32_t ip);
ImConf im_detect_whatsapp  (const uint8_t *p, int len, uint8_t proto, WhatsappFlowInfo *info);
ImConf im_detect_signal     (const uint8_t *p, int len, SignalFlowInfo *info);
ImConf im_detect_messenger (const uint8_t *p, int len, uint8_t proto, MqttImFlowInfo *info);
ImConf im_detect_wechat    (const uint8_t *p, int len);
ImConf im_detect_line      (const uint8_t *p, int len);
ImConf im_detect_viber     (const uint8_t *p, int len);
ImConf im_detect_xmpp      (const uint8_t *p, int len, XmppFlowInfo *info);
ImConf im_detect_discord   (const uint8_t *p, int len, uint16_t dport);
ImConf im_detect_by_sni    (const char *sni, ImProto *proto_out, ImConf *conf_out);

/* 工具 */
double      im_entropy          (const uint8_t *data, int len);
bool        im_is_tls           (const uint8_t *p, int len);
bool        im_is_http          (const uint8_t *p, int len);
bool        im_tls_parse_sni    (const uint8_t *p, int len, char *sni, int sni_max);
bool        im_tls_parse_alpn   (const uint8_t *p, int len, char *alpn, int alpn_max);
const char *im_proto_name       (ImProto p);
const char *im_conf_name        (ImConf c);
const char *im_transport_name   (ImTransport t);

#ifdef __cplusplus
}
#endif
