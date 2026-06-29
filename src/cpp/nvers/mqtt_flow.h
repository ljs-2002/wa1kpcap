/**
 * mqtt_flow.h  ——  MQTT 协议深度字段解析（Header-Only）
 *
 * 标准：OASIS MQTT 3.1 / 3.1.1 (ISO 20922) / 5.0
 * 默认端口：TCP 1883 (plain), 8883 (TLS), 1884 (WebSocket)
 *
 * 提取的元信息：
 *   ─ 连接 (CONNECT / CONNACK) ─
 *   protocol_name    ("MQTT" / "MQIsdp")
 *   protocol_level   (3=3.1, 4=3.1.1, 5=5.0)
 *   protocol_version_str  ("3.1" / "3.1.1" / "5.0")
 *   client_id
 *   clean_session / clean_start (v5)
 *   keep_alive_secs
 *   will_flag, will_qos, will_retain
 *   will_topic, will_message_len
 *   has_username, has_password
 *   username
 *   connack_session_present
 *   connack_return_code     (v3/v4: 0-5)
 *   connack_reason_code     (v5: 0x00-0xFF)
 *   connack_reason_str
 *   ─ 发布 (PUBLISH) ─
 *   publish_topics[MAX_TOPICS]   (去重后的 topic 名)
 *   topic_cnt
 *   qos0_cnt, qos1_cnt, qos2_cnt
 *   retain_cnt, dup_cnt
 *   total_publish_cnt
 *   publish_payload_total_bytes
 *   max_payload_bytes, min_payload_bytes
 *   avg_payload_bytes
 *   ─ 订阅 (SUBSCRIBE / SUBACK) ─
 *   sub_topics[MAX_TOPICS]   (订阅的 topic 过滤器)
 *   sub_cnt
 *   unsub_cnt
 *   suback_granted_qos[3]   (各 QoS 级别授权次数)
 *   ─ QoS 流控 ─
 *   puback_cnt, pubrec_cnt, pubrel_cnt, pubcomp_cnt
 *   ─ 控制包 ─
 *   pingreq_cnt, pingresp_cnt
 *   disconnect_cnt
 *   auth_cnt                (仅 MQTT 5.0)
 *   ─ MQTT 5.0 属性（Properties）─
 *   v5_session_expiry_interval
 *   v5_receive_maximum
 *   v5_max_packet_size
 *   v5_topic_alias_maximum
 *   v5_request_response_info
 *   v5_request_problem_info
 *   v5_user_properties[8]   (key=value 对)
 *   v5_auth_method
 *   v5_response_topic
 *   v5_correlation_data_len
 *   ─ 流统计 ─
 *   total_pkts_cli, total_pkts_srv
 *   bytes_cli, bytes_srv
 *   packet_type_cnt[16]     (各包类型计数)
 *   first_ts, last_ts
 *   idle_time_max_ms        (最长空闲间隔)
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <algorithm>

/* ============================================================
 * MQTT 包类型常量
 * ============================================================ */
#define MQTT_CONNECT       1u
#define MQTT_CONNACK       2u
#define MQTT_PUBLISH       3u
#define MQTT_PUBACK        4u
#define MQTT_PUBREC        5u
#define MQTT_PUBREL        6u
#define MQTT_PUBCOMP       7u
#define MQTT_SUBSCRIBE     8u
#define MQTT_SUBACK        9u
#define MQTT_UNSUBSCRIBE  10u
#define MQTT_UNSUBACK     11u
#define MQTT_PINGREQ      12u
#define MQTT_PINGRESP     13u
#define MQTT_DISCONNECT   14u
#define MQTT_AUTH         15u

static inline const char *mqtt_pkt_type_name(uint8_t t) {
    static const char *n[] = {
        "RESERVED","CONNECT","CONNACK","PUBLISH","PUBACK","PUBREC","PUBREL",
        "PUBCOMP","SUBSCRIBE","SUBACK","UNSUBSCRIBE","UNSUBACK",
        "PINGREQ","PINGRESP","DISCONNECT","AUTH"
    };
    return t < 16 ? n[t] : "?";
}

/* CONNACK return codes (v3.1.1) */
static inline const char *mqtt_connack_rc(uint8_t rc) {
    switch (rc) {
    case 0: return "Accepted";
    case 1: return "Refused-UnacceptableProtocol";
    case 2: return "Refused-IdentifierRejected";
    case 3: return "Refused-ServerUnavailable";
    case 4: return "Refused-BadUsernamePassword";
    case 5: return "Refused-NotAuthorized";
    default: return "Unknown";
    }
}

/* MQTT 5.0 Reason Codes (common) */
static inline const char *mqtt_v5_reason(uint8_t rc) {
    switch (rc) {
    case 0x00: return "Success";
    case 0x04: return "DisconnectWithWillMessage";
    case 0x10: return "NoMatchingSubscribers";
    case 0x80: return "UnspecifiedError";
    case 0x81: return "MalformedPacket";
    case 0x82: return "ProtocolError";
    case 0x83: return "ImplementationSpecificError";
    case 0x84: return "UnsupportedProtocolVersion";
    case 0x85: return "ClientIdentifierNotValid";
    case 0x86: return "BadUserNameOrPassword";
    case 0x87: return "NotAuthorized";
    case 0x88: return "ServerUnavailable";
    case 0x89: return "ServerBusy";
    case 0x8A: return "Banned";
    case 0x8D: return "KeepAliveTimeout";
    case 0x8E: return "SessionTakenOver";
    case 0x8F: return "TopicFilterInvalid";
    case 0x90: return "TopicNameInvalid";
    case 0x97: return "QuotaExceeded";
    case 0x99: return "PayloadFormatInvalid";
    case 0x9A: return "RetainNotSupported";
    case 0x9B: return "QoSNotSupported";
    case 0x9C: return "UseAnotherServer";
    case 0x9D: return "ServerMoved";
    case 0x9F: return "ConnectionRateExceeded";
    default:   return "Reserved";
    }
}

/* ============================================================
 * 快速识别：是否为 MQTT
 * ============================================================ */
static inline bool detect_mqtt(const uint8_t *p, int len) {
    if (len < 4) return false;
    /* CONNECT 包: type=1, protocol_name=MQTT 或 MQIsdp */
    uint8_t fh = p[0];
    uint8_t pt = (fh >> 4) & 0x0F;
    if (pt == MQTT_CONNECT) {
        /* 跳过 Remaining Length（1-4字节）*/
        int ri = 1, mult = 1; uint32_t rl = 0;
        while (ri < len && ri < 5) {
            rl += (p[ri] & 0x7F) * (uint32_t)mult;
            if (!(p[ri] & 0x80)) { ri++; break; }
            mult *= 128; ri++;
        }
        if (ri + 6 < len) {
            uint16_t pname_len = ((uint16_t)p[ri]<<8) | p[ri+1];
            if (pname_len == 4 && memcmp(p+ri+2, "MQTT",  4)==0) return true;
            if (pname_len == 6 && memcmp(p+ri+2, "MQIsdp",6)==0) return true;
        }
    }
    /* 其他包类型: type 1-15 */
    return (pt >= 1 && pt <= 15);
}

/* ============================================================
 * 内部辅助：解码 Remaining Length（VarInt）
 * 返回消耗的字节数，-1=失败
 * ============================================================ */
static inline int mqtt__decode_remlen(const uint8_t *p, int max,
                                       uint32_t *out) {
    uint32_t val = 0; uint32_t mult = 1; int i = 0;
    do {
        if (i >= max || i >= 4) return -1;
        val += ((uint32_t)(p[i] & 0x7F)) * mult;
        mult *= 128;
    } while (p[i++] & 0x80);
    *out = val;
    return i;
}

/* 读取 MQTT UTF-8 string (uint16 len + bytes) */
static inline int mqtt__read_str(const uint8_t *p, int rem,
                                  char *out, int outsz) {
    if (rem < 2) return -1;
    uint16_t slen = ((uint16_t)p[0]<<8) | p[1];
    if ((int)slen > rem - 2) return -1;
    int cp = slen < (uint16_t)(outsz-1) ? slen : (uint16_t)(outsz-1);
    memcpy(out, p+2, (size_t)cp);
    out[cp] = '\0';
    return 2 + slen;
}

/* 读取 MQTT binary data (uint16 len + bytes) */
static inline int mqtt__read_bin(const uint8_t *p, int rem, uint32_t *outlen) {
    if (rem < 2) return -1;
    *outlen = ((uint32_t)p[0]<<8) | p[1];
    if ((int)*outlen > rem - 2) return -1;
    return 2 + (int)*outlen;
}

/* ============================================================
 * MQTT 5.0 Properties 解析（简化版，提取关键属性）
 * ============================================================ */
struct MqttV5Props {
    uint32_t session_expiry_interval;
    uint16_t receive_maximum;
    uint32_t max_packet_size;
    uint16_t topic_alias_maximum;
    uint8_t  request_response_info;
    uint8_t  request_problem_info;
    char     auth_method[64];
    char     response_topic[128];
    uint32_t correlation_data_len;
    char     user_props[8][128];   /* "key=value" 格式 */
    uint8_t  user_prop_cnt;
    char     reason_str[128];

    /* 解析 Properties 区（已跳过 properties_length 字节本身）*/
    int parse(const uint8_t *p, int len) {
        memset(this, 0, sizeof *this);
        const uint8_t *end = p + len;
        while (p < end) {
            uint8_t id = *p++;
            switch (id) {
            case 0x11: /* Session Expiry Interval (uint32) */
                if (p+4 > end) return -1;
                session_expiry_interval = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
                                          ((uint32_t)p[2]<<8)|p[3]; p+=4; break;
            case 0x21: /* Receive Maximum (uint16) */
                if (p+2 > end) return -1;
                receive_maximum = ((uint16_t)p[0]<<8)|p[1]; p+=2; break;
            case 0x27: /* Maximum Packet Size (uint32) */
                if (p+4 > end) return -1;
                max_packet_size = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
                                  ((uint32_t)p[2]<<8)|p[3]; p+=4; break;
            case 0x22: /* Topic Alias Maximum (uint16) */
                if (p+2 > end) return -1;
                topic_alias_maximum = ((uint16_t)p[0]<<8)|p[1]; p+=2; break;
            case 0x19: /* Request Response Info (byte) */
                if (p >= end) return -1;
                request_response_info = *p++; break;
            case 0x17: /* Request Problem Info (byte) */
                if (p >= end) return -1;
                request_problem_info = *p++; break;
            case 0x15: { /* Authentication Method (UTF-8) */
                char tmp[64]; int adv = mqtt__read_str(p,(int)(end-p),tmp,sizeof tmp);
                if (adv < 0) return -1;
                snprintf(auth_method, sizeof auth_method, "%s", tmp); p += adv; break;
            }
            case 0x08: { /* Response Topic (UTF-8) */
                char tmp[128]; int adv = mqtt__read_str(p,(int)(end-p),tmp,sizeof tmp);
                if (adv < 0) return -1;
                snprintf(response_topic, sizeof response_topic, "%s", tmp); p += adv; break;
            }
            case 0x09: { /* Correlation Data (binary) */
                uint32_t bl=0; int adv = mqtt__read_bin(p,(int)(end-p),&bl);
                if (adv < 0) return -1;
                correlation_data_len = bl; p += adv; break;
            }
            case 0x26: { /* User Property (UTF-8 pair) */
                char key[64],val[64];
                int a1 = mqtt__read_str(p,(int)(end-p),key,sizeof key); if(a1<0) return -1; p+=a1;
                int a2 = mqtt__read_str(p,(int)(end-p),val,sizeof val); if(a2<0) return -1; p+=a2;
                if (user_prop_cnt < 8)
                    snprintf(user_props[user_prop_cnt++],128,"%s=%s",key,val);
                break;
            }
            case 0x1F: { /* Reason String (UTF-8) */
                char tmp[128]; int adv = mqtt__read_str(p,(int)(end-p),tmp,sizeof tmp);
                if (adv < 0) return -1;
                snprintf(reason_str, sizeof reason_str, "%s", tmp); p += adv; break;
            }
            default: return -1; /* 未知属性，终止 */
            }
        }
        return 0;
    }
};

/* ============================================================
 * MQTT 流记录
 * ============================================================ */
static const int MQTT_MAX_TOPICS = 64;

struct MqttFlowRecord {

    /* ---- 协议版本 ---- */
    char     protocol_name[8];     /* "MQTT" / "MQIsdp"                   */
    uint8_t  protocol_level;       /* 3 / 4 / 5                           */
    char     protocol_version_str[8]; /* "3.1" / "3.1.1" / "5.0"         */

    /* ---- CONNECT ---- */
    char     client_id[128];
    bool     clean_session;        /* v3/v4; v5 中为 clean_start          */
    uint16_t keep_alive_secs;
    bool     will_flag;
    uint8_t  will_qos;
    bool     will_retain;
    char     will_topic[128];
    uint32_t will_message_len;
    bool     has_username;
    bool     has_password;
    char     username[128];

    /* ---- CONNACK ---- */
    bool     connack_session_present;
    uint8_t  connack_return_code;
    char     connack_reason_str[64];

    /* ---- PUBLISH 统计 ---- */
    char     publish_topics[MQTT_MAX_TOPICS][128];
    uint8_t  topic_cnt;
    uint32_t total_publish_cnt;
    uint32_t qos0_cnt, qos1_cnt, qos2_cnt;
    uint32_t retain_cnt, dup_cnt;
    uint64_t publish_payload_bytes;
    uint32_t max_payload_bytes;
    uint32_t min_payload_bytes;

    /* ---- 订阅 ---- */
    char     sub_topics[MQTT_MAX_TOPICS][128];
    uint8_t  sub_topic_cnt;
    uint32_t sub_cnt;
    uint32_t unsub_cnt;
    uint32_t suback_granted[3];    /* granted QoS 0/1/2 计数              */
    uint32_t suback_refused_cnt;

    /* ---- QoS 流控包计数 ---- */
    uint32_t puback_cnt, pubrec_cnt, pubrel_cnt, pubcomp_cnt;

    /* ---- 控制包 ---- */
    uint32_t pingreq_cnt, pingresp_cnt, disconnect_cnt, auth_cnt;

    /* ---- MQTT 5.0 属性 ---- */
    MqttV5Props v5_connect_props;
    bool        v5_props_parsed;

    /* ---- 流统计 ---- */
    uint32_t packet_type_cnt[16];  /* 各包类型计数                        */
    uint32_t total_pkts_cli, total_pkts_srv;
    uint64_t bytes_cli, bytes_srv;
    double   first_ts, last_ts;
    double   idle_time_max_ms;     /* 最长包间隔                          */
    double   _last_ts;

    /* ============================================================
     * 初始化
     * ============================================================ */
    void init() noexcept {
        memset(this, 0, sizeof *this);
        min_payload_bytes = UINT32_MAX;
        first_ts = -1.0; _last_ts = -1.0;
    }

    /* ============================================================
     * 记录 topic（去重后加入列表）
     * ============================================================ */
    void _record_topic(const char *topic, char arr[][128], uint8_t *cnt) {
        for (int i = 0; i < *cnt; i++)
            if (strcmp(arr[i], topic) == 0) return;
        if (*cnt < MQTT_MAX_TOPICS) {
            snprintf(arr[(*cnt)++], 128, "%s", topic);
        }
    }

    /* ============================================================
     * 解析 CONNECT 包（可变头 + payload）
     * p 指向可变头起始，rem 为剩余字节数
     * ============================================================ */
    void _parse_connect(const uint8_t *p, int rem) {
        if (rem < 10) return;
        /* Protocol Name */
        int adv = mqtt__read_str(p, rem, protocol_name, sizeof protocol_name);
        if (adv < 0) return;
        p += adv; rem -= adv;
        if (rem < 4) return;

        /* Protocol Level */
        protocol_level = p[0]; p++; rem--;
        switch (protocol_level) {
        case 3: snprintf(protocol_version_str, sizeof protocol_version_str, "3.1"); break;
        case 4: snprintf(protocol_version_str, sizeof protocol_version_str, "3.1.1"); break;
        case 5: snprintf(protocol_version_str, sizeof protocol_version_str, "5.0"); break;
        default: snprintf(protocol_version_str, sizeof protocol_version_str, "?(%u)", protocol_level);
        }

        /* Connect Flags */
        uint8_t flags = p[0]; p++; rem--;
        has_username   = (flags >> 7) & 1;
        has_password   = (flags >> 6) & 1;
        will_retain    = (flags >> 5) & 1;
        will_qos       = (flags >> 3) & 0x3;
        will_flag      = (flags >> 2) & 1;
        clean_session  = (flags >> 1) & 1;

        /* Keep Alive */
        keep_alive_secs = ((uint16_t)p[0]<<8) | p[1]; p+=2; rem-=2;

        /* MQTT 5.0: Connect Properties */
        if (protocol_level == 5 && rem >= 1) {
            uint32_t prop_len = 0;
            int pladv = mqtt__decode_remlen(p, rem, &prop_len);
            if (pladv > 0 && (int)prop_len <= rem - pladv) {
                v5_connect_props.parse(p + pladv, (int)prop_len);
                v5_props_parsed = true;
                p += pladv + (int)prop_len;
                rem -= pladv + (int)prop_len;
            }
        }

        /* Payload: Client ID */
        if ((adv = mqtt__read_str(p, rem, client_id, sizeof client_id)) < 0) return;
        p += adv; rem -= adv;

        /* Will Topic & Message */
        if (will_flag) {
            if (protocol_level == 5 && rem >= 1) { /* Will Properties */
                uint32_t wpl = 0; int wpladv = mqtt__decode_remlen(p, rem, &wpl);
                if (wpladv > 0) { p += wpladv + (int)wpl; rem -= wpladv + (int)wpl; }
            }
            if ((adv = mqtt__read_str(p, rem, will_topic, sizeof will_topic)) < 0) return;
            p += adv; rem -= adv;
            uint32_t wmlen = 0;
            if ((adv = mqtt__read_bin(p, rem, &wmlen)) < 0) return;
            will_message_len = wmlen;
            p += adv; rem -= adv;
        }

        /* Username */
        if (has_username && rem >= 2) {
            mqtt__read_str(p, rem, username, sizeof username);
        }
    }

    /* ============================================================
     * 解析 PUBLISH 包
     * ============================================================ */
    void _parse_publish(const uint8_t *p, int rem, uint8_t flags) {
        uint8_t qos    = (flags >> 1) & 0x3;
        bool    retain = (flags & 0x1) != 0;
        bool    dup    = (flags >> 3) != 0;

        char topic[128];
        int adv = mqtt__read_str(p, rem, topic, sizeof topic);
        if (adv < 0) return;
        p += adv; rem -= adv;

        _record_topic(topic, publish_topics, &topic_cnt);

        /* Packet ID (QoS 1 or 2) */
        if (qos > 0) {
            if (rem < 2) return;
            p += 2; rem -= 2;
        }

        /* MQTT 5.0 Publish Properties */
        if (protocol_level == 5 && rem >= 1) {
            uint32_t ppl = 0; int ppladv = mqtt__decode_remlen(p, rem, &ppl);
            if (ppladv > 0) { p += ppladv + (int)ppl; rem -= ppladv + (int)ppl; }
        }

        uint32_t payload_len = (uint32_t)std::max(rem, 0);
        total_publish_cnt++;
        publish_payload_bytes += payload_len;
        if (payload_len > max_payload_bytes) max_payload_bytes = payload_len;
        if (payload_len < min_payload_bytes) min_payload_bytes = payload_len;
        if (qos == 0) qos0_cnt++;
        else if (qos == 1) qos1_cnt++;
        else if (qos == 2) qos2_cnt++;
        if (retain) retain_cnt++;
        if (dup)    dup_cnt++;
    }

    /* ============================================================
     * 解析 SUBSCRIBE 包
     * ============================================================ */
    void _parse_subscribe(const uint8_t *p, int rem) {
        if (rem < 2) return;
        p += 2; rem -= 2;  /* skip packet ID */
        if (protocol_level == 5 && rem >= 1) { /* Properties */
            uint32_t pl = 0; int pladv = mqtt__decode_remlen(p, rem, &pl);
            if (pladv > 0) { p += pladv + (int)pl; rem -= pladv + (int)pl; }
        }
        while (rem > 2) {
            char filter[128]; int adv = mqtt__read_str(p, rem, filter, sizeof filter);
            if (adv < 0) break;
            p += adv; rem -= adv;
            if (rem < 1) break;
            sub_cnt++;
            _record_topic(filter, sub_topics, &sub_topic_cnt);
            p++; rem--; /* QoS byte (or subscription options byte in v5) */
        }
    }

    /* ============================================================
     * 每包处理
     * @param data    TCP payload 起始指针
     * @param len     TCP payload 长度
     * @param is_cli  true = 客户端→服务端
     * @param ts      绝对时间戳（秒）
     * ============================================================ */
    void process_pkt(const uint8_t *data, int len,
                     bool is_cli, double ts) noexcept {
        if (len < 2 || !data) return;

        if (first_ts < 0.0) first_ts = ts;
        last_ts = ts;
        if (_last_ts > 0.0) {
            double gap_ms = (ts - _last_ts) * 1000.0;
            if (gap_ms > idle_time_max_ms) idle_time_max_ms = gap_ms;
        }
        _last_ts = ts;

        if (is_cli) total_pkts_cli++; else total_pkts_srv++;
        if (is_cli) bytes_cli += (uint64_t)len; else bytes_srv += (uint64_t)len;

        /* 一个 TCP payload 可能包含多个 MQTT 包 */
        const uint8_t *ptr = data;
        int rem = len;

        while (rem >= 2) {
            uint8_t fh    = ptr[0];
            uint8_t ptype = (fh >> 4) & 0x0F;
            uint8_t flags = fh & 0x0F;

            uint32_t pkt_rem = 0;
            int rl_bytes = mqtt__decode_remlen(ptr+1, rem-1, &pkt_rem);
            if (rl_bytes < 0) break;
            if (1 + rl_bytes + (int)pkt_rem > rem) break; /* 包不完整 */

            if (ptype < 16) packet_type_cnt[ptype]++;

            const uint8_t *vhdr = ptr + 1 + rl_bytes;
            int vrem = (int)pkt_rem;

            switch (ptype) {
            case MQTT_CONNECT:    _parse_connect(vhdr, vrem); break;
            case MQTT_CONNACK:
                if (vrem >= 2) {
                    connack_session_present = (vhdr[0] & 0x01) != 0;
                    connack_return_code = vhdr[1];
                    if (protocol_level == 5) {
                        snprintf(connack_reason_str, sizeof connack_reason_str,
                                 "%s", mqtt_v5_reason(vhdr[1]));
                    } else {
                        snprintf(connack_reason_str, sizeof connack_reason_str,
                                 "%s", mqtt_connack_rc(vhdr[1]));
                    }
                }
                break;
            case MQTT_PUBLISH:    _parse_publish(vhdr, vrem, flags); break;
            case MQTT_PUBACK:     puback_cnt++; break;
            case MQTT_PUBREC:     pubrec_cnt++; break;
            case MQTT_PUBREL:     pubrel_cnt++; break;
            case MQTT_PUBCOMP:    pubcomp_cnt++; break;
            case MQTT_SUBSCRIBE:  _parse_subscribe(vhdr, vrem); break;
            case MQTT_SUBACK:
                /* Return codes */
                for (int i = 0; i < vrem - 2; i++) {
                    uint8_t rc = vhdr[2+i];
                    if (rc <= 2) suback_granted[rc]++;
                    else if (rc == 0x80) suback_refused_cnt++;
                }
                break;
            case MQTT_UNSUBSCRIBE: unsub_cnt++; break;
            case MQTT_PINGREQ:    pingreq_cnt++; break;
            case MQTT_PINGRESP:   pingresp_cnt++; break;
            case MQTT_DISCONNECT: disconnect_cnt++; break;
            case MQTT_AUTH:       auth_cnt++; break;
            default: break;
            }

            /* 推进 */
            int advance = 1 + rl_bytes + (int)pkt_rem;
            ptr += advance; rem -= advance;
        }
    }

    /* ============================================================
     * 输出日志
     * ============================================================ */
    void emit_log(FILE *fp, const char *flow_id = "") const {
        fprintf(fp, "[MQTT] %s\n", flow_id);
        fprintf(fp, "  Protocol         : %s v%s (level=%u)\n",
                protocol_name, protocol_version_str, protocol_level);
        fprintf(fp, "  Client-ID        : %s\n", client_id);
        fprintf(fp, "  Clean-Session    : %d  KeepAlive=%us\n",
                clean_session, keep_alive_secs);
        if (has_username) fprintf(fp, "  Username         : %s\n", username);
        fprintf(fp, "  Auth             : user=%d pass=%d\n",
                has_username, has_password);
        if (will_flag)
            fprintf(fp, "  Will             : topic=%s qos=%u retain=%d msglen=%u\n",
                    will_topic, will_qos, will_retain, will_message_len);
        fprintf(fp, "  CONNACK          : session_present=%d rc=%u (%s)\n",
                connack_session_present, connack_return_code, connack_reason_str);

        fprintf(fp, "  PUBLISH          : total=%u QoS0=%u QoS1=%u QoS2=%u retain=%u dup=%u\n",
                total_publish_cnt, qos0_cnt, qos1_cnt, qos2_cnt, retain_cnt, dup_cnt);
        fprintf(fp, "  Payload bytes    : total=%llu max=%u min=%u avg=%.1f\n",
                (unsigned long long)publish_payload_bytes,
                max_payload_bytes,
                min_payload_bytes == UINT32_MAX ? 0u : min_payload_bytes,
                total_publish_cnt > 0 ? (double)publish_payload_bytes/total_publish_cnt : 0.0);

        fprintf(fp, "  Pub topics (%u)  :", topic_cnt);
        for (int i = 0; i < topic_cnt && i < 8; i++) fprintf(fp, " %s", publish_topics[i]);
        if (topic_cnt > 8) fprintf(fp, " ...");
        fprintf(fp, "\n");

        fprintf(fp, "  SUBSCRIBE (%u)   :", sub_topic_cnt);
        for (int i = 0; i < sub_topic_cnt && i < 8; i++) fprintf(fp, " %s", sub_topics[i]);
        fprintf(fp, "\n");

        fprintf(fp, "  SUBACKs granted  : QoS0=%u QoS1=%u QoS2=%u refused=%u\n",
                suback_granted[0], suback_granted[1], suback_granted[2], suback_refused_cnt);
        fprintf(fp, "  QoS flow         : PUBACK=%u PUBREC=%u PUBREL=%u PUBCOMP=%u\n",
                puback_cnt, pubrec_cnt, pubrel_cnt, pubcomp_cnt);
        fprintf(fp, "  Control          : PINGREQ=%u PINGRESP=%u DISCONNECT=%u AUTH=%u\n",
                pingreq_cnt, pingresp_cnt, disconnect_cnt, auth_cnt);
        fprintf(fp, "  Pkts             : cli=%u srv=%u\n",
                total_pkts_cli, total_pkts_srv);
        fprintf(fp, "  Bytes            : cli=%llu srv=%llu\n",
                (unsigned long long)bytes_cli, (unsigned long long)bytes_srv);
        fprintf(fp, "  Idle max         : %.1f ms\n", idle_time_max_ms);

        if (v5_props_parsed) {
            fprintf(fp, "  [v5 Props]       : session_exp=%u recv_max=%u max_pkt=%u "
                        "alias_max=%u auth=%s\n",
                    v5_connect_props.session_expiry_interval,
                    v5_connect_props.receive_maximum,
                    v5_connect_props.max_packet_size,
                    v5_connect_props.topic_alias_maximum,
                    v5_connect_props.auth_method);
            for (int i = 0; i < v5_connect_props.user_prop_cnt; i++)
                fprintf(fp, "  [v5 UserProp]    : %s\n", v5_connect_props.user_props[i]);
        }
        fprintf(fp, "\n");
    }
};
