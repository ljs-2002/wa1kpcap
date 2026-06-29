/**
 * protocol_json_emit.h — JSON Lines emit for header-only L7 flow records
 */
#pragma once

#include "json_log.h"

#include <arpa/inet.h>
#include <cstdio>

inline void json_five_tuple_u32(FILE* f,
                                uint32_t sip, uint16_t sp,
                                uint32_t dip, uint16_t dp,
                                uint8_t proto) {
    char ss[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN];
    in_addr sa{sip}, da{dip};
    inet_ntop(AF_INET, &sa, ss, sizeof ss);
    inet_ntop(AF_INET, &da, ds, sizeof ds);
    json_five_tuple(f, ss, sp, ds, dp, proto);
}

inline void json_hex_bytes(FILE* f, const uint8_t* b, int n, int max_n = 32) {
    fputc('"', f);
    int lim = n < max_n ? n : max_n;
    for (int i = 0; i < lim; i++)
        fprintf(f, "%02x", b[i]);
    if (n > lim) fputs("...", f);
    fputc('"', f);
}

#include "http_flow.h"
#include "ssh_flow.h"
#include "mqtt_flow.h"
#include "sip_flow.h"
#include "quic_flow.h"
#include "rdp_flow.h"
#include "vnc_flow.h"

inline void http_emit_json(FILE* f, const char* pcap_file, const char* flow_id,
                           uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
                           uint8_t proto, const HttpFlowRecord& r) {
    fprintf(f, "{\"file\":");
    json_esc_cstr(f, pcap_file);
    fprintf(f, ",\"flow_id\":");
    json_esc_cstr(f, flow_id);
    fprintf(f, ",\"protocol\":\"HTTP\",");
    json_five_tuple_u32(f, sip, sp, dip, dp, proto);
    fprintf(f, ",\"meta\":{"
            "\"http_version\":");
    json_esc_cstr(f, r.http_version);
    fprintf(f, ",\"is_http2\":%s,\"method\":", r.is_http2 ? "true" : "false");
    json_esc_cstr(f, http_method_name(r.method));
    fprintf(f, ",\"status_code\":%u,\"status_reason\":", (unsigned)r.status_code);
    json_esc_cstr(f, r.status_reason);
    fprintf(f, ",\"url\":");
    json_esc_cstr(f, r.url);
    fprintf(f, ",\"host\":");
    json_esc_cstr(f, r.host);
    fprintf(f, ",\"user_agent\":");
    json_esc_cstr(f, r.user_agent);
    fprintf(f, ",\"server\":");
    json_esc_cstr(f, r.server);
    fprintf(f, ",\"content_type\":");
    json_esc_cstr(f, r.content_type);
    fprintf(f, ",\"content_length\":%llu", (unsigned long long)r.content_length);
    fprintf(f, ",\"total_request_cnt\":%u,\"total_response_cnt\":%u",
            r.total_request_cnt, r.total_response_cnt);
    fprintf(f, ",\"status_dist\":{\"1xx\":%u,\"2xx\":%u,\"3xx\":%u,\"4xx\":%u,\"5xx\":%u}",
            r.status_1xx, r.status_2xx, r.status_3xx, r.status_4xx, r.status_5xx);
    fprintf(f, ",\"bytes\":{\"req\":%llu,\"rsp\":%llu}",
            (unsigned long long)r.total_request_bytes,
            (unsigned long long)r.total_response_bytes);
    fprintf(f, ",\"has_auth\":%s,\"websocket_upgrade\":%s",
            r.has_auth ? "true" : "false",
            r.websocket_upgrade ? "true" : "false");
    fprintf(f, "}}\n");
}

inline bool http_has_signal(const HttpFlowRecord& r) {
    return r.total_request_cnt > 0 || r.total_response_cnt > 0 || r.is_http2 ||
           r.http_version[0] != '\0';
}

inline void ssh_emit_json(FILE* f, const char* pcap_file, const char* flow_id,
                          uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
                          uint8_t proto, const SshFlowRecord& r) {
    static const char* kex_type_name[] = {"unknown", "ecdh", "dh-group", "dh-gex"};
    static const char* state_name[] = {"INIT", "BANNER", "KEXINIT", "KEX", "NEWKEYS", "ENCRYPTED"};
    fprintf(f, "{\"file\":");
    json_esc_cstr(f, pcap_file);
    fprintf(f, ",\"flow_id\":");
    json_esc_cstr(f, flow_id);
    fprintf(f, ",\"protocol\":\"SSH\",");
    json_five_tuple_u32(f, sip, sp, dip, dp, proto);
    fprintf(f, ",\"meta\":{"
            "\"cli_banner\":");
    json_esc_cstr(f, r.cli_software);
    fprintf(f, ",\"srv_banner\":");
    json_esc_cstr(f, r.srv_software);
    fprintf(f, ",\"state\":");
    json_esc_cstr(f, state_name[(int)r.state < 6 ? (int)r.state : 0]);
    fprintf(f, ",\"neg_kex\":");
    json_esc_cstr(f, r.neg_kex);
    fprintf(f, ",\"kex_type\":");
    json_esc_cstr(f, kex_type_name[(int)r.kex_type < 4 ? (int)r.kex_type : 0]);
    fprintf(f, ",\"neg_enc_c2s\":");
    json_esc_cstr(f, r.neg_enc_c2s);
    fprintf(f, ",\"neg_enc_s2c\":");
    json_esc_cstr(f, r.neg_enc_s2c);
    fprintf(f, ",\"host_key_type\":");
    json_esc_cstr(f, r.host_key_type);
    fprintf(f, ",\"auth_username\":");
    json_esc_cstr(f, r.auth_username);
    fprintf(f, ",\"auth_method\":");
    json_esc_cstr(f, r.auth_method);
    fprintf(f, ",\"auth_success\":%s", r.auth_success ? "true" : "false");
    fprintf(f, ",\"pkts_total\":%u,\"bytes_pre_enc\":%llu,\"bytes_post_enc\":%llu",
            r.pkts_total,
            (unsigned long long)r.bytes_pre_enc,
            (unsigned long long)r.bytes_post_enc);
    if (r.disconnect_reason)
        fprintf(f, ",\"disconnect_reason\":%u,\"disconnect_desc\":",
                r.disconnect_reason);
    else
        fprintf(f, ",\"disconnect_reason\":0,\"disconnect_desc\":");
    json_esc_cstr(f, r.disconnect_desc);
    fprintf(f, "}}\n");
}

inline bool ssh_has_signal(const SshFlowRecord& r) {
    return r.pkts_total > 0 && (r.cli_software[0] || r.srv_software[0] ||
                                r.state != SshFlowRecord::S_INIT);
}

inline void mqtt_emit_json(FILE* f, const char* pcap_file, const char* flow_id,
                           uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
                           uint8_t proto, const MqttFlowRecord& r) {
    fprintf(f, "{\"file\":");
    json_esc_cstr(f, pcap_file);
    fprintf(f, ",\"flow_id\":");
    json_esc_cstr(f, flow_id);
    fprintf(f, ",\"protocol\":\"MQTT\",");
    json_five_tuple_u32(f, sip, sp, dip, dp, proto);
    fprintf(f, ",\"meta\":{"
            "\"protocol_name\":");
    json_esc_cstr(f, r.protocol_name);
    fprintf(f, ",\"protocol_version\":");
    json_esc_cstr(f, r.protocol_version_str);
    fprintf(f, ",\"client_id\":");
    json_esc_cstr(f, r.client_id);
    fprintf(f, ",\"username\":");
    json_esc_cstr(f, r.username);
    fprintf(f, ",\"keep_alive_secs\":%u,\"clean_session\":%d",
            r.keep_alive_secs, r.clean_session);
    fprintf(f, ",\"connack_return_code\":%u,\"total_publish_cnt\":%u",
            r.connack_return_code, r.total_publish_cnt);
    fprintf(f, ",\"publish_topics\":[");
    for (int i = 0; i < r.topic_cnt && i < 8; i++) {
        if (i) fputc(',', f);
        json_esc_cstr(f, r.publish_topics[i]);
    }
    fprintf(f, "],\"sub_topics\":[");
    for (int i = 0; i < r.sub_topic_cnt && i < 8; i++) {
        if (i) fputc(',', f);
        json_esc_cstr(f, r.sub_topics[i]);
    }
    fprintf(f, "],\"pkts\":{\"cli\":%u,\"srv\":%u},\"bytes\":{\"cli\":%llu,\"srv\":%llu}",
            r.total_pkts_cli, r.total_pkts_srv,
            (unsigned long long)r.bytes_cli, (unsigned long long)r.bytes_srv);
    fprintf(f, "}}\n");
}

inline bool mqtt_has_signal(const MqttFlowRecord& r) {
    return r.client_id[0] || r.total_publish_cnt > 0 || r.protocol_name[0] ||
           r.total_pkts_cli + r.total_pkts_srv > 0;
}

inline void sip_emit_json(FILE* f, const char* pcap_file, const char* flow_id,
                          uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
                          uint8_t proto, const SipFlowRecord& r) {
    fprintf(f, "{\"file\":");
    json_esc_cstr(f, pcap_file);
    fprintf(f, ",\"flow_id\":");
    json_esc_cstr(f, flow_id);
    fprintf(f, ",\"protocol\":\"SIP\",");
    json_five_tuple_u32(f, sip, sp, dip, dp, proto);
    fprintf(f, ",\"meta\":{"
            "\"method\":");
    json_esc_cstr(f, sip_method_name(r.first_method));
    fprintf(f, ",\"status_code\":%u,\"status_reason\":", (unsigned)r.last_status_code);
    json_esc_cstr(f, r.last_status_reason);
    fprintf(f, ",\"call_id\":");
    json_esc_cstr(f, r.call_id);
    fprintf(f, ",\"from_uri\":");
    json_esc_cstr(f, r.from_uri);
    fprintf(f, ",\"to_uri\":");
    json_esc_cstr(f, r.to_uri);
    fprintf(f, ",\"user_agent\":");
    json_esc_cstr(f, r.user_agent);
    fprintf(f, ",\"server\":");
    json_esc_cstr(f, r.server_str);
    fprintf(f, ",\"total_msgs\":%u,\"transaction_cnt\":%u",
            r.total_msgs, r.transaction_cnt);
    fprintf(f, ",\"resp_dist\":{\"1xx\":%u,\"2xx\":%u,\"3xx\":%u,\"4xx\":%u,\"5xx\":%u,\"6xx\":%u}",
            r.resp_1xx, r.resp_2xx, r.resp_3xx, r.resp_4xx, r.resp_5xx, r.resp_6xx);
    fprintf(f, ",\"sdp_media_cnt\":%d", r.sdp_media_cnt);
    fprintf(f, "}}\n");
}

inline bool sip_has_signal(const SipFlowRecord& r) {
    return r.total_msgs > 0 || r.call_id[0];
}

inline void quic_emit_json(FILE* f, const char* pcap_file, const char* flow_id,
                           uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
                           uint8_t proto, const QuicFlowRecord& r) {
    fprintf(f, "{\"file\":");
    json_esc_cstr(f, pcap_file);
    fprintf(f, ",\"flow_id\":");
    json_esc_cstr(f, flow_id);
    fprintf(f, ",\"protocol\":\"QUIC\",");
    json_five_tuple_u32(f, sip, sp, dip, dp, proto);
    fprintf(f, ",\"meta\":{"
            "\"version\":");
    json_esc_cstr(f, quic_version_name(r.version));
    fprintf(f, ",\"version_hex\":\"0x%08x\"", r.version);
    fprintf(f, ",\"n_total\":%u,\"n_initial\":%u,\"n_0rtt\":%u,\"n_handshake\":%u",
            r.n_total, r.n_initial, r.n_0rtt, r.n_handshake);
    fprintf(f, ",\"n_retry\":%u,\"n_short\":%u,\"seen_version_neg\":%s",
            r.n_retry, r.n_short, r.seen_version_neg ? "true" : "false");
    fprintf(f, ",\"first_dcid\":");
    json_hex_bytes(f, r.first_dcid, r.first_dcid_len);
    fprintf(f, ",\"first_scid\":");
    json_hex_bytes(f, r.first_scid, r.first_scid_len);
    fprintf(f, ",\"n_tparams\":%d,\"first_ts\":%.6f,\"last_ts\":%.6f",
            r.n_tparams, r.first_ts, r.last_ts);
    fprintf(f, "}}\n");
}

inline bool quic_has_signal(const QuicFlowRecord& r) { return r.is_quic; }

inline void rdp_emit_json(FILE* f, const char* pcap_file, const char* flow_id,
                          uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
                          uint8_t proto, const RdpFlowRecord& r) {
    fprintf(f, "{\"file\":");
    json_esc_cstr(f, pcap_file);
    fprintf(f, ",\"flow_id\":");
    json_esc_cstr(f, flow_id);
    fprintf(f, ",\"protocol\":\"RDP\",");
    json_five_tuple_u32(f, sip, sp, dip, dp, proto);
    fprintf(f, ",\"meta\":{"
            "\"seen_cr\":%s,\"seen_cc\":%s,\"seen_dt\":%s,\"seen_dr\":%s",
            r.seen_cr ? "true" : "false", r.seen_cc ? "true" : "false",
            r.seen_dt ? "true" : "false", r.seen_dr ? "true" : "false");
    fprintf(f, ",\"client_name\":");
    json_esc_cstr(f, r.client_name);
    fprintf(f, ",\"desktop\":\"%ux%u\",\"color_depth\":%u",
            r.desktop_width, r.desktop_height, r.color_depth);
    fprintf(f, ",\"req_protocols\":\"0x%08x\",\"sel_protocol\":",
            r.req_protocols);
    json_esc_cstr(f, rdp_protocol_name(r.sel_protocol));
    fprintf(f, ",\"encryption_method\":");
    json_esc_cstr(f, rdp_enc_method_name(r.encryption_method));
    fprintf(f, ",\"neg_failure\":%s", r.neg_failure ? "true" : "false");
    fprintf(f, "}}\n");
}

inline bool rdp_has_signal(const RdpFlowRecord& r) { return r.is_rdp; }

inline void vnc_emit_json(FILE* f, const char* pcap_file, const char* flow_id,
                          uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
                          uint8_t proto, const VncFlowRecord& r) {
    fprintf(f, "{\"file\":");
    json_esc_cstr(f, pcap_file);
    fprintf(f, ",\"flow_id\":");
    json_esc_cstr(f, flow_id);
    fprintf(f, ",\"protocol\":\"VNC\",");
    json_five_tuple_u32(f, sip, sp, dip, dp, proto);
    fprintf(f, ",\"meta\":{"
            "\"proto_version\":\"%u.%u\"", r.proto_major, r.proto_minor);
    fprintf(f, ",\"server_banner\":");
    json_esc_cstr(f, r.server_banner);
    fprintf(f, ",\"sel_sec_type\":");
    json_esc_cstr(f, vnc_sec_name(r.sel_sec_type));
    fprintf(f, ",\"auth_failed\":%s", r.auth_failed ? "true" : "false");
    fprintf(f, ",\"fb_width\":%u,\"fb_height\":%u,\"desktop_name\":",
            r.fb_width, r.fb_height);
    json_esc_cstr(f, r.desktop_name);
    fprintf(f, "}}\n");
}

inline bool vnc_has_signal(const VncFlowRecord& r) { return r.is_vnc; }
