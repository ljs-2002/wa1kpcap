/**
 * json_log.h  ——  JSON Lines 输出辅助（nvers）
 */
#pragma once

#include <cstdio>
#include <cstring>
#include <ostream>
#include <string>
#include <vector>

inline void json_esc_cstr(FILE* f, const char* s) {
    fputc('"', f);
    if (s) {
        for (; *s; s++) {
            unsigned char c = (unsigned char)*s;
            if (c == '"' || c == '\\') fputc('\\', f);
            else if (c == '\n') fputs("\\n", f);
            else if (c == '\r') fputs("\\r", f);
            else if (c == '\t') fputs("\\t", f);
            else fputc((int)c, f);
        }
    }
    fputc('"', f);
}

inline void json_esc_os(std::ostream& o, const char* s) {
    o << '"';
    if (s) {
        for (; *s; s++) {
            unsigned char c = (unsigned char)*s;
            if (c == '"' || c == '\\') o << '\\' << (char)c;
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else o << (char)c;
        }
    }
    o << '"';
}

inline void json_esc_os(std::ostream& o, const std::string& s) {
    json_esc_os(o, s.c_str());
}

inline void json_u16_arr(FILE* f, const uint16_t* arr, int n) {
    fputc('[', f);
    for (int i = 0; i < n; i++) {
        if (i) fputc(',', f);
        fprintf(f, "%u", (unsigned)arr[i]);
    }
    fputc(']', f);
}

inline void json_i32_arr(FILE* f, const int32_t* arr, int n) {
    fputc('[', f);
    for (int i = 0; i < n; i++) {
        if (i) fputc(',', f);
        fprintf(f, "%d", arr[i]);
    }
    fputc(']', f);
}

inline void json_str_arr(FILE* f, const char* const* arr, int n) {
    fputc('[', f);
    for (int i = 0; i < n; i++) {
        if (i) fputc(',', f);
        json_esc_cstr(f, arr[i]);
    }
    fputc(']', f);
}

inline void json_str_vec(FILE* f, const std::vector<std::string>& v) {
    fputc('[', f);
    for (size_t i = 0; i < v.size(); i++) {
        if (i) fputc(',', f);
        json_esc_cstr(f, v[i].c_str());
    }
    fputc(']', f);
}

inline void json_five_tuple(FILE* f,
                            const char* src_ip, uint16_t src_port,
                            const char* dst_ip, uint16_t dst_port,
                            uint8_t proto) {
    fprintf(f, "\"five_tuple\":{\"src_ip\":");
    json_esc_cstr(f, src_ip);
    fprintf(f, ",\"src_port\":%u,\"dst_ip\":", (unsigned)src_port);
    json_esc_cstr(f, dst_ip);
    fprintf(f, ",\"dst_port\":%u,\"proto\":%u}", (unsigned)dst_port, (unsigned)proto);
}

inline void json_five_tuple_os(std::ostream& o,
                               const char* src_ip, uint16_t src_port,
                               const char* dst_ip, uint16_t dst_port,
                               uint8_t proto) {
    o << "\"five_tuple\":{\"src_ip\":";
    json_esc_os(o, src_ip);
    o << ",\"src_port\":" << src_port << ",\"dst_ip\":";
    json_esc_os(o, dst_ip);
    o << ",\"dst_port\":" << dst_port << ",\"proto\":" << (unsigned)proto << "}";
}
