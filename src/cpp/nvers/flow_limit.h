/**
 * flow_limit.h  ——  每流分析包数上限（nvers 统一约定）
 *
 *   n_limit == 0  →  分析该流全部包（默认）
 *   n_limit >  0  →  仅分析前 n_limit 个包
 */
#pragma once

#include <cstdint>
#include <cstdio>

static constexpr int FLOW_LIMIT_ALL = 0;

inline bool flow_limit_reached(uint32_t pkt_count, int n_limit) noexcept {
    return n_limit > 0 && pkt_count >= (uint32_t)n_limit;
}

inline void flow_limit_print_desc(FILE* f, int n_limit) {
    if (n_limit > 0)
        fprintf(f, "前 %d 包", n_limit);
    else
        fprintf(f, "全部包");
}
