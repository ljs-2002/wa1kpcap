#pragma once

#include <cmath>
#include <cstdint>
#include <vector>
#include <algorithm>

static inline double dabs(double x) { return x < 0 ? -x : x; }
static inline double dmax(double a, double b) { return a > b ? a : b; }

static constexpr int STATS_PER_ARRAY = 21;

struct ArrayStats {
    double mean = 0, std_val = 0, var = 0, lo = 0, hi = 0, median = 0, total = 0;
    double up_mean = 0, up_std = 0, up_lo = 0, up_hi = 0, up_total = 0;
    double dn_mean = 0, dn_std = 0, dn_lo = 0, dn_hi = 0, dn_total = 0;
    int64_t n = 0, n_up = 0, n_dn = 0;
};

inline ArrayStats compute_stats_core(const double* ptr, int64_t n) {
    ArrayStats s{};
    s.n = n;
    if (n == 0) return s;

    double total = 0.0, sq_total = 0.0;
    double lo = dabs(ptr[0]), hi = lo;
    double up_total = 0.0, up_sq = 0.0, up_lo = 0.0, up_hi = 0.0;
    double dn_total = 0.0, dn_sq = 0.0, dn_lo = 0.0, dn_hi = 0.0;
    int64_t n_up = 0, n_dn = 0;

    std::vector<double> abs_vals(n);

    for (int64_t i = 0; i < n; i++) {
        double v = ptr[i];
        double a = dabs(v);
        abs_vals[i] = a;
        total += a;
        sq_total += a * a;
        if (a < lo) lo = a;
        if (a > hi) hi = a;

        if (v > 0) {
            if (n_up == 0) { up_lo = up_hi = a; }
            else { if (a < up_lo) up_lo = a; if (a > up_hi) up_hi = a; }
            up_total += a; up_sq += a * a; n_up++;
        } else if (v < 0) {
            if (n_dn == 0) { dn_lo = dn_hi = a; }
            else { if (a < dn_lo) dn_lo = a; if (a > dn_hi) dn_hi = a; }
            dn_total += a; dn_sq += a * a; n_dn++;
        }
    }

    double mean = total / n;
    double var_val = sq_total / n - mean * mean;
    if (var_val < 0) var_val = 0.0;

    double median;
    if (n % 2 == 1) {
        std::nth_element(abs_vals.begin(), abs_vals.begin() + n / 2, abs_vals.end());
        median = abs_vals[n / 2];
    } else {
        std::nth_element(abs_vals.begin(), abs_vals.begin() + n / 2, abs_vals.end());
        double right = abs_vals[n / 2];
        double left = abs_vals[0];
        for (int64_t i = 1; i < n / 2; i++) {
            if (abs_vals[i] > left) left = abs_vals[i];
        }
        median = (left + right) * 0.5;
    }

    double up_mean_v = 0.0, up_std_v = 0.0;
    if (n_up > 1) {
        up_mean_v = up_total / n_up;
        double up_var = up_sq / n_up - up_mean_v * up_mean_v;
        up_std_v = sqrt(dmax(0.0, up_var));
    } else if (n_up == 1) { up_mean_v = up_total; }

    double dn_mean_v = 0.0, dn_std_v = 0.0;
    if (n_dn > 1) {
        dn_mean_v = dn_total / n_dn;
        double dn_var = dn_sq / n_dn - dn_mean_v * dn_mean_v;
        dn_std_v = sqrt(dmax(0.0, dn_var));
    } else if (n_dn == 1) { dn_mean_v = dn_total; }

    s.mean = mean;
    s.std_val = sqrt(var_val);
    s.var = var_val;
    s.lo = lo;
    s.hi = hi;
    s.median = median;
    s.total = total;
    s.up_mean = up_mean_v;
    s.up_std = up_std_v;
    s.up_lo = up_lo;
    s.up_hi = up_hi;
    s.up_total = up_total;
    s.dn_mean = dn_mean_v;
    s.dn_std = dn_std_v;
    s.dn_lo = dn_lo;
    s.dn_hi = dn_hi;
    s.dn_total = dn_total;
    s.n_up = n_up;
    s.n_dn = n_dn;
    return s;
}

// Compute stats from int64_t vector (converts to double internally)
inline ArrayStats compute_stats_from_ints(const std::vector<int64_t>& vec) {
    if (vec.empty()) return {};
    std::vector<double> dv(vec.begin(), vec.end());
    return compute_stats_core(dv.data(), static_cast<int64_t>(dv.size()));
}

inline ArrayStats compute_stats_from_doubles(const std::vector<double>& vec) {
    if (vec.empty()) return {};
    return compute_stats_core(vec.data(), static_cast<int64_t>(vec.size()));
}
