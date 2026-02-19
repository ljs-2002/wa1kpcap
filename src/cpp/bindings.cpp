// NOMINMAX must be defined before any Windows headers to prevent min/max macros
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>

#include <algorithm>
#include <cmath>
#include <vector>

#include "pcap_reader.h"
#include "protocol_engine.h"
#include "parsed_packet.h"
#include "yaml_loader.h"
#include "bpf_filter.h"
#include "flow_buffer.h"

// Safety: undef any remaining macros that leaked through
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#ifdef abs
#undef abs
#endif

namespace py = pybind11;
using namespace pybind11::literals;

static inline double dabs(double x) { return x >= 0.0 ? x : -x; }
static inline double dmax(double a, double b) { return a >= b ? a : b; }

// ── ClassCache: cached Python class references for dataclass construction ──

struct ClassCache {
    py::object ParsedPacket_cls;
    #define X_CLS(P, s, S, Py) py::object P##Info_cls;
    BUILTIN_PROTOCOLS(X_CLS)
    #undef X_CLS
    py::object empty_bytes;
    py::object none;
    py::object true_;
    py::object neg1;
    py::object zero;
    bool ready = false;

    void ensure_ready() {
        if (ready) return;
        auto mod = py::module_::import("wa1kpcap.core.packet");
        ParsedPacket_cls = mod.attr("ParsedPacket");
        #define X_INIT(P, s, S, Py) P##Info_cls = mod.attr(Py);
        BUILTIN_PROTOCOLS(X_INIT)
        #undef X_INIT
        empty_bytes = py::bytes("", 0);
        none = py::none();
        true_ = py::bool_(true);
        neg1 = py::int_(-1);
        zero = py::int_(0);
        ready = true;
    }
};

static ClassCache g_cc;

// ── build_dataclass_from_struct: convert NativeParsedPacket → Python ParsedPacket ──

static py::object build_dataclass_from_struct(
    const NativeParsedPacket& pkt,
    py::object raw_data_py,
    double timestamp, int link_type, int caplen, int wirelen)
{
    g_cc.ensure_ready();
    auto& cc = g_cc;

    py::object eth = cc.none;
    if (pkt.has_eth) {
        eth = cc.EthernetInfo_cls(
            pkt.eth.src, pkt.eth.dst, pkt.eth.type, cc.empty_bytes);
    }

    py::object ip = cc.none;
    if (pkt.has_ip) {
        py::object ip_raw = pkt.ip.options_raw.empty()
            ? cc.empty_bytes : py::bytes(pkt.ip.options_raw);
        ip = cc.IPInfo_cls(
            pkt.ip.version, pkt.ip.src, pkt.ip.dst, pkt.ip.proto,
            pkt.ip.ttl, pkt.ip.len, pkt.ip.id, pkt.ip.flags,
            pkt.ip.offset, ip_raw);
    }

    py::object ip6 = cc.none;
    if (pkt.has_ip6) {
        py::object ip6_raw = pkt.ip6.options_raw.empty()
            ? cc.empty_bytes : py::bytes(pkt.ip6.options_raw);
        ip6 = cc.IP6Info_cls(
            pkt.ip6.version, pkt.ip6.src, pkt.ip6.dst,
            pkt.ip6.next_header, pkt.ip6.hop_limit,
            pkt.ip6.flow_label, pkt.ip6.len, ip6_raw);
    }

    py::object tcp = cc.none;
    if (pkt.has_tcp) {
        py::object tcp_opts = pkt.tcp.options.empty()
            ? cc.empty_bytes : py::bytes(pkt.tcp.options);
        tcp = cc.TCPInfo_cls(
            pkt.tcp.sport, pkt.tcp.dport, pkt.tcp.seq,
            pkt.tcp.ack_num, pkt.tcp.flags, pkt.tcp.win,
            pkt.tcp.urgent, tcp_opts, cc.empty_bytes);
    }

    py::object udp = cc.none;
    if (pkt.has_udp) {
        udp = cc.UDPInfo_cls(
            pkt.udp.sport, pkt.udp.dport, pkt.udp.len, cc.empty_bytes);
    }

    py::object dns = cc.none;
    if (pkt.has_dns) {
        dns = cc.DNSInfo_cls(
            py::cast(pkt.dns.queries), py::list(),
            pkt.dns.response_code, pkt.dns.question_count,
            pkt.dns.answer_count, pkt.dns.authority_count,
            pkt.dns.additional_count, pkt.dns.flags, cc.empty_bytes);
    }

    py::object tls = cc.none;
    if (pkt.has_tls) {
        py::object ver = pkt.tls.version.empty()
            ? cc.none : py::cast(pkt.tls.version);
        py::object ct = pkt.tls.content_type >= 0
            ? py::cast(pkt.tls.content_type) : cc.none;
        py::object ht = pkt.tls.handshake_type >= 0
            ? py::cast(pkt.tls.handshake_type) : cc.none;
        py::list sni_list;
        if (!pkt.tls.sni.empty()) sni_list.append(pkt.tls.sni);
        py::object cs = pkt.tls.cipher_suite >= 0
            ? py::cast(pkt.tls.cipher_suite) : cc.none;

        py::list cert_list;
        for (auto& cert : pkt.tls.certificates) {
            cert_list.append(py::bytes(cert));
        }

        tls = cc.TLSInfo_cls(
            ver, ct, ht, sni_list,
            py::cast(pkt.tls.cipher_suites), cs,
            py::cast(pkt.tls.alpn),
            py::cast(pkt.tls.signature_algorithms),
            py::cast(pkt.tls.supported_groups),
            cc.none, cert_list,
            py::dict(), py::list(),
            pkt.tls.record_length, cc.empty_bytes);

        // Set _handshake_types attribute
        if (!pkt.tls.handshake_types.empty()) {
            py::list ht_list;
            for (auto v : pkt.tls.handshake_types) ht_list.append(v);
            py::setattr(tls, "_handshake_types", ht_list);
        }
    }

    py::object arp = cc.none;
    if (pkt.has_arp) {
        arp = cc.ARPInfo_cls(
            pkt.arp.hw_type, pkt.arp.proto_type, pkt.arp.opcode,
            pkt.arp.sender_mac, pkt.arp.sender_ip,
            pkt.arp.target_mac, pkt.arp.target_ip, cc.empty_bytes);
    }

    py::object icmp = cc.none;
    if (pkt.has_icmp) {
        py::object rest = pkt.icmp.rest_data.empty()
            ? cc.empty_bytes : py::bytes(pkt.icmp.rest_data);
        icmp = cc.ICMPInfo_cls(pkt.icmp.type, pkt.icmp.code, rest);
    }

    py::object icmp6 = cc.none;
    if (pkt.has_icmp6) {
        py::object rest = pkt.icmp6.rest_data.empty()
            ? cc.empty_bytes : py::bytes(pkt.icmp6.rest_data);
        icmp6 = cc.ICMP6Info_cls(pkt.icmp6.type, pkt.icmp6.code, pkt.icmp6.checksum, rest);
    }

    py::object vlan = cc.none;
    if (pkt.has_vlan) {
        vlan = cc.VLANInfo_cls(
            pkt.vlan.vlan_id, pkt.vlan.priority, pkt.vlan.dei,
            pkt.vlan.ether_type, cc.empty_bytes);
    }

    py::object sll = cc.none;
    if (pkt.has_sll) {
        sll = cc.SLLInfo_cls(
            pkt.sll.packet_type, pkt.sll.arphrd_type,
            pkt.sll.addr, pkt.sll.protocol, cc.empty_bytes);
    }

    py::object sll2 = cc.none;
    if (pkt.has_sll2) {
        sll2 = cc.SLL2Info_cls(
            pkt.sll2.protocol_type, pkt.sll2.interface_index,
            pkt.sll2.arphrd_type, pkt.sll2.packet_type,
            pkt.sll2.addr, cc.empty_bytes);
    }

    py::object gre = cc.none;
    if (pkt.has_gre) {
        gre = cc.GREInfo_cls(
            pkt.gre.flags, pkt.gre.protocol_type,
            pkt.gre.has_checksum ? py::cast(pkt.gre.checksum) : cc.none,
            pkt.gre.has_key ? py::cast(pkt.gre.key) : cc.none,
            pkt.gre.has_sequence ? py::cast(pkt.gre.sequence) : cc.none,
            cc.empty_bytes);
    }

    py::object vxlan = cc.none;
    if (pkt.has_vxlan) {
        vxlan = cc.VXLANInfo_cls(pkt.vxlan.flags, pkt.vxlan.vni, cc.empty_bytes);
    }

    py::object mpls = cc.none;
    if (pkt.has_mpls) {
        mpls = cc.MPLSInfo_cls(
            pkt.mpls.label, pkt.mpls.tc, pkt.mpls.ttl,
            pkt.mpls.stack_depth, pkt.mpls.bottom_of_stack,
            cc.empty_bytes);
    }

    py::object dhcp = cc.none;
    if (pkt.has_dhcp) {
        py::bytes opts_raw(reinterpret_cast<const char*>(pkt.dhcp.options_raw.data()),
                           pkt.dhcp.options_raw.size());
        dhcp = cc.DHCPInfo_cls(
            pkt.dhcp.op, pkt.dhcp.htype, pkt.dhcp.xid,
            pkt.dhcp.ciaddr, pkt.dhcp.yiaddr, pkt.dhcp.siaddr,
            pkt.dhcp.giaddr, pkt.dhcp.chaddr,
            opts_raw, cc.empty_bytes);
    }

    py::object dhcpv6 = cc.none;
    if (pkt.has_dhcpv6) {
        py::bytes opts_raw(reinterpret_cast<const char*>(pkt.dhcpv6.options_raw.data()),
                           pkt.dhcpv6.options_raw.size());
        dhcpv6 = cc.DHCPv6Info_cls(
            pkt.dhcpv6.msg_type, pkt.dhcpv6.transaction_id,
            opts_raw, cc.empty_bytes);
    }

    py::object raw_payload = pkt._raw_tcp_payload.empty()
        ? cc.empty_bytes : py::bytes(pkt._raw_tcp_payload);

    // Convert extra_layers (unknown protocols) to py::dict of py::dict
    py::object extra_layers_py = cc.none;
    if (!pkt.extra_layers.empty()) {
        py::dict el;
        for (auto& [name, fm] : pkt.extra_layers) {
            el[py::cast(name)] = fieldmap_to_pydict(fm);
        }
        extra_layers_py = el;
    }

    // Compute flow key cache
    py::object flow_key_cache = cc.none;
    if (pkt.has_ip || pkt.has_ip6) {
        std::string src_ip, dst_ip;
        int64_t protocol = 0;
        if (pkt.has_ip) {
            src_ip = pkt.ip.src; dst_ip = pkt.ip.dst; protocol = pkt.ip.proto;
        } else {
            src_ip = pkt.ip6.src; dst_ip = pkt.ip6.dst; protocol = pkt.ip6.next_header;
        }
        int64_t src_port = 0, dst_port = 0;
        if (pkt.has_tcp) { src_port = pkt.tcp.sport; dst_port = pkt.tcp.dport; }
        else if (pkt.has_udp) { src_port = pkt.udp.sport; dst_port = pkt.udp.dport; }

        int64_t vlan_id = pkt.has_vlan ? pkt.vlan.vlan_id : 0;

        py::tuple canonical;
        if (std::make_tuple(src_ip, src_port) <= std::make_tuple(dst_ip, dst_port)) {
            canonical = py::make_tuple(src_ip, src_port, dst_ip, dst_port, protocol, vlan_id);
        } else {
            canonical = py::make_tuple(dst_ip, dst_port, src_ip, src_port, protocol, vlan_id);
        }
        flow_key_cache = py::make_tuple(canonical, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id);
    }

    return cc.ParsedPacket_cls(
        timestamp, raw_data_py, (int)link_type, caplen, wirelen,
        pkt.ip_len, pkt.trans_len, pkt.app_len,
        eth, ip, ip6, tcp, udp, icmp, tls, cc.none, dns,
        cc.true_, cc.neg1, cc.neg1,
        cc.none, cc.none, cc.none, cc.none,
        raw_payload, flow_key_cache, extra_layers_py,
        arp, icmp6,
        vlan, sll, sll2, gre, vxlan, mpls, dhcp, dhcpv6);
}

// Standalone function for compute_array_stats (MSVC compatibility)
static py::dict compute_array_stats_impl(py::array_t<double, py::array::c_style | py::array::forcecast> arr) {
    auto buf = arr.request();
    double* ptr = static_cast<double*>(buf.ptr);
    Py_ssize_t n = buf.size;

    if (n == 0) return py::dict();

    // Single pass: compute all stats
    double total = 0.0, sq_total = 0.0;
    double lo = dabs(ptr[0]), hi = lo;
    double up_total = 0.0, up_sq = 0.0, up_lo = 0.0, up_hi = 0.0;
    double dn_total = 0.0, dn_sq = 0.0, dn_lo = 0.0, dn_hi = 0.0;
    Py_ssize_t n_up = 0, n_dn = 0;

    std::vector<double> abs_vals(n);

    for (Py_ssize_t i = 0; i < n; i++) {
        double v = ptr[i];
        double a = dabs(v);
        abs_vals[i] = a;
        total += a;
        sq_total += a * a;
        if (a < lo) lo = a;
        if (a > hi) hi = a;

        if (v > 0) {
            if (n_up == 0) {
                up_lo = up_hi = a;
            } else {
                if (a < up_lo) up_lo = a;
                if (a > up_hi) up_hi = a;
            }
            up_total += a;
            up_sq += a * a;
            n_up++;
        } else if (v < 0) {
            if (n_dn == 0) {
                dn_lo = dn_hi = a;
            } else {
                if (a < dn_lo) dn_lo = a;
                if (a > dn_hi) dn_hi = a;
            }
            dn_total += a;
            dn_sq += a * a;
            n_dn++;
        }
    }

    double mean = total / n;
    double var = sq_total / n - mean * mean;
    if (var < 0) var = 0.0;
    double std_val = sqrt(var);

    // Median via nth_element O(n)
    double median;
    if (n % 2 == 1) {
        std::nth_element(abs_vals.begin(), abs_vals.begin() + n / 2, abs_vals.end());
        median = abs_vals[n / 2];
    } else {
        std::nth_element(abs_vals.begin(), abs_vals.begin() + n / 2, abs_vals.end());
        double right = abs_vals[n / 2];
        // Find max in left partition
        double left = abs_vals[0];
        for (Py_ssize_t i = 1; i < n / 2; i++) {
            if (abs_vals[i] > left) left = abs_vals[i];
        }
        median = (left + right) * 0.5;
    }

    // Directional stats
    double up_mean = 0.0, up_std = 0.0;
    if (n_up > 1) {
        up_mean = up_total / n_up;
        double up_var = up_sq / n_up - up_mean * up_mean;
        up_std = sqrt(dmax(0.0, up_var));
    } else if (n_up == 1) {
        up_mean = up_total;
        up_std = 0.0;
    }

    double dn_mean = 0.0, dn_std = 0.0;
    if (n_dn > 1) {
        dn_mean = dn_total / n_dn;
        double dn_var = dn_sq / n_dn - dn_mean * dn_mean;
        dn_std = sqrt(dmax(0.0, dn_var));
    } else if (n_dn == 1) {
        dn_mean = dn_total;
        dn_std = 0.0;
    }

    return py::dict(
        "mean"_a = mean,
        "std"_a = std_val,
        "var"_a = var,
        "min"_a = lo,
        "max"_a = hi,
        "range"_a = hi - lo,
        "median"_a = median,
        "sum"_a = total,
        "up_mean"_a = up_mean,
        "up_std"_a = up_std,
        "up_min"_a = up_lo,
        "up_max"_a = up_hi,
        "up_sum"_a = up_total,
        "up_count"_a = static_cast<int64_t>(n_up),
        "down_mean"_a = dn_mean,
        "down_std"_a = dn_std,
        "down_min"_a = dn_lo,
        "down_max"_a = dn_hi,
        "down_sum"_a = dn_total,
        "down_count"_a = static_cast<int64_t>(n_dn),
        "count"_a = static_cast<int64_t>(n)
    );
}

// ── Core stats computation (reusable for single + batch) ──

struct ArrayStats {
    double mean, std_val, var, lo, hi, median, total;
    double up_mean, up_std, up_lo, up_hi, up_total;
    double dn_mean, dn_std, dn_lo, dn_hi, dn_total;
    int64_t n, n_up, n_dn;
};

static ArrayStats compute_stats_core(const double* ptr, Py_ssize_t n) {
    ArrayStats s{};
    s.n = n;
    if (n == 0) return s;

    double total = 0.0, sq_total = 0.0;
    double lo = dabs(ptr[0]), hi = lo;
    double up_total = 0.0, up_sq = 0.0, up_lo = 0.0, up_hi = 0.0;
    double dn_total = 0.0, dn_sq = 0.0, dn_lo = 0.0, dn_hi = 0.0;
    Py_ssize_t n_up = 0, n_dn = 0;

    std::vector<double> abs_vals(n);

    for (Py_ssize_t i = 0; i < n; i++) {
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
    double var = sq_total / n - mean * mean;
    if (var < 0) var = 0.0;

    double median;
    if (n % 2 == 1) {
        std::nth_element(abs_vals.begin(), abs_vals.begin() + n / 2, abs_vals.end());
        median = abs_vals[n / 2];
    } else {
        std::nth_element(abs_vals.begin(), abs_vals.begin() + n / 2, abs_vals.end());
        double right = abs_vals[n / 2];
        double left = abs_vals[0];
        for (Py_ssize_t i = 1; i < n / 2; i++) {
            if (abs_vals[i] > left) left = abs_vals[i];
        }
        median = (left + right) * 0.5;
    }

    double up_mean = 0.0, up_std = 0.0;
    if (n_up > 1) {
        up_mean = up_total / n_up;
        double up_var = up_sq / n_up - up_mean * up_mean;
        up_std = sqrt(dmax(0.0, up_var));
    } else if (n_up == 1) { up_mean = up_total; }

    double dn_mean = 0.0, dn_std = 0.0;
    if (n_dn > 1) {
        dn_mean = dn_total / n_dn;
        double dn_var = dn_sq / n_dn - dn_mean * dn_mean;
        dn_std = sqrt(dmax(0.0, dn_var));
    } else if (n_dn == 1) { dn_mean = dn_total; }

    s.mean = mean; s.std_val = sqrt(var); s.var = var;
    s.lo = lo; s.hi = hi; s.median = median; s.total = total;
    s.up_mean = up_mean; s.up_std = up_std; s.up_lo = up_lo;
    s.up_hi = up_hi; s.up_total = up_total;
    s.dn_mean = dn_mean; s.dn_std = dn_std; s.dn_lo = dn_lo;
    s.dn_hi = dn_hi; s.dn_total = dn_total;
    s.n_up = n_up; s.n_dn = n_dn;
    return s;
}

static py::dict stats_to_pydict(const ArrayStats& s) {
    return py::dict(
        "mean"_a = s.mean, "std"_a = s.std_val, "var"_a = s.var,
        "min"_a = s.lo, "max"_a = s.hi, "range"_a = s.hi - s.lo,
        "median"_a = s.median, "sum"_a = s.total,
        "up_mean"_a = s.up_mean, "up_std"_a = s.up_std,
        "up_min"_a = s.up_lo, "up_max"_a = s.up_hi,
        "up_sum"_a = s.up_total, "up_count"_a = s.n_up,
        "down_mean"_a = s.dn_mean, "down_std"_a = s.dn_std,
        "down_min"_a = s.dn_lo, "down_max"_a = s.dn_hi,
        "down_sum"_a = s.dn_total, "down_count"_a = s.n_dn,
        "count"_a = s.n
    );
}

// Batch: compute stats for multiple named arrays in one C++ call
// Returns (names_list, flat_array) where flat_array has 21 doubles per array
static constexpr int STATS_PER_ARRAY = 21;

static py::tuple compute_batch_stats_flat_impl(py::dict named_arrays) {
    // Collect names and arrays
    std::vector<std::string> names;
    std::vector<ArrayStats> all_stats;

    for (auto& item : named_arrays) {
        auto arr = py::cast<py::array_t<double, py::array::c_style | py::array::forcecast>>(item.second);
        auto buf = arr.request();
        Py_ssize_t n = buf.size;
        if (n == 0) continue;
        names.push_back(py::cast<std::string>(item.first));
        all_stats.push_back(compute_stats_core(static_cast<double*>(buf.ptr), n));
    }

    Py_ssize_t count = static_cast<Py_ssize_t>(names.size());
    // Create flat numpy array: count * 21 doubles
    auto result_arr = py::array_t<double>(count * STATS_PER_ARRAY);
    auto result_buf = result_arr.request();
    double* out = static_cast<double*>(result_buf.ptr);

    for (Py_ssize_t i = 0; i < count; i++) {
        const ArrayStats& s = all_stats[i];
        double* row = out + i * STATS_PER_ARRAY;
        row[0] = s.mean;      row[1] = s.std_val;   row[2] = s.var;
        row[3] = s.lo;        row[4] = s.hi;        row[5] = s.hi - s.lo;
        row[6] = s.median;    row[7] = s.total;
        row[8] = s.up_mean;   row[9] = s.up_std;    row[10] = s.up_lo;
        row[11] = s.up_hi;    row[12] = s.up_total;  row[13] = static_cast<double>(s.n_up);
        row[14] = s.dn_mean;  row[15] = s.dn_std;   row[16] = s.dn_lo;
        row[17] = s.dn_hi;    row[18] = s.dn_total;  row[19] = static_cast<double>(s.n_dn);
        row[20] = static_cast<double>(s.n);
    }

    py::list name_list;
    for (auto& nm : names) name_list.append(nm);

    return py::make_tuple(name_list, result_arr);
}

PYBIND11_MODULE(_wa1kpcap_native, m) {
    m.doc() = "wa1kpcap native C++ engine";

    // ── Native struct types (no shared_ptr — embedded directly in NativeParsedPacket) ──

    py::class_<NativeEthernetInfo>(m, "NativeEthernetInfo")
        .def(py::init<>())
        .def_readwrite("src", &NativeEthernetInfo::src)
        .def_readwrite("dst", &NativeEthernetInfo::dst)
        .def_readwrite("type", &NativeEthernetInfo::type);

    py::class_<NativeIPInfo>(m, "NativeIPInfo")
        .def(py::init<>())
        .def_readwrite("version", &NativeIPInfo::version)
        .def_readwrite("src", &NativeIPInfo::src)
        .def_readwrite("dst", &NativeIPInfo::dst)
        .def_readwrite("proto", &NativeIPInfo::proto)
        .def_readwrite("ttl", &NativeIPInfo::ttl)
        .def_readwrite("len", &NativeIPInfo::len)
        .def_readwrite("id", &NativeIPInfo::id)
        .def_readwrite("flags", &NativeIPInfo::flags)
        .def_readwrite("offset", &NativeIPInfo::offset)
        .def_property_readonly("is_fragment", &NativeIPInfo::is_fragment)
        .def_property_readonly("is_fragmented", &NativeIPInfo::more_fragments)
        .def_property_readonly("more_fragments", &NativeIPInfo::more_fragments);

    py::class_<NativeIP6Info>(m, "NativeIP6Info")
        .def(py::init<>())
        .def_readwrite("version", &NativeIP6Info::version)
        .def_readwrite("src", &NativeIP6Info::src)
        .def_readwrite("dst", &NativeIP6Info::dst)
        .def_readwrite("next_header", &NativeIP6Info::next_header)
        .def_readwrite("hop_limit", &NativeIP6Info::hop_limit)
        .def_readwrite("flow_label", &NativeIP6Info::flow_label)
        .def_readwrite("len", &NativeIP6Info::len);

    py::class_<NativeTCPInfo>(m, "NativeTCPInfo")
        .def(py::init<>())
        .def_readwrite("sport", &NativeTCPInfo::sport)
        .def_readwrite("dport", &NativeTCPInfo::dport)
        .def_readwrite("seq", &NativeTCPInfo::seq)
        .def_readwrite("ack_num", &NativeTCPInfo::ack_num)
        .def_readwrite("flags", &NativeTCPInfo::flags)
        .def_readwrite("win", &NativeTCPInfo::win)
        .def_readwrite("urgent", &NativeTCPInfo::urgent)
        .def_property("options",
            [](const NativeTCPInfo& self) { return py::bytes(self.options); },
            [](NativeTCPInfo& self, py::bytes v) { self.options = std::string(v); })
        .def_property_readonly("syn", &NativeTCPInfo::syn)
        .def_property_readonly("fin", &NativeTCPInfo::fin)
        .def_property_readonly("rst", &NativeTCPInfo::rst)
        .def_property_readonly("psh", &NativeTCPInfo::psh)
        .def_property_readonly("ack", &NativeTCPInfo::ack)
        .def_property_readonly("urg", &NativeTCPInfo::urg)
        .def_property_readonly("ece", &NativeTCPInfo::ece)
        .def_property_readonly("cwr", &NativeTCPInfo::cwr)
        .def_property_readonly("is_handshake", &NativeTCPInfo::is_handshake)
        .def_property_readonly("is_handshake_ack", &NativeTCPInfo::is_handshake_ack);

    py::class_<NativeUDPInfo>(m, "NativeUDPInfo")
        .def(py::init<>())
        .def_readwrite("sport", &NativeUDPInfo::sport)
        .def_readwrite("dport", &NativeUDPInfo::dport)
        .def_readwrite("len", &NativeUDPInfo::len);

    py::class_<NativeTLSInfo>(m, "NativeTLSInfo")
        .def(py::init<>())
        .def_readwrite("version", &NativeTLSInfo::version)
        .def_readwrite("content_type", &NativeTLSInfo::content_type)
        .def_readwrite("handshake_type", &NativeTLSInfo::handshake_type)
        .def_readwrite("sni", &NativeTLSInfo::sni)
        .def_readwrite("cipher_suites", &NativeTLSInfo::cipher_suites)
        .def_readwrite("cipher_suite", &NativeTLSInfo::cipher_suite)
        .def_readwrite("record_length", &NativeTLSInfo::record_length)
        .def_readwrite("alpn", &NativeTLSInfo::alpn)
        .def_readwrite("signature_algorithms", &NativeTLSInfo::signature_algorithms)
        .def_readwrite("supported_groups", &NativeTLSInfo::supported_groups)
        .def_readwrite("handshake_types", &NativeTLSInfo::handshake_types)
        .def_readwrite("certificates", &NativeTLSInfo::certificates);

    py::class_<NativeDNSInfo>(m, "NativeDNSInfo")
        .def(py::init<>())
        .def_readwrite("queries", &NativeDNSInfo::queries)
        .def_readwrite("response_code", &NativeDNSInfo::response_code)
        .def_readwrite("question_count", &NativeDNSInfo::question_count)
        .def_readwrite("answer_count", &NativeDNSInfo::answer_count)
        .def_readwrite("authority_count", &NativeDNSInfo::authority_count)
        .def_readwrite("additional_count", &NativeDNSInfo::additional_count)
        .def_readwrite("flags", &NativeDNSInfo::flags)
        .def_property_readonly("is_query", &NativeDNSInfo::is_query)
        .def_property_readonly("is_response", &NativeDNSInfo::is_response);

    py::class_<NativeARPInfo>(m, "NativeARPInfo")
        .def(py::init<>())
        .def_readwrite("hw_type", &NativeARPInfo::hw_type)
        .def_readwrite("proto_type", &NativeARPInfo::proto_type)
        .def_readwrite("opcode", &NativeARPInfo::opcode)
        .def_readwrite("sender_mac", &NativeARPInfo::sender_mac)
        .def_readwrite("sender_ip", &NativeARPInfo::sender_ip)
        .def_readwrite("target_mac", &NativeARPInfo::target_mac)
        .def_readwrite("target_ip", &NativeARPInfo::target_ip);

    py::class_<NativeICMPInfo>(m, "NativeICMPInfo")
        .def(py::init<>())
        .def_readwrite("type", &NativeICMPInfo::type)
        .def_readwrite("code", &NativeICMPInfo::code)
        .def_readwrite("checksum", &NativeICMPInfo::checksum)
        .def_property("rest_data",
            [](const NativeICMPInfo& self) { return py::bytes(self.rest_data); },
            [](NativeICMPInfo& self, const std::string& v) { self.rest_data = v; });

    py::class_<NativeICMP6Info>(m, "NativeICMP6Info")
        .def(py::init<>())
        .def_readwrite("type", &NativeICMP6Info::type)
        .def_readwrite("code", &NativeICMP6Info::code)
        .def_readwrite("checksum", &NativeICMP6Info::checksum)
        .def_property("rest_data",
            [](const NativeICMP6Info& self) { return py::bytes(self.rest_data); },
            [](NativeICMP6Info& self, const std::string& v) { self.rest_data = v; });

    py::class_<NativeGREInfo>(m, "NativeGREInfo")
        .def(py::init<>())
        .def_readwrite("flags", &NativeGREInfo::flags)
        .def_readwrite("protocol_type", &NativeGREInfo::protocol_type)
        .def_readwrite("checksum", &NativeGREInfo::checksum)
        .def_readwrite("key", &NativeGREInfo::key)
        .def_readwrite("sequence", &NativeGREInfo::sequence)
        .def_readwrite("has_checksum", &NativeGREInfo::has_checksum)
        .def_readwrite("has_key", &NativeGREInfo::has_key)
        .def_readwrite("has_sequence", &NativeGREInfo::has_sequence);

    py::class_<NativeVXLANInfo>(m, "NativeVXLANInfo")
        .def(py::init<>())
        .def_readwrite("flags", &NativeVXLANInfo::flags)
        .def_readwrite("vni", &NativeVXLANInfo::vni);

    py::class_<NativeMPLSInfo>(m, "NativeMPLSInfo")
        .def(py::init<>())
        .def_readwrite("label", &NativeMPLSInfo::label)
        .def_readwrite("tc", &NativeMPLSInfo::tc)
        .def_readwrite("ttl", &NativeMPLSInfo::ttl)
        .def_readwrite("stack_depth", &NativeMPLSInfo::stack_depth)
        .def_readwrite("bottom_of_stack", &NativeMPLSInfo::bottom_of_stack);

    py::class_<NativeDHCPInfo>(m, "NativeDHCPInfo")
        .def(py::init<>())
        .def_readwrite("op", &NativeDHCPInfo::op)
        .def_readwrite("htype", &NativeDHCPInfo::htype)
        .def_readwrite("xid", &NativeDHCPInfo::xid)
        .def_readwrite("ciaddr", &NativeDHCPInfo::ciaddr)
        .def_readwrite("yiaddr", &NativeDHCPInfo::yiaddr)
        .def_readwrite("siaddr", &NativeDHCPInfo::siaddr)
        .def_readwrite("giaddr", &NativeDHCPInfo::giaddr)
        .def_readwrite("chaddr", &NativeDHCPInfo::chaddr)
        .def_readwrite("options_raw", &NativeDHCPInfo::options_raw);

    py::class_<NativeDHCPv6Info>(m, "NativeDHCPv6Info")
        .def(py::init<>())
        .def_readwrite("msg_type", &NativeDHCPv6Info::msg_type)
        .def_readwrite("transaction_id", &NativeDHCPv6Info::transaction_id)
        .def_readwrite("options_raw", &NativeDHCPv6Info::options_raw);

    py::class_<NativeParsedPacket>(m, "NativeParsedPacket")
        .def(py::init<>())
        .def_readwrite("timestamp", &NativeParsedPacket::timestamp)
        .def_property("raw_data",
            [](const NativeParsedPacket& self) { return py::bytes(self.raw_data); },
            [](NativeParsedPacket& self, py::bytes v) { self.raw_data = std::string(v); })
        .def_readwrite("link_layer_type", &NativeParsedPacket::link_layer_type)
        .def_readwrite("caplen", &NativeParsedPacket::caplen)
        .def_readwrite("wirelen", &NativeParsedPacket::wirelen)
        .def_readwrite("ip_len", &NativeParsedPacket::ip_len)
        .def_readwrite("trans_len", &NativeParsedPacket::trans_len)
        .def_readwrite("app_len", &NativeParsedPacket::app_len)
        // Protocol layers: return None if not present, else reference to embedded struct
        .def_property("eth",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_eth) return py::none();
                return py::cast(&self.eth, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_eth = false; }
                else { self.eth = val.cast<NativeEthernetInfo&>(); self.has_eth = true; }
            })
        .def_property("ip",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_ip) return py::none();
                return py::cast(&self.ip, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_ip = false; }
                else { self.ip = val.cast<NativeIPInfo&>(); self.has_ip = true; }
            })
        .def_property("ip6",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_ip6) return py::none();
                return py::cast(&self.ip6, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_ip6 = false; }
                else { self.ip6 = val.cast<NativeIP6Info&>(); self.has_ip6 = true; }
            })
        .def_property("tcp",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_tcp) return py::none();
                return py::cast(&self.tcp, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_tcp = false; }
                else { self.tcp = val.cast<NativeTCPInfo&>(); self.has_tcp = true; }
            })
        .def_property("udp",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_udp) return py::none();
                return py::cast(&self.udp, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_udp = false; }
                else { self.udp = val.cast<NativeUDPInfo&>(); self.has_udp = true; }
            })
        .def_property("tls",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_tls) return py::none();
                return py::cast(&self.tls, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_tls = false; }
                else { self.tls = val.cast<NativeTLSInfo&>(); self.has_tls = true; }
            })
        .def_property("dns",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_dns) return py::none();
                return py::cast(&self.dns, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_dns = false; }
                else { self.dns = val.cast<NativeDNSInfo&>(); self.has_dns = true; }
            })
        .def_property("arp",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_arp) return py::none();
                return py::cast(&self.arp, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_arp = false; }
                else { self.arp = val.cast<NativeARPInfo&>(); self.has_arp = true; }
            })
        .def_property("icmp",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_icmp) return py::none();
                return py::cast(&self.icmp, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_icmp = false; }
                else { self.icmp = val.cast<NativeICMPInfo&>(); self.has_icmp = true; }
            })
        .def_property("icmp6",
            [](py::object self_py) -> py::object {
                auto& self = self_py.cast<NativeParsedPacket&>();
                if (!self.has_icmp6) return py::none();
                return py::cast(&self.icmp6, py::return_value_policy::reference_internal, self_py);
            },
            [](NativeParsedPacket& self, py::object val) {
                if (val.is_none()) { self.has_icmp6 = false; }
                else { self.icmp6 = val.cast<NativeICMP6Info&>(); self.has_icmp6 = true; }
            })
        .def_readwrite("is_client_to_server", &NativeParsedPacket::is_client_to_server)
        .def_readwrite("packet_index", &NativeParsedPacket::packet_index)
        .def_readwrite("flow_index", &NativeParsedPacket::flow_index)
        .def_property("_raw_tcp_payload",
            [](const NativeParsedPacket& self) { return py::bytes(self._raw_tcp_payload); },
            [](NativeParsedPacket& self, py::bytes v) { self._raw_tcp_payload = std::string(v); })
        .def_property_readonly("payload",
            [](const NativeParsedPacket& self) { return py::bytes(self._raw_tcp_payload); })
        .def_property_readonly("has_payload",
            [](const NativeParsedPacket& self) { return !self._raw_tcp_payload.empty(); })
        .def_readwrite("tls_bytes_consumed", &NativeParsedPacket::tls_bytes_consumed);

    // ── PcapReader ──
    py::class_<NativePcapReader>(m, "NativePcapReader")
        .def(py::init<const std::string&>(), py::arg("path"))
        .def("__iter__", [](NativePcapReader& self) -> NativePcapReader& {
            self.open();
            return self;
        }, py::return_value_policy::reference_internal)
        .def("__next__", [](NativePcapReader& self) -> py::tuple {
            auto pkt = self.next();
            if (!pkt.has_value()) throw py::stop_iteration();
            auto& [ts, data, caplen, wirelen, link_type] = *pkt;
            return py::make_tuple(ts, py::bytes(reinterpret_cast<const char*>(data.data()), data.size()),
                                  caplen, wirelen, link_type);
        })
        .def("open", &NativePcapReader::open)
        .def("close", &NativePcapReader::close)
        .def_property_readonly("link_type", &NativePcapReader::link_type)
        .def("__enter__", [](NativePcapReader& self) -> NativePcapReader& {
            self.open();
            return self;
        }, py::return_value_policy::reference_internal)
        .def("__exit__", [](NativePcapReader& self, py::object, py::object, py::object) {
            self.close();
        });

    // ── NativeParser ──
    py::class_<NativeParser>(m, "NativeParser")
        .def(py::init<const std::string&>(), py::arg("protocols_dir"))
        .def("parse_packet", &NativeParser::parse_packet,
             py::arg("buf"), py::arg("link_type"), py::arg("save_raw_bytes") = false)
        .def("parse_packet_struct", &NativeParser::parse_packet_struct,
             py::arg("buf"), py::arg("link_type"), py::arg("save_raw_bytes") = false,
             py::arg("app_layer_mode") = 0)
        .def("parse_tls_record", &NativeParser::parse_tls_record,
             py::arg("buf"))
        .def("load_extra_file", &NativeParser::load_extra_file,
             py::arg("file_path"))
        .def("add_protocol_routing", &NativeParser::add_protocol_routing,
             py::arg("parent_proto"), py::arg("value"), py::arg("target_proto"))
        .def("parse_to_dataclass", [](NativeParser& self, py::bytes buf,
                                       uint32_t link_type, bool save_raw_bytes,
                                       double timestamp, int caplen, int wirelen,
                                       int app_layer_mode) -> py::object {
            // Parse to C++ struct (fast, no dict/converter overhead)
            NativeParsedPacket pkt = self.parse_packet_struct(buf, link_type, save_raw_bytes, app_layer_mode);
            return build_dataclass_from_struct(pkt, buf, timestamp, link_type, caplen, wirelen);
        }, py::arg("buf"), py::arg("link_type"), py::arg("save_raw_bytes") = false,
           py::arg("timestamp") = 0.0, py::arg("caplen") = 0, py::arg("wirelen") = 0,
           py::arg("app_layer_mode") = 0);

    // ── NativeFilter ──
    py::class_<NativeFilter>(m, "NativeFilter")
        .def(py::init<const std::string&>(), py::arg("filter_str"))
        .def("matches", &NativeFilter::matches, py::arg("parsed_dict"))
        .def("matches_raw", [](const NativeFilter& self, py::bytes buf, uint32_t link_type) {
            std::string data = buf;
            return self.matches_raw(
                reinterpret_cast<const uint8_t*>(data.data()), data.size(), link_type);
        }, py::arg("buf"), py::arg("link_type"))
        .def("can_match_raw", &NativeFilter::can_match_raw);

    // ── FlowBuffer ──
    py::class_<FlowBuffer>(m, "FlowBuffer")
        .def(py::init<>())
        .def("append", [](FlowBuffer& self, py::bytes data) {
            std::string s = data;
            self.append(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        })
        .def("available", &FlowBuffer::available)
        .def("try_parse_app", &FlowBuffer::try_parse_app,
             py::arg("engine"), py::arg("protocol"))
        .def("clear", &FlowBuffer::clear);

    // ── NativePipeline: fused read→filter→parse→dataclass in C++ ──
    // Eliminates per-packet Python↔C++ boundary crossing.
    // Python sees this as an iterator yielding ParsedPacket dataclasses.

    struct NativePipeline {
        NativePcapReader reader;
        const ProtocolEngine* engine;  // borrowed from NativeParser
        const NativeFilter* filter;    // may be nullptr
        bool filter_can_raw;
        bool save_raw_bytes;
        bool opened;
        int app_layer_mode;

        NativePipeline(const std::string& path, NativeParser& parser,
                       NativeFilter* filt, bool save_raw, int app_mode)
            : reader(path), engine(&parser.engine()), filter(filt),
              filter_can_raw(filt ? filt->can_match_raw() : false),
              save_raw_bytes(save_raw), opened(false), app_layer_mode(app_mode) {}
    };

    py::class_<NativePipeline>(m, "NativePipeline")
        .def(py::init([](const std::string& path, NativeParser& parser,
                         py::object filter_obj, bool save_raw_bytes, int app_layer_mode) {
            NativeFilter* filt = nullptr;
            if (!filter_obj.is_none()) {
                filt = filter_obj.cast<NativeFilter*>();
            }
            return std::make_unique<NativePipeline>(path, parser, filt, save_raw_bytes, app_layer_mode);
        }), py::arg("path"), py::arg("parser"), py::arg("filter") = py::none(),
            py::arg("save_raw_bytes") = false, py::arg("app_layer_mode") = 0,
            // Keep parser and filter alive while pipeline exists
            py::keep_alive<1, 3>(), py::keep_alive<1, 4>())
        .def("__enter__", [](NativePipeline& self) -> NativePipeline& {
            self.reader.open();
            self.opened = true;
            return self;
        })
        .def("__exit__", [](NativePipeline& self, py::object, py::object, py::object) {
            self.reader.close();
            self.opened = false;
        })
        .def("__iter__", [](NativePipeline& self) -> NativePipeline& { return self; })
        .def("__next__", [](NativePipeline& self) -> py::object {
            // Loop until we find a packet that passes the filter, or EOF
            while (true) {
                auto view = self.reader.next_view();
                if (!view.has_value()) {
                    throw py::stop_iteration();
                }

                const uint8_t* buf = view->data;
                size_t len = view->caplen;
                uint32_t pkt_link_type = view->link_type;

                // Fast raw-byte pre-filter
                if (self.filter && self.filter_can_raw) {
                    if (!self.filter->matches_raw(buf, len, pkt_link_type)) {
                        continue;
                    }
                }

                // Parse to C++ struct (zero-copy from mmap'd buffer)
                NativeParsedPacket pkt = self.engine->parse_packet_struct(
                    buf, len, pkt_link_type, self.save_raw_bytes, self.app_layer_mode);

                // App-layer filter fallback (needs parsed fields)
                if (self.filter && !self.filter_can_raw) {
                    py::dict parsed_dict = self.engine->parse_packet(
                        buf, len, pkt_link_type, self.save_raw_bytes);
                    if (!self.filter->matches(parsed_dict)) {
                        continue;
                    }
                }

                // Build Python bytes from mmap'd data (single copy, only for matched packets)
                py::bytes raw_data_py(reinterpret_cast<const char*>(buf), len);
                return build_dataclass_from_struct(
                    pkt, raw_data_py, view->timestamp, pkt_link_type,
                    view->caplen, view->wirelen);
            }
        });

    // ── compute_array_stats: single-pass statistics for numpy arrays ──
    m.def("compute_array_stats", &compute_array_stats_impl, py::arg("arr"));

    // ── compute_batch_stats: batch stats for multiple arrays in one call ──
    m.def("compute_batch_stats", &compute_batch_stats_flat_impl, py::arg("named_arrays"));

    // ── Profiling API ──
    m.def("profiling_enable", []() { g_profiling_enabled = true; g_prof.reset(); });
    m.def("profiling_disable", []() { g_profiling_enabled = false; });
    m.def("profiling_reset", []() { g_prof.reset(); });
    m.def("profiling_get_stats", []() -> py::dict {
        py::dict d;
        d["total_ns"] = g_prof.total_ns.load();
        d["parse_layer_ns"] = g_prof.parse_layer_ns.load();
        d["fill_struct_ns"] = g_prof.fill_struct_ns.load();
        d["next_proto_ns"] = g_prof.next_proto_ns.load();
        d["total_packets"] = g_prof.total_packets.load();
        d["total_layers"] = g_prof.total_layers.load();

        // Per-primitive breakdown
        py::dict prims;
        auto add_prim = [&](const char* name, uint64_t ns, uint64_t count) {
            py::dict p;
            p["ns"] = ns;
            p["count"] = count;
            prims[name] = p;
        };
        add_prim("fixed", g_prof.fixed_ns.load(), g_prof.fixed_count.load());
        add_prim("bitfield", g_prof.bitfield_ns.load(), g_prof.bitfield_count.load());
        add_prim("computed", g_prof.computed_ns.load(), g_prof.computed_count.load());
        add_prim("length_prefixed", g_prof.length_prefixed_ns.load(), g_prof.length_prefixed_count.load());
        add_prim("hardcoded", g_prof.hardcoded_ns.load(), g_prof.hardcoded_count.load());
        add_prim("tlv", g_prof.tlv_ns.load(), g_prof.tlv_count.load());
        add_prim("counted_list", g_prof.counted_list_ns.load(), g_prof.counted_list_count.load());
        add_prim("rest", g_prof.rest_ns.load(), g_prof.rest_count.load());
        add_prim("prefixed_list", g_prof.prefixed_list_ns.load(), g_prof.prefixed_list_count.load());
        add_prim("repeat", g_prof.repeat_ns.load(), g_prof.repeat_count.load());
        add_prim("ext_list", g_prof.ext_list_ns.load(), g_prof.ext_list_count.load());
        d["primitives"] = prims;

        return d;
    });
}
