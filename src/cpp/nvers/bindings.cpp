/**
 * pybind11 bindings for nvers feature extractors integrated into wa1kpcap.
 */
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "nvers_api.h"

namespace py = pybind11;

static wa1kpcap::nvers::ExtractConfig cfg_from_py(
    const std::string& pcap_path,
    const std::string& output_path,
    int n_limit,
    int workers,
    int filter_port,
    bool verbose) {
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_path;
    cfg.output_path = output_path;
    cfg.n_limit = n_limit;
    cfg.workers = workers;
    cfg.filter_port = filter_port;
    cfg.verbose = verbose;
    return cfg;
}

PYBIND11_MODULE(_wa1kpcap_nvers, m) {
    m.doc() = "wa1kpcap nvers native feature extractors (CIC, seq, TLS, ...)";

    py::enum_<wa1kpcap::nvers::FeatureKind>(m, "FeatureKind")
        .value("CIC", wa1kpcap::nvers::FeatureKind::CIC)
        .value("CICEXT", wa1kpcap::nvers::FeatureKind::CICEXT)
        .value("SEQ", wa1kpcap::nvers::FeatureKind::SEQ)
        .value("PAYLOAD", wa1kpcap::nvers::FeatureKind::PAYLOAD)
        .value("TLS", wa1kpcap::nvers::FeatureKind::TLS)
        .value("DNS", wa1kpcap::nvers::FeatureKind::DNS)
        .value("SMTP", wa1kpcap::nvers::FeatureKind::SMTP)
        .value("DHCP", wa1kpcap::nvers::FeatureKind::DHCP)
        .value("FTP", wa1kpcap::nvers::FeatureKind::FTP)
        .value("HTTP", wa1kpcap::nvers::FeatureKind::HTTP)
        .value("SSH", wa1kpcap::nvers::FeatureKind::SSH)
        .value("MQTT", wa1kpcap::nvers::FeatureKind::MQTT)
        .value("SIP", wa1kpcap::nvers::FeatureKind::SIP)
        .value("QUIC", wa1kpcap::nvers::FeatureKind::QUIC)
        .value("RDP", wa1kpcap::nvers::FeatureKind::RDP)
        .value("VNC", wa1kpcap::nvers::FeatureKind::VNC)
        .value("PCAP_SPLIT", wa1kpcap::nvers::FeatureKind::PCAP_SPLIT)
        .value("VPN", wa1kpcap::nvers::FeatureKind::VPN)
        .value("IM", wa1kpcap::nvers::FeatureKind::IM)
        .value("FLOW", wa1kpcap::nvers::FeatureKind::FLOW)
        .export_values();

    py::class_<wa1kpcap::nvers::ExtractResult>(m, "ExtractResult")
        .def_readonly("exit_code", &wa1kpcap::nvers::ExtractResult::exit_code)
        .def_readonly("message", &wa1kpcap::nvers::ExtractResult::message)
        .def_readonly("flows", &wa1kpcap::nvers::ExtractResult::flows)
        .def_readonly("packets", &wa1kpcap::nvers::ExtractResult::packets)
        .def_readonly("elapsed_sec", &wa1kpcap::nvers::ExtractResult::elapsed_sec)
        .def("__bool__", [](const wa1kpcap::nvers::ExtractResult& r) { return r.exit_code == 0; });

    py::class_<wa1kpcap::nvers::ExtractConfig>(m, "ExtractConfig")
        .def(py::init<>())
        .def_readwrite("pcap_path", &wa1kpcap::nvers::ExtractConfig::pcap_path)
        .def_readwrite("output_path", &wa1kpcap::nvers::ExtractConfig::output_path)
        .def_readwrite("n_limit", &wa1kpcap::nvers::ExtractConfig::n_limit)
        .def_readwrite("workers", &wa1kpcap::nvers::ExtractConfig::workers)
        .def_readwrite("filter_port", &wa1kpcap::nvers::ExtractConfig::filter_port)
        .def_readwrite("verbose", &wa1kpcap::nvers::ExtractConfig::verbose);

    m.def("default_output_name", &wa1kpcap::nvers::default_output_name);
    m.def("unified_sequence_fields", &wa1kpcap::nvers::unified_sequence_fields);
    m.def("wa1k_to_nvers_seq_key", &wa1kpcap::nvers::wa1k_to_nvers_seq_key);

    m.def("run_cic", [](const std::string& pcap, const std::string& out, int n, int j) {
        return wa1kpcap::nvers::run_cic(cfg_from_py(pcap, out, n, j, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("n_limit") = 0, py::arg("workers") = 0);

    m.def("run_cicext", [](const std::string& pcap, const std::string& out, int n, int j) {
        return wa1kpcap::nvers::run_cicext(cfg_from_py(pcap, out, n, j, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("n_limit") = 0, py::arg("workers") = 0);

    m.def("run_seq", [](const std::string& pcap, const std::string& out, int n, int j) {
        return wa1kpcap::nvers::run_seq(cfg_from_py(pcap, out, n, j, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("n_limit") = 0, py::arg("workers") = 0);

    m.def("run_payload", [](const std::string& pcap, const std::string& out, int n, int j) {
        return wa1kpcap::nvers::run_payload(cfg_from_py(pcap, out, n, j, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("n_limit") = 0, py::arg("workers") = 0);

    m.def("run_tls", [](const std::string& pcap, const std::string& out, int port) {
        return wa1kpcap::nvers::run_tls(cfg_from_py(pcap, out, 0, 0, port, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("filter_port") = 0);

    m.def("run_dns", [](const std::string& pcap, const std::string& out, bool verbose) {
        return wa1kpcap::nvers::run_dns(cfg_from_py(pcap, out, 0, 0, 0, verbose));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("verbose") = false);

    m.def("run_smtp", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_smtp(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_dhcp", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_dhcp(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_ftp", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_ftp(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_http", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_http(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_ssh", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_ssh(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_mqtt", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_mqtt(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_sip", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_sip(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_quic", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_quic(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_rdp", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_rdp(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_vnc", [](const std::string& pcap, const std::string& out) {
        return wa1kpcap::nvers::run_vnc(cfg_from_py(pcap, out, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_path") = "");

    m.def("run_pcap_split", [](const std::string& pcap, const std::string& out_dir) {
        return wa1kpcap::nvers::run_pcap_split(cfg_from_py(pcap, out_dir, 0, 0, 0, false));
    }, py::arg("pcap_path"), py::arg("output_dir") = "");

    m.def("run_vpn", [](const std::string& pcap, const std::string& out, bool verbose) {
        return wa1kpcap::nvers::run_vpn(cfg_from_py(pcap, out, 0, 0, 0, verbose));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("verbose") = false);

    m.def("run_im", [](const std::string& pcap, const std::string& out, bool verbose) {
        return wa1kpcap::nvers::run_im(cfg_from_py(pcap, out, 0, 0, 0, verbose));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("verbose") = false);

    m.def("run_flow", [](const std::string& pcap, const std::string& out, int n, bool verbose) {
        return wa1kpcap::nvers::run_flow(cfg_from_py(pcap, out, n, 0, 0, verbose));
    }, py::arg("pcap_path"), py::arg("output_path") = "",
       py::arg("n_limit") = 0, py::arg("verbose") = false);

    m.def("run_feature", &wa1kpcap::nvers::run_feature);
    m.def("run_batch", &wa1kpcap::nvers::run_batch);
}
