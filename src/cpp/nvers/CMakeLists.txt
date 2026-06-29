# nvers high-throughput feature extractors (libpcap + OpenSSL)
# All sources under src/cpp/nvers/

find_package(pybind11 CONFIG REQUIRED)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP libpcap)
endif()

if(NOT PCAP_FOUND)
    find_library(PCAP_LIBRARY NAMES pcap)
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
        set(PCAP_LIBRARIES ${PCAP_LIBRARY})
        set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
        set(PCAP_FOUND TRUE)
    endif()
endif()

if(NOT PCAP_FOUND)
    message(FATAL_ERROR "libpcap not found; install libpcap-dev")
endif()

find_package(OpenSSL REQUIRED)

set(NVERS_SOURCES
    nvers_api.cpp
    cic_extractor.cpp
    cicext_extractor.cpp
    seq_extractor.cpp
    payload_extractor.cpp
    tls_extractor.cpp
    dns_extractor.cpp
    smtp_extractor.cpp
    dhcp_extractor.cpp
    ftp_extractor.cpp
    pcap_split.cpp
    vpn_extractor.cpp
    vpn_detect.cpp
    im_extractor.cpp
    im_detect.cpp
    flow_extractor.cpp
    l7_extractors.cpp
    bindings.cpp
)

pybind11_add_module(_wa1kpcap_nvers ${NVERS_SOURCES})

target_compile_definitions(_wa1kpcap_nvers PRIVATE NVERS_LIBRARY)

target_include_directories(_wa1kpcap_nvers PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PCAP_INCLUDE_DIRS}
    ${Python3_INCLUDE_DIRS}
)

target_link_libraries(_wa1kpcap_nvers PRIVATE
    ${PCAP_LIBRARIES}
    Python3::Module
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
    m
)

install(TARGETS _wa1kpcap_nvers DESTINATION wa1kpcap)
