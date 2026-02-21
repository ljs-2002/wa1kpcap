find_package(pybind11 CONFIG REQUIRED)

# Fetch yaml-cpp
# yaml-cpp 0.8.0 uses cmake_minimum_required < 3.5, which CMake 4.0+ rejects
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
include(FetchContent)
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG 0.8.0
)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yaml-cpp)

set(NATIVE_SOURCES
    bindings.cpp
    pcap_reader.cpp
    protocol_engine.cpp
    quic_crypto.cpp
    yaml_loader.cpp
    bpf_filter.cpp
    flow_buffer.cpp
    expression_eval.cpp
    hardcoded_parsers.cpp
)

pybind11_add_module(_wa1kpcap_native ${NATIVE_SOURCES})

target_link_libraries(_wa1kpcap_native PRIVATE yaml-cpp::yaml-cpp)

target_include_directories(_wa1kpcap_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Install the module into the wa1kpcap package
install(TARGETS _wa1kpcap_native DESTINATION wa1kpcap)
