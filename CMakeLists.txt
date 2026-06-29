cmake_minimum_required(VERSION 3.15)
project(wa1kpcap_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Ensure pybind11 picks up the correct Python headers/libs (conda, venv, etc.)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

option(BUILD_NATIVE "Build native C++ engine" ON)
option(BUILD_NVERS "Build nvers feature extractors (libpcap + OpenSSL)" ON)

if(BUILD_NATIVE)
    add_subdirectory(src/cpp)
endif()

if(BUILD_NVERS)
    add_subdirectory(src/cpp/nvers)
endif()
