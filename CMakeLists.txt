cmake_minimum_required(VERSION 3.15)
project(wa1kpcap_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BUILD_NATIVE "Build native C++ engine" ON)

if(BUILD_NATIVE)
    add_subdirectory(src/cpp)
endif()
