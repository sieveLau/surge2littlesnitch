cmake_minimum_required(VERSION 3.15)

project(surge2littlesnitch)

set(CMAKE_CXX_STANDARD 20)

ADD_SUBDIRECTORY(ext/curlcpp)
INCLUDE_DIRECTORIES(ext/curlcpp)
ADD_SUBDIRECTORY(ext/json)
INCLUDE_DIRECTORIES(ext/json)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(ext/gtest)
include_directories(ext/gtest/googletest)

add_subdirectory(cidr2range)

add_library(rule_holder rule_holder.hpp rule_holder.cpp)

add_executable(surge2ls main.cpp)

target_link_libraries(surge2ls curlcpp::curlcpp nlohmann_json::nlohmann_json cidr2range rule_holder)