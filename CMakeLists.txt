cmake_minimum_required(VERSION 3.15)

project(surge2littlesnitch)

set(CMAKE_CXX_STANDARD 17)

ADD_SUBDIRECTORY(ext/curlcpp)
INCLUDE_DIRECTORIES(ext/curlcpp)
ADD_SUBDIRECTORY(ext/json)
INCLUDE_DIRECTORIES(ext/json)

add_subdirectory(cidr2range)

add_library(rule_holder rule_holder.hpp rule_holder.cpp)

add_executable(surge2ls main.cpp)

target_link_libraries(surge2ls curlcpp::curlcpp nlohmann_json::nlohmann_json)