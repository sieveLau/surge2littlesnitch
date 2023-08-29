include_guard()

add_library(cidr2range cidr2range.hpp cidr2range.cpp)

include(CTest)

add_executable(test_cidr2range test.cpp)

target_link_libraries(test_cidr2range cidr2range)

add_test(NAME test_cidr2range
COMMAND test_cidr2range)