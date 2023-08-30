include_guard()

add_library(cidr2range cidr2range.hpp cidr2range.cpp)

enable_testing()

find_package(GTest)

add_executable(test_cidr2range test.cpp)

target_link_libraries(test_cidr2range cidr2range GTest::gtest_main)
if(WIN32)
  target_link_libraries(test_cidr2range wsock32 ws2_32)
endif()

include(GoogleTest)
gtest_discover_tests(test_cidr2range)