#include "cidr2range.hpp"
#include "include/gtest/gtest.h"

TEST(IPV4, FREE_BIT_NOT_ALIGNED) {
    EXPECT_STREQ(cidr2range("118.89.204.198/23").c_str(), "118.89.204.0-118.89.205.255");
    EXPECT_STREQ(cidr2range("118.89.243.198/22").c_str(), "118.89.240.0-118.89.243.255");
    EXPECT_STREQ(cidr2range("118.89.243.198/21").c_str(), "118.89.240.0-118.89.247.255");
    EXPECT_STREQ(cidr2range("118.89.243.198/20").c_str(), "118.89.240.0-118.89.255.255");
    EXPECT_STREQ(cidr2range("118.89.243.198/19").c_str(), "118.89.224.0-118.89.255.255");
    EXPECT_STREQ(cidr2range("118.89.243.198/18").c_str(), "118.89.192.0-118.89.255.255");
    EXPECT_STREQ(cidr2range("118.89.243.198/17").c_str(), "118.89.128.0-118.89.255.255");
}

TEST(IPV4, FREE_BIT_ALIGNED) {
    EXPECT_STREQ(cidr2range("118.89.204.198/24").c_str(), "118.89.204.0-118.89.204.255");
    EXPECT_STREQ(cidr2range("118.89.204.198/16").c_str(), "118.89.0.0-118.89.255.255");
    EXPECT_STREQ(cidr2range("118.89.204.198/8").c_str(), "118.0.0.0-118.255.255.255");
    EXPECT_STREQ(cidr2range("118.89.204.198/0").c_str(), "0.0.0.0-255.255.255.255");
}

TEST(IPV4, NO_FREE_BIT) {
    EXPECT_STREQ(cidr2range("118.89.204.198/32").c_str(), "118.89.204.198-118.89.204.198");
    EXPECT_STREQ(cidr2range("118.89.0.198/32").c_str(), "118.89.0.198-118.89.0.198");
    EXPECT_STREQ(cidr2range("118.0.204.198/32").c_str(), "118.0.204.198-118.0.204.198");
    EXPECT_STREQ(cidr2range("118.0.0.198/32").c_str(), "118.0.0.198-118.0.0.198");
}

TEST(IPV6, FREE_BIT_ALIGNED) {
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/112").c_str(),
                 "2402:4e00:1200:ed00:0:9089:6dac:0-2402:4e00:1200:ed00:0:9089:6dac:ffff");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/96").c_str(),
                 "2402:4e00:1200:ed00:0:9089::-2402:4e00:1200:ed00:0:9089:ffff:ffff");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/80").c_str(),
                 "2402:4e00:1200:ed00::-2402:4e00:1200:ed00:0:ffff:ffff:ffff");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/64").c_str(),
                 "2402:4e00:1200:ed00::-2402:4e00:1200:ed00:ffff:ffff:ffff:ffff");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/48").c_str(),
                 "2402:4e00:1200::-2402:4e00:1200:ffff:ffff:ffff:ffff:ffff");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/32").c_str(),
                 "2402:4e00::-2402:4e00:ffff:ffff:ffff:ffff:ffff:ffff");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/16").c_str(),
                 "2402::-2402:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/0").c_str(),
                 "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

// int main(int argc, char **argv) {
//
//   // printf("%s\n",cidr2range(argv[1]).c_str());
//   assert(cidr2range("118.89.204.198/23") == "118.89.204.0-118.89.205.255");
//   assert(cidr2range("118.89.204.198/32") == "118.89.204.198-118.89.204.198");
//   assert(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/112") ==
//   "2402:4e00:1200:ed00:0:9089:6dac:0-2402:4e00:1200:ed00:0:9089:6dac:ffff"); return 0;
// }