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
    EXPECT_STREQ(cidr2range("118.89.204.198").c_str(), "118.89.204.198-118.89.204.198");
    EXPECT_STREQ(cidr2range("118.89.0.198/32").c_str(), "118.89.0.198-118.89.0.198");
    EXPECT_STREQ(cidr2range("118.0.204.198/32").c_str(), "118.0.204.198-118.0.204.198");
    EXPECT_STREQ(cidr2range("118.0.0.198/32").c_str(), "118.0.0.198-118.0.0.198");
}

TEST(IPV4, INVALID_DR){
    EXPECT_ANY_THROW(cidr2range("118.89.204.198/33"));
}

TEST(IPV4, INVALID_ADDR){
    EXPECT_ANY_THROW(cidr2range("118.89.204:198/31"));
    EXPECT_ANY_THROW(cidr2range("118.89.204.257"));
}

TEST(IPV6, FREE_BIT_NOT_ALIGNED) {
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/127").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:96b6-2402:4e00:1200:ed00:eef1:9089:6dac:96b7");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/126").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:96b4-2402:4e00:1200:ed00:eef1:9089:6dac:96b7");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/125").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:96b0-2402:4e00:1200:ed00:eef1:9089:6dac:96b7");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/124").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:96b0-2402:4e00:1200:ed00:eef1:9089:6dac:96bf");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/123").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:96a0-2402:4e00:1200:ed00:eef1:9089:6dac:96bf");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/122").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:9680-2402:4e00:1200:ed00:eef1:9089:6dac:96bf");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/121").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:9680-2402:4e00:1200:ed00:eef1:9089:6dac:96ff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/120").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:9600-2402:4e00:1200:ed00:eef1:9089:6dac:96ff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/119").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:9600-2402:4e00:1200:ed00:eef1:9089:6dac:97ff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/118").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:9400-2402:4e00:1200:ed00:eef1:9089:6dac:97ff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/117").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:9000-2402:4e00:1200:ed00:eef1:9089:6dac:97ff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/116").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:9000-2402:4e00:1200:ed00:eef1:9089:6dac:9fff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/115").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:8000-2402:4e00:1200:ed00:eef1:9089:6dac:9fff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/114").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:8000-2402:4e00:1200:ed00:eef1:9089:6dac:bfff");
        EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/113").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:8000-2402:4e00:1200:ed00:eef1:9089:6dac:ffff");
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

TEST(IPV6, NO_FREE_BIT) {
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6/128").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:96b6-2402:4e00:1200:ed00:eef1:9089:6dac:96b6");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:96b6").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:96b6-2402:4e00:1200:ed00:eef1:9089:6dac:96b6");
    EXPECT_STREQ(cidr2range("2402:0:1200:ed00:eef1:9089:6dac:96b6/128").c_str(), "2402:0:1200:ed00:eef1:9089:6dac:96b6-2402:0:1200:ed00:eef1:9089:6dac:96b6");
    EXPECT_STREQ(cidr2range("2402:4e00:0:ed00:eef1:9089:6dac:96b6/128").c_str(), "2402:4e00:0:ed00:eef1:9089:6dac:96b6-2402:4e00:0:ed00:eef1:9089:6dac:96b6");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:0:eef1:9089:6dac:96b6/128").c_str(), "2402:4e00:1200:0:eef1:9089:6dac:96b6-2402:4e00:1200:0:eef1:9089:6dac:96b6");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/128").c_str(), "2402:4e00:1200:ed00:0:9089:6dac:96b6-2402:4e00:1200:ed00:0:9089:6dac:96b6");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:0:6dac:96b6/128").c_str(), "2402:4e00:1200:ed00:eef1:0:6dac:96b6-2402:4e00:1200:ed00:eef1:0:6dac:96b6");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:0:96b6/128").c_str(), "2402:4e00:1200:ed00:eef1:9089:0:96b6-2402:4e00:1200:ed00:eef1:9089:0:96b6");
    EXPECT_STREQ(cidr2range("2402:4e00:1200:ed00:eef1:9089:6dac:0/128").c_str(), "2402:4e00:1200:ed00:eef1:9089:6dac:0-2402:4e00:1200:ed00:eef1:9089:6dac:0");
}

TEST(IPV6, INVALID_DR){
    EXPECT_ANY_THROW(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/129"));
}

TEST(IPV6, INVALID_ADDR){
    EXPECT_ANY_THROW(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:gggg"));
}