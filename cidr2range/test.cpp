#include "cidr2range.hpp"
#include "include/gtest/gtest.h"

TEST(IPV4,NO_FREE_BIT){
	EXPECT_STREQ(cidr2range("118.89.204.198/32").c_str(),"118.89.204.198-118.89.204.198");
}

TEST(IPV4, FREE_BIT){
	EXPECT_STREQ(cidr2range("118.89.204.198/23").c_str(),"118.89.204.0-118.89.205.255");
}

//int main(int argc, char **argv) {
//
//  // printf("%s\n",cidr2range(argv[1]).c_str());
//  assert(cidr2range("118.89.204.198/23") == "118.89.204.0-118.89.205.255");
//  assert(cidr2range("118.89.204.198/32") == "118.89.204.198-118.89.204.198");
//  assert(cidr2range("2402:4e00:1200:ed00:0:9089:6dac:96b6/112") == "2402:4e00:1200:ed00:0:9089:6dac:0-2402:4e00:1200:ed00:0:9089:6dac:ffff");
//  return 0;
//}