#include "cidr2range.hpp"

int main(int argc, char **argv) {

  // printf("%s\n",cidr2range(argv[1]).c_str());
  assert(cidr2range("118.89.204.198/23") == "118.89.204.0-118.89.205.255");
  assert(cidr2range("118.89.204.198/32") == "118.89.204.198-118.89.204.198");
  return 0;
}