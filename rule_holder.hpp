#pragma once
#include <memory>
#include <vector>
#include <string>
#include <map>

class rule_holder {
    std::vector<std::string> hosts;
    std::vector<std::string> domains;
    std::vector<std::string> ip;
public:
  rule_holder() = default;
  rule_holder(const rule_holder &another);
  friend void swap(rule_holder &first, rule_holder &second)// nothrow
  {
    // enable ADL (not necessary in our case, but good practice)
    using std::swap;

    // by swapping the members of two objects,
    // the two objects are effectively swapped
    swap(first.hosts, second.hosts);
    swap(first.domains, second.domains);
    swap(first.ip, second.ip);
  }
  rule_holder &operator=(rule_holder other)// (1)
  {
    swap(*this, other);// (2)

    return *this;
  }
  rule_holder(rule_holder &&another) noexcept : rule_holder() {
    swap(*this, another);
  }
  ~rule_holder() = default;

  void add_domain(std::string domain, bool host = false);
  void add_ip(std::string ip);

  std::map<std::string,std::string> to_string();
};