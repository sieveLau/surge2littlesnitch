#include "rule_holder.hpp"

rule_holder::rule_holder(const rule_holder& another): rule_holder() {
    for(auto&& host : another.hosts){
        hosts.emplace_back(host);
    }
    for(auto&& domain : another.domains){
        domains.emplace_back(domain);
    }
    for(auto&& an_ip : another.ip){
        ip.emplace_back(an_ip);
    }
}