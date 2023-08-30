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
void rule_holder::add_domain(std::string domain, bool host) {
    if (host){
        hosts.emplace_back(std::move(domain));
    } else
        domains.emplace_back(std::move(domain));
}
void rule_holder::add_ip(std::string ip) {
    this->ip.emplace_back(std::move(ip));
}

std::string vector_to_string(const std::vector<std::string>& v){
    if (v.empty()) return "";
    std::string string_builder;
    const auto end = v.end();
    for (auto i = v.begin();;) {
        string_builder.append("\"");
        string_builder.append(*i);
        string_builder.append("\"");
        if (++i == end) break;
        string_builder.append(", ");
    }
    return string_builder;
}

std::map<std::string,std::string> rule_holder::to_string() {
    std::map<std::string,std::string> return_val;

    return_val["domain"]=vector_to_string(domains);
    return_val["host"]=vector_to_string(hosts);
    return_val["ip"]=vector_to_string(ip);
    return return_val;
}
