#include "cidr2range.hpp"
using std::regex;
using std::string;
using std::cmatch;
using std::bitset;
using std::cout;
using std::endl;

string cidr2range(const string& cidr){
    // string ip = "118.89.204.198/23";
    regex ipv4(R"((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})((\/)(\d{1,2}))?)");
    cmatch m;
    char ipv4_result_range[32]={'\0'};
    const char* ipv4_range_fmt = "%lu.%lu.%lu.%lu-%lu.%lu.%lu.%lu";
    if(regex_match(cidr.c_str(),m,ipv4)){
            auto first_eight_bits = stoi(m[1]);
            auto second_eight_bits = stoi(m[2]);
            auto third_eight_bits = stoi(m[3]);
            auto forth_eight_bits = stoi(m[4]);

            bitset<32> origin_in_binary((first_eight_bits << 24) + (second_eight_bits << 16) + (third_eight_bits << 8) + forth_eight_bits);
            bitset<32> netmask_in_binary;
            netmask_in_binary.set();

            if(m.size()>6){
                int origin_netmask_from_cidr = 32;
                // auto netmask_str = m[7].str();
                origin_netmask_from_cidr = stoi(m[7]);
                // cout<<origin_netmask_from_cidr<<endl;
                int bits_to_move = 32 - origin_netmask_from_cidr;
                netmask_in_binary <<= bits_to_move;
            }
            // cout<<netmask_in_binary<<endl;
            // cout<<origin_in_binary<<endl;
            auto begin_addr_in_binary = origin_in_binary&netmask_in_binary;
            auto end_addr_in_binary = origin_in_binary | netmask_in_binary.flip();

            const bitset<32> one("11111111000000000000000000000000");
            const bitset<32> two("00000000111111110000000000000000");
            const bitset<32> three("00000000000000001111111100000000");
            const bitset<32> four("00000000000000000000000011111111");

            // cout<<begin_addr_in_binary<<endl;
            // cout<<end_addr_in_binary<<endl;
            snprintf(ipv4_result_range,std::size(ipv4_result_range),
                ipv4_range_fmt,
                ((begin_addr_in_binary & one)>>24).to_ulong(),
                ((begin_addr_in_binary & two)>>16).to_ulong(),
                ((begin_addr_in_binary & three)>>8).to_ulong(),
                (begin_addr_in_binary & four).to_ulong(),
                ((end_addr_in_binary & one)>>24).to_ulong(),
                ((end_addr_in_binary & two)>>16).to_ulong(),
                ((end_addr_in_binary & three)>>8).to_ulong(),
                (end_addr_in_binary & four).to_ulong()
                );
            // cout<<((begin_addr_in_binary & one)>>24).to_ulong()<<endl;
            // cout<<((begin_addr_in_binary & two)>>16).to_ulong()<<endl;
            // cout<<((begin_addr_in_binary & three)>>8).to_ulong()<<endl;
            // cout<<(begin_addr_in_binary & four).to_ulong()<<endl;

            // cout<<((end_addr_in_binary & one)>>24).to_ulong()<<endl;
            // cout<<((end_addr_in_binary & two)>>16).to_ulong()<<endl;
            // cout<<((end_addr_in_binary & three)>>8).to_ulong()<<endl;
            // cout<<(end_addr_in_binary & four).to_ulong()<<endl;
            cout<< ipv4_result_range << endl;
            return ipv4_result_range;
    }
    return "";
}
