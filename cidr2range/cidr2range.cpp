#include "cidr2range.hpp"

#include <array>
#include <bitset>
#include <cmath>
#include <exception>
#include <regex>
#include <string>
using std::bitset;
using std::cmatch;
using std::cout;
using std::endl;
using std::regex;
using std::string;

// modified https://stackoverflow.com/a/48557165
/**
 * 将bitset按照给定的组大小进行顺序反转<br/>
 * 例如：11000110 11001100 01011001 01110110 会被翻转成 01110110 01011001 11001100 11000110<br/>
 * 主要用于inet_pton之后放进bitset里，而且符合直觉逻辑
 * @tparam N 传入的std::bitset的大小，自动获取
 * @param b 需要以组为单位翻转的bitset，会直接修改这个bitset
 * @param bit_per_group 每个组的bit数量
 * @return 成功则返回翻转的bitset，否则返回空
 */
template <std::size_t N>
std::bitset<N> reverse_by_group(const std::bitset<N> &b, size_t bit_per_group) {
    string str = b.to_string();
    if (str.empty() || str.length() % bit_per_group != 0) return {};

    auto *buffer_for_reversed_string = new char[str.length() + 1]{'\0'};
    const auto buf_len = str.length() + 1;
    buffer_for_reversed_string[buf_len - 1] = {'\0'};

    // 用于提取ipv4（二进制形式）各个位的正则表达式
    auto *reg_fmt_str = "\\d{%lu}";
    // 根据bit_per_group的数字位数来计算需要占用char[]的多少位
    // log10(n)向上取整就是10进制数的字符串形式需要占用的char数量
    size_t size_for_the_number = ceil(log10(bit_per_group));
    // 分配数组内存，数量=reg_fmt_str的长度-3-数字要占用的char位
    // 3是%lu，3个char
    auto *reg_str = new char[sizeof(reg_fmt_str) - 3 + size_for_the_number]{'\0'};
    snprintf(reg_str, sizeof(reg_str), reg_fmt_str, bit_per_group);
    std::regex reg(reg_str);
    delete[] reg_str;

    std::cmatch m;

    std::regex_token_iterator<std::string::iterator> rend;
    std::regex_token_iterator<std::string::iterator> a(str.begin(), str.end(), reg);
    for (int i = 1; a != rend; ++i) {
        // 确定这个token的大小
        auto size_to_write = a->length();
        auto str_to_copy = (*a).str();
        // 根据当前token大小、已经写入的token数量来确定从哪个position开始写
        // 以ipv4的8位为例，buffer总长33（4x8+string结束符1)，写入起始点33-1-8=24
        auto pos = buf_len - 1 - (size_to_write * i);
        for (auto &&ch : str_to_copy) {
            buffer_for_reversed_string[pos++] = ch;
        }
        a++;
    }

    //    printf("%s\n", buffer_for_reversed_string);

    auto return_result = std::bitset<N>(buffer_for_reversed_string);
    delete[] buffer_for_reversed_string;
    return return_result;
}

// https://stackoverflow.com/a/47328569
void printBinaryValue2(unsigned int num) {
    char result[sizeof(num) * 8];
    int count = 0;
    while (num) {
        result[count++] = ((num & 1 == 1) ? '1' : '0');
        num >>= 1;
    }
    if (count) {
        count--;
        while (count >= 0) {
            putchar(result[count--]);
        }
    } else {
        putchar('0');
    }
}

void set_bits(unsigned char *const in, const int full_length, const int dr, const int zero_or_one) {
    const int full_group_to_change = (full_length - dr) / 8;
    const int max_group_index = full_length / 8 - 1;
    const int remaining_bits_to_change = (full_length - dr) % 8;
    for (int i = max_group_index, j = full_group_to_change; j > 0; --i, --j) {
        in[i] = zero_or_one == 0 ? 0x0 : 0xFF;
    }
    const int group_to_change_by_bit = max_group_index - full_group_to_change;
    bitset<8> this_byte(in[group_to_change_by_bit]);

    for (int i = 0, j = remaining_bits_to_change; j > 0; ++i) {
        this_byte.set(i, zero_or_one);
        if (j > 0) --j;
        if (j == 0) {
            in[group_to_change_by_bit] = (unsigned char)this_byte.to_ulong();
            break;
        }
    }
}

string cidr2range(const string &cidr) {
    /*const int IPV4_LENGTH = 32;
    const int IPV6_LENGTH = 128;*/
    //   unsigned char buf[sizeof(struct in6_addr)];

    auto ci_dr = cidr.find_first_of('/');
    int dr;
    string ci, return_val;
    ci = cidr.substr(0, ci_dr);
    if (ci_dr == std::string::npos) {
        return_val.append(ci).append("-").append(ci);
        return return_val;
    } else {
        dr = stoi(cidr.substr(ci_dr + 1));
    }

    // int domain = 4;
    unsigned char in[sizeof(struct in6_addr)](0x0);
    //    string bit_str;
    auto inet_result = inet_pton(AF_INET, ci.c_str(), &in);

    if (inet_result > 0) {
        if (dr > 32) {
            std::cerr << "Invalid dr." << endl;
            throw std::out_of_range("Invalid dr for IPv4: " + dr);
        } else if (dr == 32) {
            return_val.append(ci).append("-").append(ci);
            return return_val;
        }
        set_bits(in, 32, dr, 0);
        char ip_buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in, ip_buffer, INET_ADDRSTRLEN);
        return_val.append(ip_buffer).append("-");
        ip_buffer[0] = '\0';
        set_bits(in, 32, dr, 1);
        inet_ntop(AF_INET, &in, ip_buffer, INET_ADDRSTRLEN);
        return_val.append(ip_buffer);
        return return_val;
    } else if ((inet_result = inet_pton(AF_INET6, ci.c_str(), &in)) > 0) {
        if (dr > 128) {
            std::cerr << "Invalid dr." << endl;
            throw std::out_of_range("Invalid dr for IPv6: " + dr);
        } else if (dr == 128) {
            return_val.append(ci).append("-").append(ci);
            return return_val;
        }
        set_bits(in, 128, dr, 0);
        char ip_buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in, ip_buffer, INET6_ADDRSTRLEN);
        return_val.append(ip_buffer).append("-");
        ip_buffer[0] = '\0';
        set_bits(in, 128, dr, 1);
        inet_ntop(AF_INET6, &in, ip_buffer, INET6_ADDRSTRLEN);
        return_val.append(ip_buffer);
        return return_val;
    }
    throw std::runtime_error("Invalid address.");
    // if (inet_result > 0) {
    // std::bitset<IPV4_LENGTH> bit(in);
    //        bit = reverse_by_group(bit, IPV4_LENGTH / 4);
    //        cout << bit << endl;
    //        dr=32;
    //        bitset<32> netmask_in_binary;
    //        netmask_in_binary.set();
    //        if (ci_dr != std::string::npos) dr = stoi(cidr.substr(ci_dr+1));
    //        int bits_to_move = 32 - dr;
    //        netmask_in_binary <<= bits_to_move;
    //        auto begin_addr_in_binary = bit & netmask_in_binary;
    //        auto end_addr_in_binary = bit | netmask_in_binary.flip();
    //        auto begin_bit = reverse_by_group(begin_addr_in_binary, 8);
    //        auto end_bit = reverse_by_group(end_addr_in_binary, 8);
    //        char end_text[IPV4_LENGTH];
    //        char begin_text[IPV4_LENGTH];
    //        in4.s_addr=begin_bit.to_ulong();
    //        inet_ntop(AF_INET, &in4, begin_text, IPV4_LENGTH);
    //        in4.s_addr=end_bit.to_ulong();
    //        inet_ntop(AF_INET, &in4, end_text, IPV4_LENGTH);
    //        auto* fmt = "%s-%s";
    //
    //        char range_buffer[31]{'\0'};
    //        snprintf(range_buffer,31,fmt,begin_text,end_text);
    //        cout << range_buffer <<endl;
    //        return range_buffer;
    //    } else if ( (inet_result = inet_pton(AF_INET6, ci.c_str(), &in6))>0 ) {
    //        string bits;
    //        for(int i = 0; i < 16; ++i){
    //            std::bitset<8> bit(in6.s6_addr[i]);
    //            cout<<i<<bit.to_string()<<endl;
    //        }
    //
    //        std::bitset<IPV6_LENGTH> bit(in6.s6_addr);
    //
    //        bit = reverse_by_group(bit, 16);
    //        cout << bit << endl;
    //        dr=128;
    //        bitset<128> netmask_in_binary;
    //        netmask_in_binary.set();
    //        if (ci_dr != std::string::npos) dr = stoi(cidr.substr(ci_dr+1));
    //        int bits_to_move = 128 - dr;
    //        netmask_in_binary <<= bits_to_move;
    //        auto begin_addr_in_binary = bit & netmask_in_binary;
    //        auto end_addr_in_binary = bit | netmask_in_binary.flip();
    //        auto begin_bit = reverse_by_group(begin_addr_in_binary, 16);
    //        auto end_bit = reverse_by_group(end_addr_in_binary, 16);
    //        char end_text[IPV6_LENGTH];
    //        char begin_text[IPV6_LENGTH];
    ////        in6.s6_addr=begin_bit.to_ulong();
    //        inet_ntop(AF_INET, &in4, begin_text, IPV4_LENGTH);
    ////        in4.s_addr=end_bit.to_ulong();
    //        inet_ntop(AF_INET, &in4, end_text, IPV4_LENGTH);
    //        auto* fmt = "%s-%s";
    //
    //        char range_buffer[31]{'\0'};
    //        snprintf(range_buffer,31,fmt,begin_text,end_text);
    //        cout << range_buffer <<endl;
    //        return range_buffer;
    //    } else {
    //        std::cerr << "Not a valid address." << endl;
    //        return "";
    //    }

    //
    //
    //    if (regex_match(cidr.c_str(), m, ipv4)) {
    //        auto first_eight_bits = stoi(m[1]);
    //        auto second_eight_bits = stoi(m[2]);
    //        auto third_eight_bits = stoi(m[3]);
    //        auto forth_eight_bits = stoi(m[4]);
    //
    //        bitset<32> origin_in_binary
    //            ((first_eight_bits << 24) + (second_eight_bits << 16) + (third_eight_bits << 8) + forth_eight_bits);
    //        cout << origin_in_binary << endl;
    //        bitset<32> netmask_in_binary;
    //        netmask_in_binary.set();
    //
    //        // cout<<netmask_in_binary<<endl;
    //        // cout<<origin_in_binary<<endl;
    //        auto begin_addr_in_binary = origin_in_binary & netmask_in_binary;
    //        auto end_addr_in_binary = origin_in_binary | netmask_in_binary.flip();
    //
    //        const bitset<32> one("11111111000000000000000000000000");
    //        const bitset<32> two("00000000111111110000000000000000");
    //        const bitset<32> three("00000000000000001111111100000000");
    //        const bitset<32> four("00000000000000000000000011111111");
    //
    //        // cout<<begin_addr_in_binary<<endl;
    //        // cout<<end_addr_in_binary<<endl;
    //        snprintf(ipv4_result_range, std::size(ipv4_result_range),
    //                 ipv4_range_fmt,
    //                 ((begin_addr_in_binary & one) >> 24).to_ulong(),
    //                 ((begin_addr_in_binary & two) >> 16).to_ulong(),
    //                 ((begin_addr_in_binary & three) >> 8).to_ulong(),
    //                 (begin_addr_in_binary & four).to_ulong(),
    //                 ((end_addr_in_binary & one) >> 24).to_ulong(),
    //                 ((end_addr_in_binary & two) >> 16).to_ulong(),
    //                 ((end_addr_in_binary & three) >> 8).to_ulong(),
    //                 (end_addr_in_binary & four).to_ulong());
    //        // cout<<((begin_addr_in_binary & one)>>24).to_ulong()<<endl;
    //        // cout<<((begin_addr_in_binary & two)>>16).to_ulong()<<endl;
    //        // cout<<((begin_addr_in_binary & three)>>8).to_ulong()<<endl;
    //        // cout<<(begin_addr_in_binary & four).to_ulong()<<endl;
    //
    //        // cout<<((end_addr_in_binary & one)>>24).to_ulong()<<endl;
    //        // cout<<((end_addr_in_binary & two)>>16).to_ulong()<<endl;
    //        // cout<<((end_addr_in_binary & three)>>8).to_ulong()<<endl;
    //        // cout<<(end_addr_in_binary & four).to_ulong()<<endl;
    //        cout << ipv4_result_range << endl;
    //        return ipv4_result_range;
    //    }
}
