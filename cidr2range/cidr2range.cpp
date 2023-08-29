#include "cidr2range.hpp"
#include <arpa/inet.h>
#include <array>
#include <bitset>
#include <cmath>
#include <netinet/in.h>
#include <regex>
#include <string>
#include <sys/socket.h>
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
template<std::size_t N>
std::bitset<N> reverse_by_group(const std::bitset<N> &b, size_t bit_per_group) {
    string str = b.to_string();
    if (str.empty() || str.length() % bit_per_group != 0)
        return {};

    auto *buffer_for_reversed_string = new char[str.length() + 1]{'\0'};
    const auto buf_len = str.length() + 1;
    buffer_for_reversed_string[buf_len - 1] = {'\0'};

    // 用于提取ipv4（二进制形式）各个位的正则表达式
    auto *reg_fmt_str = "\\d{%lu}";
    // 根据bit_per_group的数字位数来计算需要占用char[]的多少位
    // log10(n)向上取整就是10进制数的字符串形式需要占用的char数量
    size_t size_for_the_number = ceil(log10(bit_per_group));
    // 分配数组内存，数量=reg_fmt_str的长度-3-数字要占用的char位+1
    // 3是%lu，3个char；+1是结尾'\0'
    auto *reg_str = new char[strlen(reg_fmt_str) - 2 + size_for_the_number]{'\0'};
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

string cidr2range(const string &cidr) {

    //   unsigned char buf[sizeof(struct in6_addr)];
    in_addr in;

    auto ci_dr = cidr.find_first_of('/');
    string ci, dr;
    ci = cidr.substr(0, ci_dr);

    auto inet_result = inet_pton(AF_INET, ci.c_str(), &in);
    if (inet_result > 0) {
        printBinaryValue2(in.s_addr);
        putchar('\n');
        std::bitset<sizeof(in_addr) * 8> bit(in.s_addr);
        bit = reverse_by_group(bit, 8);
        cout << bit << endl;
    }
    if (ci_dr != std::string::npos) {
        dr = cidr.substr(ci_dr + 1);
    }

    // string ip = "118.89.204.198/23";
    regex ipv4(R"((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})((\/)(\d{1,2}))?)");
    cmatch m;
    char ipv4_result_range[32] = {'\0'};
    const char *ipv4_range_fmt = "%lu.%lu.%lu.%lu-%lu.%lu.%lu.%lu";
    if (regex_match(cidr.c_str(), m, ipv4)) {
        auto first_eight_bits = stoi(m[1]);
        auto second_eight_bits = stoi(m[2]);
        auto third_eight_bits = stoi(m[3]);
        auto forth_eight_bits = stoi(m[4]);

        bitset<32> origin_in_binary
            ((first_eight_bits << 24) + (second_eight_bits << 16) + (third_eight_bits << 8) + forth_eight_bits);
        cout << origin_in_binary << endl;
        bitset<32> netmask_in_binary;
        netmask_in_binary.set();

        if (m.size() > 6) {
            int origin_netmask_from_cidr = 32;
            // auto netmask_str = m[7].str();
            origin_netmask_from_cidr = stoi(m[7]);
            // cout<<origin_netmask_from_cidr<<endl;
            int bits_to_move = 32 - origin_netmask_from_cidr;
            netmask_in_binary <<= bits_to_move;
        }
        // cout<<netmask_in_binary<<endl;
        // cout<<origin_in_binary<<endl;
        auto begin_addr_in_binary = origin_in_binary & netmask_in_binary;
        auto end_addr_in_binary = origin_in_binary | netmask_in_binary.flip();

        const bitset<32> one("11111111000000000000000000000000");
        const bitset<32> two("00000000111111110000000000000000");
        const bitset<32> three("00000000000000001111111100000000");
        const bitset<32> four("00000000000000000000000011111111");

        // cout<<begin_addr_in_binary<<endl;
        // cout<<end_addr_in_binary<<endl;
        snprintf(ipv4_result_range, std::size(ipv4_result_range),
                 ipv4_range_fmt,
                 ((begin_addr_in_binary & one) >> 24).to_ulong(),
                 ((begin_addr_in_binary & two) >> 16).to_ulong(),
                 ((begin_addr_in_binary & three) >> 8).to_ulong(),
                 (begin_addr_in_binary & four).to_ulong(),
                 ((end_addr_in_binary & one) >> 24).to_ulong(),
                 ((end_addr_in_binary & two) >> 16).to_ulong(),
                 ((end_addr_in_binary & three) >> 8).to_ulong(),
                 (end_addr_in_binary & four).to_ulong());
        // cout<<((begin_addr_in_binary & one)>>24).to_ulong()<<endl;
        // cout<<((begin_addr_in_binary & two)>>16).to_ulong()<<endl;
        // cout<<((begin_addr_in_binary & three)>>8).to_ulong()<<endl;
        // cout<<(begin_addr_in_binary & four).to_ulong()<<endl;

        // cout<<((end_addr_in_binary & one)>>24).to_ulong()<<endl;
        // cout<<((end_addr_in_binary & two)>>16).to_ulong()<<endl;
        // cout<<((end_addr_in_binary & three)>>8).to_ulong()<<endl;
        // cout<<(end_addr_in_binary & four).to_ulong()<<endl;
        cout << ipv4_result_range << endl;
        return ipv4_result_range;
    }
    return "";
}
