#include "cidr2range.hpp"

using std::bitset;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

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
    const int IPV4_LENGTH = 32;
    const int IPV6_LENGTH = 128;

    auto ci_dr = cidr.find_first_of('/');
    int dr;
    string ci, return_val;
    ci = cidr.substr(0, ci_dr);

    unsigned char in[sizeof(struct in6_addr)](0x0);
    auto inet_result = inet_pton(AF_INET, ci.c_str(), &in);

    if (inet_result > 0) {
        if (ci_dr == string::npos) {
            return_val.append(ci).append("-").append(ci);
            return return_val;
        } else {
            dr = stoi(cidr.substr(ci_dr + 1));
        }
        if (dr > IPV4_LENGTH) {
            cerr << "Invalid dr." << endl;
            throw std::out_of_range("Invalid dr for IPv4: " + dr);
        } else if (dr == IPV4_LENGTH) {
            return_val.append(ci).append("-").append(ci);
            return return_val;
        }
        set_bits(in, IPV4_LENGTH, dr, 0);
        char ip_buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in, ip_buffer, INET_ADDRSTRLEN);
        return_val.append(ip_buffer).append("-");
        ip_buffer[0] = '\0';
        set_bits(in, IPV4_LENGTH, dr, 1);
        inet_ntop(AF_INET, &in, ip_buffer, INET_ADDRSTRLEN);
        return_val.append(ip_buffer);
        return return_val;
    } else if ((inet_result = inet_pton(AF_INET6, ci.c_str(), &in)) > 0) {
        if (ci_dr == string::npos) {
            return_val.append(ci).append("-").append(ci);
            return return_val;
        } else {
            dr = stoi(cidr.substr(ci_dr + 1));
        }
        if (dr > IPV6_LENGTH) {
            cerr << "Invalid dr." << endl;
            throw std::out_of_range("Invalid dr for IPv6: " + dr);
        } else if (dr == IPV6_LENGTH) {
            return_val.append(ci).append("-").append(ci);
            return return_val;
        }
        set_bits(in, IPV6_LENGTH, dr, 0);
        char ip_buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in, ip_buffer, INET6_ADDRSTRLEN);
        return_val.append(ip_buffer).append("-");
        ip_buffer[0] = '\0';
        set_bits(in, IPV6_LENGTH, dr, 1);
        inet_ntop(AF_INET6, &in, ip_buffer, INET6_ADDRSTRLEN);
        return_val.append(ip_buffer);
        return return_val;
    }
    throw std::runtime_error("Invalid address.");
}
