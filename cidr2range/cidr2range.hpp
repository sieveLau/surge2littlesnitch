#pragma once
#include <string>
#include <regex>
#include <bitset>
#include <iostream>
#include <arpa/inet.h>
#include <format>

std::string cidr2range(const std::string& cidr);