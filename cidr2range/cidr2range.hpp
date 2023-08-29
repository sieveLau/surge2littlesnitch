#pragma once
#include <string>
#include <regex>
#include <bitset>
#include <iostream>
#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <format>

std::string cidr2range(const std::string& cidr);