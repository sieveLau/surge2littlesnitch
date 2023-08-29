#pragma once
#include <bitset>
#include <iostream>
#include <regex>
#include <string>
#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <format>

std::string cidr2range(const std::string& cidr);