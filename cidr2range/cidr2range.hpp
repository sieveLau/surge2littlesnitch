#pragma once
#include <bitset>
#include <iostream>
#include <string>
#include <exception>
#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

std::string cidr2range(const std::string& cidr);