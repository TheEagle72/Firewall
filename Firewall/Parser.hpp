#pragma once
#include <string>
#include <vector>

bool parse_permission(const std::string& str);
uint8_t parse_protocol(const std::string& str);
std::tuple<uint16_t, uint8_t> parse_port(const std::string& str);
std::tuple<uint32_t, uint8_t> parse_address(const std::string& str);
std::vector<std::string> parse_string(const std::string& str, char separator = ' ');
void wrong_format_error();
uint32_t ip_to_decimal(const std::string& str);
std::string decimal_to_ip(uint32_t number);