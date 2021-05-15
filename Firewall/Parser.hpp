#pragma once
#include <string>
#include <vector>

bool is_number(const std::string& str);
bool is_valid_ip(const std::string& str);
void wrong_format_error();
bool parse_permission(const std::string& str);
uint8_t parse_protocol(const std::string& str);
void parse_port(const std::string& str, uint16_t& port_number, uint8_t& protocol);
void parse_address(const std::string& str, uint32_t& address, uint8_t& mask);
std::vector<std::string> parse_string(const std::string& str, char separator = ' ');
uint32_t ip_to_decimal(const std::string& str);
std::string decimal_to_ip(uint32_t number);