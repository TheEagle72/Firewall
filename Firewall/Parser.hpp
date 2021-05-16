#pragma once
#include <string>
#include <vector>

#include "rule_base.hpp"

class parser_wrong_format_exception : std::exception
{
	[[nodiscard]] char const* what()  const override { return "incorrect data received during rule creation"; };
};

Permission parse_permission(const std::string& str);
uint8_t parse_protocol(const std::string& str);
std::tuple<uint16_t, uint8_t> parse_port(const std::string& str);
std::tuple<uint32_t, uint8_t> parse_address(const std::string& str);
std::vector<std::string> parse_string(const std::string& str, char separator = ' ');
uint32_t ip_to_decimal(const std::string& str);
std::string decimal_to_ip(uint32_t number);