#pragma once

#include <memory>
#include <string>
#include "rule_base.hpp"

class fabric_rule final
{
	fabric_rule() = delete;
public:
	static std::unique_ptr<rule_base> create_rule(const std::string& str);
};

