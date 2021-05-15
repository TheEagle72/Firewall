#pragma once

#include <memory>
#include <string>
#include "base_rule.hpp"

class fabric_rule
{
public:
	static std::unique_ptr<base_rule> create_rule(const std::string& str);
};

