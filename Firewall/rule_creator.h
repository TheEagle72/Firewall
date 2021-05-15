#pragma once

#include <memory>
#include <string>

#include "base_rule.hpp"

class rule_creator
{
	std::unique_ptr<base_rule> create_rule(std::string);
};

