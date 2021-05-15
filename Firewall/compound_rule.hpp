#pragma once

#include <memory>
#include <string>
#include <vector>

#include "base_rule.hpp"

class compound_rule final :public base_rule
{
private:
	std::vector<std::unique_ptr<base_rule>> rules_;
public:
	compound_rule(const bool permission, std::vector<std::unique_ptr<base_rule>>&& rules);
	bool check_packet(const Packet&, bool&) override;
};
