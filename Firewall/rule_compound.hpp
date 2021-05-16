#pragma once

#include <memory>
#include <vector>
#include "rule_base.hpp"

class rule_compound final :public rule_base
{
private:
	std::vector<std::unique_ptr<rule_base>> rules_;
public:
	rule_compound(Permission permission, Direction direction, std::vector<std::unique_ptr<rule_base>>&& rules);
	bool check_packet(const Packet& packet, Permission& permission) override;
};
