#pragma once

#include "base_rule.hpp"

class rule_address final :public base_rule
{
private:
	uint32_t address_;
	uint8_t mask_;
public:
	rule_address(const bool permission, const bool in_direction, uint32_t address, uint8_t mask);
	bool check_packet(const Packet& packet, bool& permission) override;
};


