#pragma once

#include "base_rule.hpp"

class rule_address final :public base_rule
{
private:
	uint32_t address_;
	uint8_t mask_;
public:
	rule_address(bool, uint32_t, uint8_t);
	bool check_packet(const Packet&, bool&) override;
};


