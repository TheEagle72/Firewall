#pragma once

#include "base_rule.hpp"

class rule_protocol final :public base_rule
{
private:
	uint8_t protocol_;
public:
	rule_protocol(bool permission, bool in_direction, uint8_t protocol);
	bool check_packet(const Packet& packet, bool& permission) override;
};