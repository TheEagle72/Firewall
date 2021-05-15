#pragma once

#include "base_rule.hpp"

class rule_port final :public base_rule
{
private:
	uint16_t port_;
public:
	rule_port(bool permission, bool in_direction, uint16_t port);
	bool check_packet(const Packet& packet, bool& permission) override;
};
