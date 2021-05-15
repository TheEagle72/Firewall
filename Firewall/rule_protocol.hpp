#pragma once

#include "base_rule.hpp"

class rule_protocol final :public base_rule
{
private:
	uint8_t protocol_;
public:
	rule_protocol(bool, uint8_t);
	bool check_packet(const Packet&, bool&) override;
};