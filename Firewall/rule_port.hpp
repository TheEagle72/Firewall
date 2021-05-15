#pragma once

#include "base_rule.hpp"

class rule_port final :public base_rule
{
private:
	uint16_t port_;
public:
	rule_port(bool,uint16_t);
	bool check_packet(const Packet&, bool&) override;
};
