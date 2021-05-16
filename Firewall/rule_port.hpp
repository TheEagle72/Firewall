#pragma once

#include "rule_base.hpp"

class rule_port final :public rule_base
{
private:
	uint16_t port_;
public:
	rule_port(Permission permission, Direction direction, uint16_t port);
	bool check_packet(const Packet& packet, Permission& permission) override;
};
