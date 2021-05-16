#pragma once

#include "rule_base.hpp"

class rule_protocol final :public rule_base
{
private:
	uint8_t protocol_;
public:
	rule_protocol(Permission permission, Direction direction, uint8_t protocol);
	bool check_packet(const Packet& packet, Permission& permission) override;
};