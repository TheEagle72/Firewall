#pragma once

#include "rule_base.hpp"

class rule_address final :public rule_base
{
private:
	uint32_t address_;
	uint8_t mask_;
public:
	rule_address(Permission permission, Direction direction, uint32_t address, uint8_t mask);
	bool check_packet(const Packet& packet, Permission& permission) override;
};


