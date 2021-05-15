#pragma once

#include "Packet.hpp"

class base_rule
{
protected:
	bool permission_;
	bool in_direction_; // true if packet is incoming
public:
	virtual ~base_rule() = default;
	virtual bool check_packet(const Packet&, bool& permission) = 0;
};
