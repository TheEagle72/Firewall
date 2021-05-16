#pragma once

#include "Packet.hpp"

enum class Direction
{
	incoming,
	outgoing
};

enum  class Permission
{
	allow,
	deny
};

class rule_base
{
protected:
	Permission permission_;
	Direction direction_; 
public:
	virtual ~rule_base() = default;
	virtual bool check_packet(const Packet& packet, Permission& permission) = 0;
};
