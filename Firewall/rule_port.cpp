#include "rule_port.hpp"


rule_port::rule_port(const Permission permission, const Direction direction, const uint16_t port)
{
	permission_ = permission;
	port_ = port;
	direction_ = direction;
}

bool rule_port::check_packet(const Packet& packet, Permission& permission)
{
	uint16_t port;
	if (direction_ == Direction::incoming)
	{
		port = packet.get_in_port();
	}
	else
	{
		port = packet.get_out_port();
	}

	if (port == port_)
	{
		permission = permission_;
		return true;
	}
	return false;
}
