#include "rule_port.hpp"


rule_port::rule_port(bool permission, bool in_direction, uint16_t port)
{
	permission_ = permission;
	port_ = port;
	in_direction_ = in_direction;
}

bool rule_port::check_packet(const Packet& packet, bool& permission)
{
	uint16_t port;
	if (in_direction_)
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
	else
	{
		return false;
	}
}
