#include "rule_port.hpp"


rule_port::rule_port(bool permission,uint16_t port)
{
	permission_ = permission;
	port_ = port;
}

bool rule_port::check_packet(const Packet& packet, bool& permission)
{
	if (packet.get_in_port() == port_)
	{
		permission = permission_;
		return true;
	}
	else
	{
		return false;
	}
}
