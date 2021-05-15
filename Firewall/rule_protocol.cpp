#include "rule_protocol.hpp"

rule_protocol::rule_protocol(const bool permission, const bool in_direction, const uint8_t protocol)
{
	permission_ = permission;
	protocol_ = protocol;
	in_direction_ = in_direction;
}

bool rule_protocol::check_packet(const Packet& packet, bool& permission)
{
	if (packet.get_protocol() == protocol_)
	{
		permission = permission_;
		return true;
	}
	else
	{
		return false;
	}
}
