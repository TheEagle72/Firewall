#include "rule_protocol.hpp"

rule_protocol::rule_protocol(const Permission permission, const Direction direction, const uint8_t protocol)
{
	permission_ = permission;
	protocol_ = protocol;
	direction_ = direction;
}

bool rule_protocol::check_packet(const Packet& packet, Permission& permission)
{
	if (packet.get_protocol() == protocol_)
	{
		permission = permission_;
		return true;
	}
	return false;
}
