#include "rule_protocol.hpp"

rule_protocol::rule_protocol(bool permission, uint8_t protocol)
{
	permission_ = permission;
	protocol_ = protocol;
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
