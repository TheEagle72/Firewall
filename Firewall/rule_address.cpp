#include "rule_address.hpp"
#include <unordered_map>

namespace
{
	const std::unordered_map<uint8_t, uint32_t> mask_table
	{
		{0,0x00000000},
		{8,0xFF000000},
		{16,0xFFFF0000},
		{24,0xFFFFFF00},
		{32,0xFFFFFFFF}
	};
}

rule_address::rule_address(const bool permission, const bool in_direction, uint32_t address, uint8_t mask)
{
	permission_ = permission;
	address_ = address;
	mask_ = mask;
	in_direction_ = in_direction;
}


bool rule_address::check_packet(const Packet& packet, bool& permission)
{
	uint32_t address;
	if (in_direction_)
	{
		address = packet.get_in_address();
	}
	else
	{
		address = packet.get_out_address();
	}

	if ((address & mask_table.at(mask_)) == (address_ & mask_table.at(mask_)))
	{
		permission = permission_;
		return true;
	}
	else
	{
		return false;
	}
}