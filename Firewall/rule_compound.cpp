#include "rule_compound.hpp"

#include "Parser.hpp"

using namespace std;


rule_compound::rule_compound(const Permission permission, const Direction direction, std::vector<std::unique_ptr<rule_base>>&& rules)
{
	permission_ = permission;
	rules_ = move(rules);
	direction_ = direction;
}

bool rule_compound::check_packet(const Packet& packet, Permission& permission)
{
	Permission local_permission = permission_;
	for (auto& rule : rules_)
	{
		if (!rule->check_packet(packet, local_permission))
		{
			return false;
		}
	}
	permission = permission_;
	return true;
}

