#include "compound_rule.hpp"

#include "Parser.hpp"

using namespace std;


compound_rule::compound_rule(const bool permission, std::vector<std::unique_ptr<base_rule>>&& rules)
{
	permission_ = permission;
	//rules_ = rules;
	rules_ = move(rules);
}

bool compound_rule::check_packet(const Packet& packet, bool& permission)
{
	bool local_permission;
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

