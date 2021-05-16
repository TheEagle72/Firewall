#include "Firewall.hpp"

using namespace std;

size_t Firewall::add_rule(unique_ptr<rule_base> rule)
{
	if (rule == nullptr)
	{
		throw firewall_nullptr_exception();
	}
	rules.emplace_back(move(rule));
	return rules.size() - 1;
}

void Firewall::delete_rule(const size_t index)
{
	rules.erase(rules.begin() + index);
}

void Firewall::clear()
{
	rules.clear();
}

void Firewall::set_default_permission(const Permission permission)
{
	default_permission = permission;
}

bool Firewall::check_packet(const Packet& packet) const
{
	Permission permission = default_permission;
	for (auto& rule : rules)
	{
		if (rule->check_packet(packet, permission))// if we found rule which should handle this packet then return its Permission state
		{
			break;
		}
	}
	// if no rules were found then return default state
	if (permission == Permission::allow)
	{
		return true;
	}
	return false;
}
