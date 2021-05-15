#include "Firewall.hpp"

using namespace std;

unsigned Firewall::add_rule(unique_ptr<base_rule> rule)
{
	rules.emplace_back(move(rule));
	return rules.size() - 1;
}

void Firewall::delete_rule(int index)
{
	rules.erase(rules.begin() + index);
}

void Firewall::clear()
{
	rules.clear();	//todo possible memory leak, is smart pointers deleting themselves, when only reference to the object is lost?
}

void Firewall::set_default_mode(bool allow)
{
	default_mode = allow;
}

bool Firewall::check_packet(const Packet& packet)
{
	bool permission = default_mode;
	for (auto& rule : rules)
	{
		if (rule->check_packet(packet, permission))// if we found rule which should handle this packet then return its permission state
		{
			break;
		}
	}
	// if no rules were found then return default state	
	return permission;
}
