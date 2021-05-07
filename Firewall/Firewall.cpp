#include "Firewall.hpp"
#include <string>

using namespace std;


unsigned Firewall::add_rule(const string& str)
{
	rules.emplace_back(new Rule(str));
	return rules.size() - 1;
}

void Firewall::delete_rule(int index)
{
	rules.erase(rules.begin() + index);
}

bool Firewall::check_packet(const std::string& packet)
{
	for (auto& rule : rules)
	{
		if (!rule->check_packet(packet))
		{
			return false;
		}
	}
	return true;
}
