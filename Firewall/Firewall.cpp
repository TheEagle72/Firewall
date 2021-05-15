#include "Firewall.hpp"
#include <string>

#include "compound_rule.hpp"
#include "Parser.hpp"
#include "rule_address.hpp"
#include "rule_port.hpp"
#include "rule_protocol.hpp"

using namespace std;

namespace
{
	void create_port_protocol(const std::vector<std::string>& args, std::vector<unique_ptr<base_rule>>& rules)
	{
		bool permission = parse_permission(args[0]);
		uint16_t port_number = 0;
		uint8_t protocol = 0;
		parse_port(args[1], port_number, protocol);

		if (protocol != 0)
		{
			vector<unique_ptr<base_rule>> local_rules;
			local_rules.emplace_back(new rule_port(permission, port_number));
			local_rules.emplace_back(new rule_protocol(permission, protocol));
			rules.emplace_back(new compound_rule(permission, move(local_rules)));
		}
		else
		{
			rules.emplace_back(new rule_port(permission, port_number));
		}

	}

	void create_address(const std::vector<std::string>& args, std::vector<unique_ptr<base_rule>>& rules)
	{
		bool permission = parse_permission(args[0]);
		if (args[1] != "from")
		{
			wrong_format_error();
		}
		uint32_t address = 0;
		uint8_t mask = 32;
		parse_address(args[2], address, mask);
		rules.emplace_back(new rule_address(permission, address, mask));
	}

	void create_address_to_destination(const std::vector<std::string>& args, std::vector<unique_ptr<base_rule>>& rules)
	{
		bool permission = parse_permission(args[0]);
		if (args[3] != "to")
		{
			wrong_format_error();
		}

		if (args[4] == "any")
		{
			create_address(args, rules);
		}
		else
		{
			vector<unique_ptr<base_rule>> local_rules;
			create_address(args, local_rules);

			uint32_t address = 0;
			uint8_t mask = 32;
			parse_address(args[5], address, mask);
			local_rules.emplace_back(new rule_address(permission, address, mask));// todo woudn't work. should specify that address is for outcoming packet
			rules.emplace_back(new compound_rule(permission, move(local_rules)));
		}
	}

	void create_address_to_destination_port(const std::vector<std::string>& args, std::vector<unique_ptr<base_rule>>& rules)
	{
		bool permission = parse_permission(args[0]);
		if (args[5] != "port")
		{
			wrong_format_error();
		}
		vector<unique_ptr<base_rule>> local_rules;
		create_address_to_destination(args, local_rules);
		uint16_t port_number = 0;
		uint8_t proto = 0;
		parse_port(args[6], port_number, proto);
		local_rules.emplace_back(new rule_port(permission, port_number));
		rules.emplace_back(new compound_rule(permission, move(local_rules)));
	}

	void create_address_to_destination_port_protocol(const std::vector<std::string>& args, std::vector<unique_ptr<base_rule>>& rules)
	{
		bool permission = parse_permission(args[0]);
		if (args[7] != "proto")
		{
			wrong_format_error();
		}
		vector<unique_ptr<base_rule>> local_rules;
		create_address_to_destination_port(args, local_rules);
		uint8_t protocol = parse_protocol(args[8]);
		local_rules.emplace_back(new rule_protocol(permission, protocol));
		rules.emplace_back(new compound_rule(permission, move(local_rules)));
	}
}

unsigned Firewall::add_rule(const string& str)
{
	const vector<string> args = parse_string(str);

	switch (args.size())
	{
	case 2:
		create_port_protocol(args, rules);
		break;
	case 3:
		create_address(args, rules);
		break;
	case 5:
		create_address_to_destination(args, rules);
		break;
	case 7:
		create_address_to_destination_port(args, rules);
		break;
	case 9:
		create_address_to_destination_port_protocol(args, rules);
		break;
	default:
		wrong_format_error();
	}
	//todo probably better to replace with map

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

void Firewall::set_default_mode(bool mode)
{
	default_mode = mode;
}

bool Firewall::check_packet(const Packet& packet)
{
	bool permission = default_mode;
	for (auto& rule : rules)
	{
		if (rule->check_packet(packet, permission))// if we found compound_rule which should handle this packet then return its permission state
		{
			break;
		}
	}
	// if no rules were found then we will return default state	
	return permission;
}
