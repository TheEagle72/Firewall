#include <string>
#include <algorithm>
#include <iostream>
#include <vector>

#include "Rule.hpp"
#include  "Parser.hpp"

using namespace std;

void Rule::create_port_protocol(const vector<string>& args)
{
	permission = parse_permission(args[0]);
	uint8_t port_number, protocol = 0;
	parse_port(args[1], port_number, protocol);
	rules_.emplace_back(new RulePort(port_number));
	if (protocol != 0)
	{
		rules_.emplace_back(new RuleProtocol(protocol));
	}
}

void Rule::create_address(const std::vector<std::string>& args)
{
	permission = parse_permission(args[0]);
	if (args[1] != "from")
	{
		wrong_format_error();
	}
	uint32_t address = 0;
	uint8_t mask = 0;
	parse_address(args[2], address, mask);
	rules_.emplace_back(new RuleAddress(address, mask));
}

void Rule::create_address_to_destination(const std::vector<std::string>& args)
{
	if (args[3] != "to")
	{
		wrong_format_error();
	}
	create_address(args);
	uint32_t address = 0;
	uint8_t mask = 0;
	if (args[4] != "any")
	{
		parse_address(args[4], address, mask);
		rules_.emplace_back(new RuleAddress(address, mask));
	}
}

void Rule::create_address_to_destination_port(const std::vector<std::string>& args)
{
	if (args[5] != "port")
	{
		wrong_format_error();
	}
	create_address_to_destination(args);
	uint8_t port_number;
	uint8_t proto;
	parse_port(args[6], port_number, proto);
	rules_.emplace_back(new RulePort(port_number));
}

void Rule::create_address_to_destination_port_protocol(const std::vector<std::string>& args)
{
	if (args[7] != "proto")
	{
		wrong_format_error();
	}
	create_address_to_destination_port(args);
	uint8_t protocol = parse_protocol(args[8]);
	rules_.emplace_back(new RuleProtocol(protocol));
}

Rule::Rule(const std::string& str)
{
	vector<string> args = parse_rule(str);

	switch (args.size())
	{
	case 2:
		create_port_protocol(args);
		break;
	case 3:
		create_address(args);
		break;
	case 5:
		create_address_to_destination(args);
		break;
	case 7:
		create_address_to_destination_port(args);
		break;
	case 9:
		create_address_to_destination_port_protocol(args);
		break;
	default:
		wrong_format_error();
	}
}

bool Rule::check_packet(const std::string& str)
{
	for (auto& rule : rules_)
	{
		if (!rule->check_packet(str))
		{
			return false;
		}
	}
	return true;
}

BaseRule::~BaseRule() {}

RulePort::RulePort(uint16_t port)
{
	port_ = port;
}

RuleAddress::RuleAddress(uint32_t address, uint8_t mask)
{
	address_ = address;
	mask_ = mask;
}

RuleProtocol::RuleProtocol(uint8_t protocol)
{
	protocol_ = protocol;
}
