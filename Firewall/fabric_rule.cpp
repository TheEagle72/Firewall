#include "fabric_rule.hpp"

#include <memory>
#include <vector>
#include "Parser.hpp"
#include "compound_rule.hpp"
#include "rule_protocol.hpp"
#include "rule_port.hpp"
#include "rule_address.hpp"

using namespace  std;

unique_ptr<base_rule> fabric_rule::create_rule(const std::string& str)
{
	const vector<string> args = parse_string(str);

	vector<unique_ptr<base_rule>> rules;

	bool permission = parse_permission(args[0]);

	if (args.size() < 2)
	{
		wrong_format_error();
	}

	if (args[1] == "from")
	{
		if (args.size() < 3)
		{
			wrong_format_error();
		}

		auto [in_address, in_mask] = parse_address(args[2]);

		if (args.size() < 5)
		{
			return make_unique<rule_address>(permission, true, in_address, in_mask);
		}
		rules.emplace_back(make_unique<rule_address>(permission, true, in_address, in_mask));

		if (args.size() >= 5 && args[3] == "to")
		{
			auto [out_address, out_mask] = parse_address(args[4]);
			if (out_mask != 0)
			{
				rules.emplace_back(make_unique<rule_address>(permission, false, out_address, out_mask));
			}
		}

		if (args.size() >= 7 && args[5] == "port")
		{
			auto [port, protocol] = parse_port(args[6]);
			rules.emplace_back(make_unique<rule_port>(permission, true, port));
		}

		if (args.size() >= 9 && args[7] == "proto")
		{
			const uint8_t protocol = parse_protocol(args[8]);
			rules.emplace_back(make_unique<rule_protocol>(permission, true, protocol));
		}
		return make_unique<compound_rule>(permission, true, move(rules));
	}
	else
	{
		auto [port, protocol] = parse_port(args[1]);
		if (protocol == 0)
		{
			return make_unique<rule_port>(permission, true, port);
		}
		else
		{
			rules.emplace_back(make_unique<rule_port>(permission, true, port));
			rules.emplace_back(make_unique<rule_protocol>(permission, true, protocol));
			return make_unique<compound_rule>(permission, true, move(rules));
		}
	}
}
