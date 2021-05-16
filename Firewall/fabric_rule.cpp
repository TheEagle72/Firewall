#include "fabric_rule.hpp"

#include <iostream>
#include <memory>
#include <vector>
#include "Parser.hpp"
#include "rule_compound.hpp"
#include "rule_protocol.hpp"
#include "rule_port.hpp"
#include "rule_address.hpp"

using namespace  std;

namespace
{
	void try_get_permission(const vector<string>& args)
	{
		try
		{
			Permission permission = parse_permission(args[0]);
		}
		catch (exception& e)
		{
			throw e;
		}
	}

	void try_get_port_or_incoming_address(const vector<string>& args, vector<unique_ptr<rule_base>>& rules, unique_ptr<rule_base>& ptr)
	{
		try
		{
			Permission permission = parse_permission(args[0]);
			if (args.size() < 2)
			{
				throw parser_wrong_format_exception();
			}

			if (args[1] == "from")
			{
				if (args.size() < 3)
				{
					throw parser_wrong_format_exception();
				}

				auto [in_address, in_mask] = parse_address(args[2]);

				if (args.size() < 5)
				{
					ptr = make_unique<rule_address>(permission, Direction::incoming, in_address, in_mask);
					return;
				}

				rules.emplace_back(make_unique<rule_address>(permission, Direction::incoming, in_address, in_mask));
				return;
			}
			auto [port, protocol] = parse_port(args[1]);
			if (protocol == 0)
			{
				ptr = make_unique<rule_port>(permission, Direction::incoming, port);
				return;
			}
			rules.emplace_back(make_unique<rule_port>(permission, Direction::incoming, port));
			rules.emplace_back(make_unique<rule_protocol>(permission, Direction::incoming, protocol));
			ptr = make_unique<rule_compound>(permission, Direction::incoming, move(rules));
			return;
		}
		catch (exception& e)
		{
			throw e;
		}
	}

	void  try_get_outgoing_address(const vector<string>& args, vector<unique_ptr<rule_base>>& rules, unique_ptr<rule_base>& ptr)
	{
		try
		{
			if (args.size() < 5)
			{
				return;
			}

			Permission permission = parse_permission(args[0]);
			if (args[3] == "to")
			{
				auto [out_address, out_mask] = parse_address(args[4]);
				if (out_mask != 0)
				{
					rules.emplace_back(make_unique<rule_address>(permission, Direction::outgoing, out_address, out_mask));
				}
				return;
			}
			throw parser_wrong_format_exception();
		}
		catch (exception& e)
		{
			throw e;
		}
	}


	void try_get_port(const vector<string>& args, vector<unique_ptr<rule_base>>& rules, unique_ptr<rule_base>& ptr)
	{
		try
		{
			if (args.size() < 7)
			{
				return;
			}

			Permission permission = parse_permission(args[0]);
			if (args[5] == "port")
			{
				auto [port, protocol] = parse_port(args[6]);
				rules.emplace_back(make_unique<rule_port>(permission, Direction::incoming, port));
				return;
			}
			throw parser_wrong_format_exception();
		}
		catch (exception& e)
		{
			throw e;
		}
	}

	void  try_get_protocol(const vector<string>& args, vector<unique_ptr<rule_base>>& rules, unique_ptr<rule_base>& ptr)
	{
		try
		{
			if (args.size() < 9)
			{
				return;
			}

			Permission permission = parse_permission(args[0]);
			if (args[7] == "proto")
			{
				const uint8_t protocol = parse_protocol(args[8]);

				rules.emplace_back(make_unique<rule_protocol>(permission, Direction::incoming, protocol));
				return;
			}
			throw parser_wrong_format_exception();
		}
		catch (exception& e)
		{
			throw e;
		}
	}


}

unique_ptr<rule_base> fabric_rule::create_rule(const std::string& str)
{
	try
	{
		const vector<string> args = parse_string(str);
		vector<unique_ptr<rule_base>> rules;
		unique_ptr<rule_base> result = nullptr;

		try_get_permission(args);
		try_get_port_or_incoming_address(args, rules, result);
		try_get_outgoing_address(args, rules, result);
		try_get_port(args, rules, result);
		try_get_protocol(args, rules, result);

		if (!rules.empty() && result == nullptr)
		{
			result = make_unique<rule_compound>(parse_permission(args[0]), Direction::incoming, move(rules));
		}
		return result;
	}
	catch (exception& e)
	{
		cerr << e.what() << endl;
		return nullptr;
	}

}
