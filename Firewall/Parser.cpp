#include "Parser.hpp"

#include <iostream>
#include <unordered_map>
#include "Rule.hpp"

using namespace std;

uint32_t ip_to_decimal_(const string& str)
{
	uint32_t result = 0;
	auto it1 = str.begin();
	auto it2 = it1;
	for (int shift = 24; shift >= 0; shift -= 8)
	{
		it2 = find(it1, str.end(), '.');

		string number(it1, it2);
		result += (stoull(number) << shift);

		if (it2 != str.end())
		{
			it1 = ++it2;
		}
	}
	return result;
}

string decimal_to_ip_(uint32_t number)
{
	string result;
	for (int shift = 24; shift >= 0; shift -= 8)
	{
		uint32_t tmp = (number >> shift) & 255;
		result += to_string(tmp);
		result += '.';
	}
	result.pop_back();
	return result;
}

bool is_number(const string& str)
{
	auto it = str.begin();
	while (it != str.end() && isdigit(*it)) ++it;
	return !str.empty() && it == str.end();
}

bool is_valid_ip(const string& str)
{
	auto it1 = str.begin();
	auto it2 = it1;
	for (int i = 0; i < 4; ++i)
	{
		it2 = find(it1, str.end(), '.');

		string number = string(it1, it2);
		if (!is_number(number) || stoul(number) > 255)
		{
			return false;
		}

		if (it2 != str.end())
		{
			it1 = ++it2;
		}
		else
		{
			if (i != 3)
			{
				return false;
			}
		}
	}
	return true;
}
void wrong_format_error()
{
	std::cerr << "wrong format of rule. Usage: 'allow/deny from <target> to <destination> port <port number>' or 'allow/deny <port>/<optional: protocol>'";
	exit(1);
}

bool parse_permission(const string& str)
{
	if (str == "allow")
	{
		return  true;
	}
	else
		if (str == "deny")
		{
			return false;
		}
		else
		{
			wrong_format_error();
		}
}

namespace
{
	const unordered_map<string, uint8_t> protocol_table
	{
		{"tcp",6},
		{"udp",17},
		{"icmp",1}
	};
}

uint8_t parse_protocol(const string& str)
{
	if (protocol_table.count(str))
	{
		return protocol_table.at(str);
	}
	else
	{
		wrong_format_error();
	}
}

void parse_port(const string& str, uint8_t& port_number, uint8_t& protocol)
{
	auto it = find(str.begin(), str.end(), '/');

	if (it == str.end())
	{
		//if no protocol is specified
		if (is_number(str))
		{
			port_number = stoi(str);
		}
	}
	else
	{
		string port(str.begin(), it);
		if (is_number(port))
		{
			port_number = stoul(str);
		}
		string proto = string(++it, str.end());
		protocol = parse_protocol(proto);
	}
}

void parse_address(const string& str, uint32_t& address, uint8_t& mask)
{
	auto it = find(str.begin(), str.end(), '/');

	string address_ip(str.begin(), it);
	if (is_valid_ip(address_ip))
	{
		address = stoul(str);
		if (it != str.end())
		{
			string address_mask(++it, str.end());
			if (is_valid_ip(address_mask))
			{
				mask = stoul(str);
			}
			else
			{
				wrong_format_error();
			}
		}
	}
	else
	{
		wrong_format_error();
	}
}

vector<string> parse_rule(const string& str, char separator)
{
	auto it1 = str.begin();
	auto it2 = it1;

	vector<string> result;

	while (it1 != str.end() && it2 != str.end())
	{
		it2 = find(it1, str.end(), separator);
		result.emplace_back(string(it1, it2));
		if (it2 != str.end())
		{
			it1 = ++it2;
		}
	}
	return result;
}