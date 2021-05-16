#include "Packet.hpp"
#include "Parser.hpp"

using namespace std;


Packet::Packet(const string& str)
{
	vector<string> args = parse_string(str);

	if (args.size() != 5)
	{
		throw packet_wrong_format_exception();
	}

	for (auto arg : args)
	{
		auto it = arg.begin();
		while (it != arg.end() && isdigit(*it)) ++it;
		if (!(!arg.empty() && it == arg.end()))
		{
			throw packet_wrong_format_exception();
		}
	}

	protocol = stoull(args[0]);
	in_address = stoull(args[1]);
	out_address = stoull(args[2]);
	in_port = stoull(args[3]);
	out_port = stoull(args[4]);
}

uint8_t Packet::get_protocol() const
{
	return protocol;
}

uint32_t Packet::get_in_address()const
{
	return in_address;
}

uint32_t Packet::get_out_address()const
{
	return out_address;
}

uint16_t Packet::get_in_port()const
{
	return in_port;
}

uint16_t Packet::get_out_port()const
{
	return out_port;
}
