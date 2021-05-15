#include "pch.h"
#include "Firewall.hpp"
#include "Parser.hpp"
#include "fabric_rule.hpp"
#include <unordered_map>
#include <limits>

using namespace std;

uint32_t random_ip()
{
	uint32_t result = 0;
	for (int shift = 24; shift >= 0; shift -= 8)
	{
		result += (rand() % 255) << shift;
	}
	return result;
}

namespace
{
	const unordered_map<uint8_t, uint8_t> protocol_table
	{
		{0,1}, // icmp
		{1,6}, // tcp
		{2,17} // udp
	};

	const unordered_map<uint8_t, string> protocol_table_str
	{
		{1,"icmp"}, // icmp
		{6,"tcp"}, // tcp
		{17,"udp"} // udp
	};

}

uint8_t random_protocol()
{
	return protocol_table.at(rand() % 2);
}

uint16_t random_port()
{
	return  rand() % numeric_limits<uint16_t>::max();
}

Packet generate_packet(const unsigned seed)
{
	string str;

	srand(seed);
	str += to_string(random_protocol());
	str += " ";
	str += to_string(random_ip());
	str += " ";
	str += to_string(random_ip());
	str += " ";
	str += to_string(random_port());
	str += " ";
	str += to_string(random_port());

	return  Packet(str);
}



TEST(Firewall, port)
{
	for (int i = 0; i < 100; ++i)
	{
		Firewall firewall;
		Packet packet0 = generate_packet(i);
		Packet packet1 = generate_packet(i + 1);
		Packet packet2 = generate_packet(i + 2);
		Packet packet3 = generate_packet(i + 3);

		string rule;

		rule += "allow ";
		rule += to_string(packet0.get_in_port());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "deny ";
		rule += to_string(packet1.get_in_port());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "allow ";
		rule += to_string(packet2.get_in_port());
		rule += "/";
		rule += protocol_table_str.at(packet2.get_protocol());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "deny ";
		rule += to_string(packet3.get_in_port());
		rule += "/";
		rule += protocol_table_str.at(packet3.get_protocol());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		EXPECT_EQ(firewall.check_packet(packet0), true);
		EXPECT_EQ(firewall.check_packet(packet1), false);
		EXPECT_EQ(firewall.check_packet(packet2), true);
		EXPECT_EQ(firewall.check_packet(packet3), false);
	}
}


TEST(Firewall, address)
{
	for (int i = 0; i < 100; ++i)
	{
		Firewall firewall;
		Packet packet0 = generate_packet(i);
		Packet packet1 = generate_packet(i + 1);
		Packet packet2 = generate_packet(i + 2);
		Packet packet3 = generate_packet(i + 3);
		Packet packet4 = generate_packet(i + 4);
		Packet packet5 = generate_packet(i + 5);

		string rule;

		rule += "allow from ";
		rule += decimal_to_ip(packet0.get_in_address());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "deny from ";
		rule += decimal_to_ip(packet1.get_in_address());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "allow from ";
		rule += decimal_to_ip(packet2.get_in_address());
		rule += " to any port ";
		rule += to_string(packet2.get_in_port());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "deny from ";
		rule += decimal_to_ip(packet3.get_in_address());
		rule += " to any port ";
		rule += to_string(packet3.get_in_port());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "allow from ";
		rule += decimal_to_ip(packet4.get_in_address());
		rule += " to any port ";
		rule += to_string(packet4.get_in_port());
		rule += " proto ";
		rule += protocol_table_str.at(packet4.get_protocol());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		rule += "deny from ";
		rule += decimal_to_ip(packet4.get_in_address());
		rule += " to any port ";
		rule += to_string(packet4.get_in_port());
		rule += " proto ";
		rule += protocol_table_str.at(packet4.get_protocol());
		firewall.add_rule(fabric_rule::create_rule(rule));
		rule.clear();

		EXPECT_EQ(firewall.check_packet(packet0), true);
		EXPECT_EQ(firewall.check_packet(packet1), false);
		EXPECT_EQ(firewall.check_packet(packet2), true);
		EXPECT_EQ(firewall.check_packet(packet3), false);
		EXPECT_EQ(firewall.check_packet(packet4), true);
		EXPECT_EQ(firewall.check_packet(packet5), false);

		firewall.clear();
		firewall.set_default_mode(true);
		EXPECT_EQ(firewall.check_packet(packet0), true);
		EXPECT_EQ(firewall.check_packet(packet1), true);
		EXPECT_EQ(firewall.check_packet(packet2), true);
		EXPECT_EQ(firewall.check_packet(packet3), true);
		EXPECT_EQ(firewall.check_packet(packet4), true);
		EXPECT_EQ(firewall.check_packet(packet5), true);
		firewall.set_default_mode(false);
		EXPECT_EQ(firewall.check_packet(packet0), false);
		EXPECT_EQ(firewall.check_packet(packet1), false);
		EXPECT_EQ(firewall.check_packet(packet2), false);
		EXPECT_EQ(firewall.check_packet(packet3), false);
		EXPECT_EQ(firewall.check_packet(packet4), false);
		EXPECT_EQ(firewall.check_packet(packet5), false);
	}
}