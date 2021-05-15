#include "pch.h"
#include "Firewall.hpp"
#include "Parser.hpp"
#include <unordered_map>
#include <limits>

using namespace std;

string random_ip()
{
	string result;
	for (int shift = 24; shift >= 0; shift -= 8)
	{
		result += to_string(rand() % 255);
		result += '.';
	}
	result.pop_back();
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
	str += to_string(ip_to_decimal(random_ip()));
	str += " ";
	str += to_string(ip_to_decimal(random_ip()));
	str += " ";
	str += to_string(random_port());
	str += " ";
	str += to_string(random_port());

	return  Packet(str);
}



TEST(Parser, is_number)
{
	EXPECT_EQ(is_number("128214"), true);
	EXPECT_EQ(is_number("0"), true);
	EXPECT_EQ(is_number("128"), true);
	EXPECT_EQ(is_number(""), false);
	EXPECT_EQ(is_number("abc"), false);
	EXPECT_EQ(is_number("123abc"), false);
	EXPECT_EQ(is_number("abc123"), false);
	EXPECT_EQ(is_number(".&%$@"), false);
	EXPECT_EQ(is_number("123.532"), false);
}

TEST(Parser, is_valid_ip)
{
	EXPECT_EQ(is_valid_ip("abc"), false);
	EXPECT_EQ(is_valid_ip("0.0.0.0a"), false);
	EXPECT_EQ(is_valid_ip("124214"), false);
	EXPECT_EQ(is_valid_ip("%@#%@#"), false);
	EXPECT_EQ(is_valid_ip("123.124.124"), false);
	for (int i = 0; i < 5; ++i)
	{
		EXPECT_EQ(is_valid_ip(random_ip()), true);
	}
}

TEST(Parser, ip_to_decimal)
{
	EXPECT_EQ(ip_to_decimal("0.0.0.0"), 0);
	EXPECT_EQ(ip_to_decimal("192.168.1.0"), 3232235776);
	EXPECT_EQ(ip_to_decimal("214.156.43.63"), 3600558911);
	EXPECT_EQ(ip_to_decimal("65.34.246.12"), 1092810252);
}

TEST(Parser, decimal_to_ip)
{
	EXPECT_EQ(decimal_to_ip(0), "0.0.0.0");
	EXPECT_EQ(decimal_to_ip(3232235776), "192.168.1.0");
	EXPECT_EQ(decimal_to_ip(3600558911), "214.156.43.63");
	EXPECT_EQ(decimal_to_ip(1092810252), "65.34.246.12");
}

TEST(Firewall, port)
{
	srand(0);
	Firewall firewall;
	Packet packet0 = generate_packet(0);
	Packet packet1 = generate_packet(1);
	Packet packet2 = generate_packet(2);

	firewall.set_default_mode(false);
	EXPECT_EQ(firewall.check_packet(packet0), false);
	firewall.set_default_mode(true);
	EXPECT_EQ(firewall.check_packet(packet0), true);

	string rule;
	rule += "allow ";
	rule += to_string(packet1.get_in_port());
	firewall.add_rule(rule);
	rule.clear();

	rule += "deny ";
	rule += to_string(packet2.get_in_port());
	firewall.add_rule(rule);

	EXPECT_EQ(firewall.check_packet(packet1), true);
	EXPECT_EQ(firewall.check_packet(packet2), false);
}