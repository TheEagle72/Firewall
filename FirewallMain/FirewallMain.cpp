#include <iostream>
#include <fstream>

#include "Firewall.hpp"
#include "Packet.hpp"
#include "fabric_rule.hpp"
using namespace std;

int main(int argc, char** argv)
{
	ifstream file_rules;
	ifstream file_packets;
	ofstream file_output("output.txt");
	string main_word;

	if (argc == 3)
	{
		file_rules = ifstream(argv[1]);
		file_packets = ifstream(argv[2]);
		if (!file_rules || !file_packets)
		{
			cerr << "error occurred during file opening" << endl;
			exit(0);
		}
	}
	else
	{
		cerr << "Wrong format. Usage: " << argv[0] << " rules_file_path packet_file_path" << endl;
		exit(0);
	}

	Firewall firewall;
	string str;
	while (getline(file_rules, str))
	{
		try
		{
			firewall.add_rule(move(fabric_rule::create_rule(str)));
		}
		catch (exception &e)
		{
			cerr << e.what() << endl;
		}
	}

	while (getline(file_packets, str))
	{
		try
		{
			Packet packet(str);
			file_output << str << " - " << (firewall.check_packet(packet) ? "ALLOWED" : "DENIED") << endl;
		}
		catch (exception &e)
		{
			cerr << e.what() << endl;
			file_output << str << " - WRONG FORMAT" << endl;
		}
	}

	return 0;
}
