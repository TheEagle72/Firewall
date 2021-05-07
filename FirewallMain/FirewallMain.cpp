#include <iostream>
#include <fstream>

#include "Firewall.hpp"
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
			cerr << "Error";
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
		firewall.add_rule(str);
	}

	while (getline(file_packets, str))
	{
		file_output << str << " - " << (firewall.check_packet(str) ? "ALLOWED" : "DENIED") << endl;
	}


	return 0;
}
