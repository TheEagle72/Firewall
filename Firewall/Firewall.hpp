#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <memory>
#include "base_rule.hpp"
#include <vector>
#include <string>

#include "Packet.hpp"

class Firewall
{
private:
	std::vector<std::unique_ptr<base_rule>> rules;
	bool default_mode = false;
public:
	unsigned add_rule(const std::string&);
	void delete_rule(int);
	void clear();
	void set_default_mode(bool);
	bool check_packet(const Packet&);
};
