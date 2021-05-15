#pragma once

#include <memory>
#include "base_rule.hpp"
#include <vector>
#include "Packet.hpp"

class Firewall
{
private:
	std::vector<std::unique_ptr<base_rule>> rules;
	bool default_mode = false;
public:
	unsigned add_rule(std::unique_ptr<base_rule> rule);
	void delete_rule(int index);
	void clear();
	void set_default_mode(bool allow);
	bool check_packet(const Packet& packet);
};
