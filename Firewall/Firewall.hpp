#pragma once

#include <memory>
#include "rule_base.hpp"
#include <vector>
#include "Packet.hpp"

class firewall_nullptr_exception : std::exception
{
	char const* what() const override { return "rule is nullptr"; };
};

class Firewall final
{
private:
	std::vector<std::unique_ptr<rule_base>> rules;
	Permission default_permission = Permission::allow;
public:
	Firewall() = default;
	size_t add_rule(std::unique_ptr<rule_base> rule);
	void delete_rule(size_t index);
	void clear();
	void set_default_permission(Permission permission);
	[[nodiscard]] bool check_packet(const Packet& packet) const;
};
