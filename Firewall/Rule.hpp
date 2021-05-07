#pragma once

#include <string>
#include <vector>

class BaseRule
{
private:

protected:
	bool permission = false;
public:
	virtual ~BaseRule() = 0;
	virtual bool check_packet(const std::string&) { return false; };
};

class RuleProtocol :public BaseRule
{
private:
	uint8_t protocol_;
public:
	RuleProtocol(uint8_t);
};

class RulePort :public BaseRule
{
private:
	uint16_t port_;
public:
	RulePort(uint16_t);
};

class RuleAddress :public BaseRule
{
private:
	uint32_t address_;
	uint8_t mask_;
public:
	RuleAddress(uint32_t, uint8_t);
};

class Rule :public BaseRule
{
private:
	std::vector<std::unique_ptr<BaseRule>> rules_;

	void create_port_protocol(const std::vector<std::string>& args);
	void create_address(const std::vector<std::string>& args);
	void create_address_to_destination(const std::vector<std::string>& args);
	void create_address_to_destination_port(const std::vector<std::string>& args);
	void create_address_to_destination_port_protocol(const std::vector<std::string>& args);

public:
	Rule(const std::string&);
	~Rule() = default;
	bool check_packet(const std::string&);
};