#pragma once

#include <string>
class Protocol
{
	std::string protocol_;
public:
	Protocol();
	Protocol(std::string);
};

class ProtocolTCP final : Protocol
{

};

class ProtocolUDP final : Protocol
{

};