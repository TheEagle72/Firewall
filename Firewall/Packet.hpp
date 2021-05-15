#pragma once

#include <cstdint>
#include <string>

class Packet final
{
	uint8_t protocol;
	uint32_t in_address;
	uint32_t out_address;
	uint16_t in_port;
	uint16_t out_port;
public:
	Packet(std::string&);
	[[nodiscard]] uint8_t get_protocol()const;
	[[nodiscard]] uint32_t get_in_address()const;
	[[nodiscard]] uint32_t get_out_address()const;
	[[nodiscard]] uint16_t get_in_port() const;
	[[nodiscard]] uint16_t get_out_port() const;
};

