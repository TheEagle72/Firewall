#pragma once

#include <cstdint>
#include <string>

class packet_wrong_format_exception : std::exception
{
	[[nodiscard]] char const* what()  const override { return "incorrect data received during packet creation"; };
};


class Packet final
{
	uint8_t protocol;
	uint32_t in_address;
	uint32_t out_address;
	uint16_t in_port;
	uint16_t out_port;
public:
	Packet(const std::string& str);
	[[nodiscard]] uint8_t get_protocol()const;
	[[nodiscard]] uint32_t get_in_address()const;
	[[nodiscard]] uint32_t get_out_address()const;
	[[nodiscard]] uint16_t get_in_port() const;
	[[nodiscard]] uint16_t get_out_port() const;
};

