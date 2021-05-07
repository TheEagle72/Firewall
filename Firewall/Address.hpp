#pragma once

#include <cstdint>

class Address
{
public:
	Address();
	Address(uint32_t, uint32_t);
private:
	uint32_t address_;
	uint32_t mask_;
};

