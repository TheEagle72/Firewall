#include "Address.hpp"

Address::Address()
{
	address_ = 0;
	mask_ = 0;
}

Address::Address(uint32_t address, uint32_t mask)
{
	address_ = address;
	mask_ = mask;
}
