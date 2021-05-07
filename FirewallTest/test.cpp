#include "pch.h"
#include "Firewall.hpp"
#include <limits>

uint32_t generate_packet()
{
	return rand() % (std::numeric_limits<uint32_t>::max());

	/*for (int i = 0; i < 30; ++i)
	{
		for (int j = 0; j < 3; ++j)
		{
			file_output << rand() % 255 << '.';
		}
		file_output << rand() % 255 << endl;
	}*/
}

TEST(Firewall, simple_rules)
{

	
}
