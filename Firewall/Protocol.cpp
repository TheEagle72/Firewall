#include "Protocol.hpp"

Protocol::Protocol()
{
	protocol_ = "any";
}

Protocol::Protocol(std::string protocol)
{
	protocol_ = protocol;
}
