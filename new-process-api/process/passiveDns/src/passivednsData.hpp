#pragma once

#include <boost/static_string.hpp>

#include <dnsParser/dnsQueryType.hpp>
#include <ipAddress.hpp>

namespace ipxp
{

struct PassiveDNSData {
	DNSQueryType type;
	uint16_t id;
	uint8_t ipVersion;
	uint32_t timeToLive;
	IPAddress ip;

	constexpr static std::size_t MAX_NAME_LENGTH = 255;
	boost::static_string<MAX_NAME_LENGTH> name;
};  

} // namespace ipxp

