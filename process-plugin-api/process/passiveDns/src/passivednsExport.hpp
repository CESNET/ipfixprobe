#pragma once

#include <boost/static_string.hpp>

#include <dnsParser/dnsQueryType.hpp>
#include <ipAddress.hpp>

namespace ipxp
{

struct PassiveDNSExport {
	constexpr static std::size_t MAX_NAME_LENGTH = 255;

	DNSQueryType type;
	uint16_t id;
	uint8_t ipVersion;
	boost::static_string<MAX_NAME_LENGTH> name;
	uint32_t timeToLive;
	IPAddress ip;
};  

} // namespace ipxp

