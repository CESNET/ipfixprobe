/**
 * @file
 * @brief Export data of passive DNS plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <boost/static_string.hpp>
#include <dnsParser/dnsQueryType.hpp>
#include <ipAddress.hpp>

namespace ipxp::process::passivedns {

/**
 * @struct PassiveDNSContext
 * @brief Struct representing passive DNS export data.
 */
struct PassiveDNSContext {
	DNSQueryType type;
	uint16_t id;
	// uint8_t ipVersion;
	uint32_t timeToLive;
	IPAddressVariant ip;

	constexpr static std::size_t MAX_NAME_LENGTH = 255;
	boost::static_string<MAX_NAME_LENGTH> name;
};

} // namespace ipxp::process::passivedns
