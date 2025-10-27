/**
 * @file
 * @brief Export data of DNS-SD plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnssdRecord.hpp"

#include <boost/static_string.hpp>

namespace ipxp::process::dnssd {

/**
 * @struct DNSSDContext
 * @brief Struct representing concatenated DNS-SD queries and responses.
 */
struct DNSSDContext {
	constexpr static std::size_t MAX_STRING_SIZE = 510;
	boost::static_string<MAX_STRING_SIZE> queries;
	boost::static_string<MAX_STRING_SIZE> responses;

	constexpr static std::size_t MAX_REQUEST_TO_STORE = 10;
	boost::container::static_vector<DNSSDRecord, MAX_REQUEST_TO_STORE> requests;

	/**
	 * @brief Creates new DNS-SD record or find existing one if it already exists.
	 *
	 * @param name DNS name of the request/response.
	 * @return Found or inserted record.
	 */
	DNSSDRecord& findOrInsert(const DNSName& name) noexcept
	{
		auto it = std::ranges::find_if(requests, [&name](const DNSSDRecord& record) {
			return record.requestName == name;
		});
		if (it != requests.end()) {
			return *it;
		}

		requests.emplace_back(name);
		return requests.back();
	}
};

} // namespace ipxp::process::dnssd
