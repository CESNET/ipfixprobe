#pragma once

#include <boost/container/static_vector.hpp>

#include "dnssdRecord.hpp"

namespace ipxp
{

struct DNSSDExport {
	constexpr std::size_t MAX_STRING_SIZE = 510;
	constexpr std::size_t MAX_REQUEST_TO_STORE = 510;

	boost::static_string<MAX_STRING_SIZE> queries;
	boost::static_string<MAX_STRING_SIZE> responses;

	boost::container::static_vector<DNSSDRecord, MAX_REQUEST_TO_STORE> requests;

	constexpr
	DNSRecord& findOrInsert(const DNSName& name) noexcept
	{
		auto it = std::ranges::find_if(requests, [&name](const DNSSDRecord& record) {
			return record.name == name;
		});
		if (it != requests.end()) {
			return it->response;
		}

		requests.emplace_back(name);
		return requests.back().response;
	}
	

};  

} // namespace ipxp

