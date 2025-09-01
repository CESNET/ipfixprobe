#pragma once

#include <boost/static_string.hpp>

#include "dnssdRecord.hpp"

namespace ipxp
{

struct DNSSDData {

	constexpr static std::size_t MAX_STRING_SIZE = 510;
	boost::static_string<MAX_STRING_SIZE> queries;
	boost::static_string<MAX_STRING_SIZE> responses;

	constexpr static std::size_t MAX_REQUEST_TO_STORE = 510;
	boost::container::static_vector<DNSSDRecord, MAX_REQUEST_TO_STORE> requests;

	DNSSDRecord& findOrInsert(const DNSName& name) noexcept
	{
		// TODO USE RANGE ?
		auto it = std::find_if(
			requests.begin(), requests.end(), 
			[&name](const DNSSDRecord& record) {
				return record.requestName == name;
			});
		if (it != requests.end()) {
			return *it;
		}

		requests.emplace_back(name);
		return requests.back();
	}
	

};  

} // namespace ipxp

