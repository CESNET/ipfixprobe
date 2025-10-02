#pragma once

#include "dnssdOptionsParser.hpp"

#include <string_view>

namespace ipxp {

class ServiceFilter {
public:
	ServiceFilter(const DNSSDOptionsParser::TxtProcessingMode& mode);

	bool matches(std::string_view service, std::string_view txtValue) const noexcept;

private:
	std::function<bool(std::string_view, std::string_view)> m_matcher;
	// const DNSSDOptionsParser::TxtProcessingMode m_mode;
};

} // namespace ipxp