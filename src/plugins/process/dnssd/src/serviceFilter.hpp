/**
 * @file serviceFilter.hpp
 * @brief Declaration of ServiceFilter for DNS-SD service filtering.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "dnssdOptionsParser.hpp"

#include <string_view>

namespace ipxp::process::dnssd {

class ServiceFilter {
public:
	ServiceFilter(const DNSSDOptionsParser::TxtProcessingMode& mode);

	bool matches(std::string_view service, std::string_view txtValue) const noexcept;

private:
	std::function<bool(std::string_view, std::string_view)> m_matcher;
	// const DNSSDOptionsParser::TxtProcessingMode m_mode;
};

} // namespace ipxp