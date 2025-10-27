/**
 * @file
 * @brief DNS-SD record.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <format>
#include <sstream>
#include <string_view>
#include <vector>

#include <dnsParser/dnsName.hpp>
#include <dnsParser/dnsRecord.hpp>
#include <utils/stringUtils.hpp>

namespace ipxp::process::dnssd {

/**
 * @struct DNSSDRecord
 * @brief Struct representing DNS-SD request and response to it.
 */
struct DNSSDRecord {
	DNSName requestName;

	uint16_t srvPort;
	DNSName srvTarget;
	DNSName cpu;
	DNSName operatingSystem;
	// std::vector<DNSName> txtContent;
	std::string txtContent;

	/**
	 * @brief Converts record to string.
	 * @return String representation of the record.
	 */
	std::string toString() const noexcept
	{
		/*std::string txtContentStr(200, '\0');
		concatenateRangeTo(txtContent |
			std::views::transform([](const DNSName& name) {
				return name.toString();
			}), txtContentStr, ':');
*/
		return std::format(
			"{};{};{};{};{};{};",
			requestName.toString(),
			srvPort,
			srvTarget.toString(),
			cpu.toString(),
			operatingSystem.toString(),
			txtContent);
	}
};

} // namespace ipxp::process::dnssd
