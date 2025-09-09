/**
 * @file
 * @brief DNS-SD record.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <string_view>
#include <vector>
#include <format>

#include <dnsParser/dnsRecord.hpp>
#include <dnsParser/dnsName.hpp>

namespace ipxp
{
   
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
    std::vector<DNSName> txtContent;

    /**
	 * @brief Converts record to string.
	 * @return String representation of the record.
	 */
    std::string toString() const noexcept
    {
        const std::string& txtContentStr = fmt::join(txtContent |
            std::transform([](const DNSName& name) {
                return name.toString();
            }), ":");
        return std::format(
            "{};{};{};{};{};{};", requestName.toString(), 
            srvPort, srvTarget.toString(), 
            cpu.toString(), operatingSystem.toString(),
            txtContentStr);
    }
};

} // namespace ipxp
