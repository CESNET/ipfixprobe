#pragma once

#include <string_view>
#include <vector>

#include <dnsParser/dnsRecord.hpp>

namespace ipxp
{
    
struct DNSSDRecord {
    DNSName requestName;

    uint16_t srvPort;
    DNSName srvTarget;
    DNSName hardwareInfo;
    std::vector<DNSName> txtContent;

    std::string toString() const noexcept
    {
        const std::string& txtContentStr = fmt::join(txtContent |
            std::transform([](const DNSName& name) {
                return name.toString();
            }), ":");
        return std::format(
            "{};{};{};{};{};", requestName.toString(), 
            srvPort, srvTarget.toString(), 
            hardwareInfo.toString(), txtContent);
    }
};


} // namespace ipxp
