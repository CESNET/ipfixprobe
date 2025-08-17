#pragma once

#include <string_view>
#include <vector>
#include <format>

#include <dnsParser/dnsRecord.hpp>
#include <dnsParser/dnsName.hpp>

namespace ipxp
{
    
struct DNSSDRecord {
    DNSName requestName;

    uint16_t srvPort;
    DNSName srvTarget;
    DNSName cpu;
    DNSName operatingSystem;
    std::vector<DNSName> txtContent;

    std::string toString() const noexcept
    {
        // TODO FIX
        const std::string& txtContentStr = "";
        /*fmt::join(txtContent |
            std::transform([](const DNSName& name) {
                return name.toString();
            }), ":");*/
        return std::format(
            "{};{};{};{};{};{};", requestName.toString(), 
            srvPort, srvTarget.toString(), 
            cpu.toString(), operatingSystem.toString(),
            txtContentStr);
    }
};


} // namespace ipxp
