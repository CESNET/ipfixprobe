#pragma once

#include <optional>
#include <span>
#include <string>
#include <sstream>
#include <cstdint>
#include <array>

#include "../dnsName.hpp"

namespace ipxp
{

struct DNSTXTRecord {
    //DNSName content;
    std::string content;

    static std::optional<DNSTXTRecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSTXTRecord>();

        /*const std::optional<DNSName> txt 
            = DNSName::createFrom(payload, fullDNSPayload);
        if (!txt.has_value() || txt->length() == 0) {
            return std::nullopt;
        }
        res->content = *txt;
*/
        res->content = std::string(reinterpret_cast<const char*>(payload.data()), payload.size());
        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::string res = content;
        const std::size_t firstPoint = res.find('.');
        if (firstPoint != std::string::npos) {
            res[firstPoint] = ' ';
        }

        return res;
    }

};

} // namespace ipxp
