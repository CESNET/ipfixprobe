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
    DNSName content;

    constexpr static std::optional<DNSTXTRecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSTXTRecord>();

        const std::optional<DNSName> txt 
            = DNSName::createFrom(payload, fullDNSPayload);
        if (!txt.has_value() || txt->length() == 0) {
            return std::nullopt;
        }
        res->content = *txt;

        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::string res = content.toString();
        const std::size_t firstPoint = res.find('.');
        if (firstPoint != std::string::npos) {
            res[firstPoint] = ' ';
        }

        return res;
    }

};

} // namespace ipxp
