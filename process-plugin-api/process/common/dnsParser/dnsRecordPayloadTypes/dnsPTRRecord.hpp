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
    
struct DNSPTRRecord {
    DNSName name;

    constexpr static std::optional<DNSPTRRecord> createFrom(
        std::span<const std::byte> payload, 
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSPTRRecord>();

        const std::optional<DNSName> name 
            = DNSName::createFrom(payload, fullDNSPayload);
        if (!name.has_value()) {
            return std::nullopt;
	    }

        res->name = *name;
        return res;
    }

    std::string toDNSString() const noexcept
    {
        return name.toString();
    }

};

} // namespace ipxp
