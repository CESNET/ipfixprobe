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

struct DNSISDNRecord {
    DNSName isdnAddress;
    DNSName subaddress;

    static std::optional<DNSISDNRecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSISDNRecord>();

        const std::optional<DNSName> isdnAddress 
            = DNSName::createFrom(payload, fullDNSPayload);
        if (!isdnAddress.has_value()) {
            return std::nullopt;
        }
        res->isdnAddress = *isdnAddress;

        const std::optional<DNSName> subaddress
            = DNSName::createFrom(
                payload.subspan(isdnAddress->length()), fullDNSPayload);
        if (!subaddress.has_value()) {
            return std::nullopt;
        }
        res->subaddress = *subaddress;

        return res;
    }

    std::string toDNSString() const noexcept
    {
        return isdnAddress.toString() + " " + subaddress.toString();
    }

};

} // namespace ipxp
