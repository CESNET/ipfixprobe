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
    
struct DNSMINFORecord {
    DNSName rMailBox;
    DNSName eMailBox;

    static std::optional<DNSMINFORecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSMINFORecord>();

        const std::optional<DNSName> rMailBox = DNSName::createFrom(
            payload, fullDNSPayload);
        if (!rMailBox.has_value()) {
            return std::nullopt;
        }
        res->rMailBox = *rMailBox;

        const std::optional<DNSName> eMailBox
            = DNSName::createFrom(payload.subspan(rMailBox->length()), fullDNSPayload);
        if (!eMailBox.has_value()) {
            return std::nullopt;
        }
        res->eMailBox = *eMailBox;

        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;
        oss << rMailBox.toString() << " " << eMailBox.toString();
        return oss.str();
    }

};

} // namespace ipxp
