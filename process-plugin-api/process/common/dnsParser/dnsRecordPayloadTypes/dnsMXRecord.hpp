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
    
struct DNSMXRecord {
    uint16_t preference;
    DNSName exchangeName;

    constexpr static std::optional<DNSMXRecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSMXRecord>();

        std::ostringstream oss;
        if (payload.size() < sizeof(uint16_t)) {
            return std::nullopt;
        }

        res->preference = ntohs(
            *reinterpret_cast<const uint16_t*>(payload.data()));
        const std::optional<DNSName> exchangeName
            = DNSName::createFrom(payload.subspan(sizeof(preference)), fullDNSPayload);
        if (!exchangeName.has_value()) {
            return std::nullopt;
        }

        res->exchangeName = *exchangeName;
        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;
        oss << preference << " " << exchangeName.toString();
        return oss.str();
    }

};

} // namespace ipxp
