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
    
struct DNSSRVRecord {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    DNSName target;

    constexpr static std::optional<DNSSRVRecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSSRVRecord>();

        if (payload.size() < 3 * sizeof(uint16_t)) {
            return std::nullopt;
        }

        const auto* svr = reinterpret_cast<const DNSSRVRecord*>(
            payload.data());
        res->priority = ntohs(svr->priority);
        res->weight = ntohs(svr->weight);
        res->port = ntohs(svr->port);
        const std::optional<DNSName> target = DNSName::createFrom(
            payload.subspan(sizeof(DNSSRVRecord)), fullDNSPayload); 
        if (!target.has_value()) {
            return std::nullopt;
        }
        res->target = *target;

        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;
    	oss << priority << " " << weight << " " << port;
        return oss.str();
    }
};

} // namespace ipxp
