#pragma once

#include <optional>
#include <span>
#include <string>
#include <sstream>
#include <cstdint>
#include <array>
#include <arpa/inet.h>

namespace ipxp
{

struct DNSKEYRecord {
    uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

    constexpr static std::optional<DNSKEYRecord> createFrom(
        std::span<const std::byte> payload) noexcept
    {
        auto res = std::make_optional<DNSKEYRecord>();

        if (payload.size() < sizeof(DNSKEYRecord)) {
            return std::nullopt;
        }

        const auto* dnsKey = reinterpret_cast<const DNSKEYRecord*>(payload.data());
        res->flags = ntohs(dnsKey->flags);
        res->protocol = dnsKey->protocol;
        res->algorithm = dnsKey->algorithm;

        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;
        oss << flags << " " 
            << static_cast<uint16_t>(protocol) << " "
            << static_cast<uint16_t>(algorithm) << " <key>";
        return oss.str();
    }
};

} // namespace ipxp
