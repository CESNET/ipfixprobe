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

struct DNSRRSIGRecord {
    uint16_t typeCovered;
	uint8_t algorithm;
	uint8_t labels;
	uint32_t originalTTL;
	uint32_t expiration;
	uint32_t inception;
	uint16_t keyTag;

    constexpr static std::optional<DNSRRSIGRecord> createFrom(
        std::span<const std::byte> payload) noexcept
    {
        auto res = std::make_optional<DNSRRSIGRecord>();

        if (payload.size() < sizeof(DNSRRSIGRecord)) {
		    return std::nullopt;
        }
        const auto rrsig = reinterpret_cast<const DNSRRSIGRecord*>(
            payload.data());
        res->typeCovered = ntohs(rrsig->typeCovered);
        res->algorithm = rrsig->algorithm;
        res->labels = rrsig->labels;
        res->originalTTL = ntohl(rrsig->originalTTL);
        res->expiration = ntohl(rrsig->expiration);
        res->inception = ntohl(rrsig->inception);
        res->keyTag = ntohs(rrsig->keyTag);

        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;
        oss << typeCovered << " " 
            << static_cast<uint16_t>(algorithm) << " "
            << static_cast<uint16_t>(labels) << " " 
            << originalTTL << " "
            << expiration << " " << inception << " "
            << keyTag;
        return oss.str();
    }
};

} // namespace ipxp
