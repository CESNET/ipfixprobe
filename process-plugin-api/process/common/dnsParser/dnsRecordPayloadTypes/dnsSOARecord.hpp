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
    
struct DNSSOARecord {
    uint32_t serialNumber;
	uint32_t refreshInterval;
	uint32_t retryInterval;
	uint32_t expireLimit;
	uint32_t minimumTTL;
    DNSName name;
    DNSName email;

    constexpr static std::optional<DNSSOARecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSSOARecord>();

        const std::optional<DNSName> name = DNSName::createFrom(
            payload, fullDNSPayload);
        if (!name.has_value()) {
            return std::nullopt;
        }
        res->name = *name;

        const std::optional<DNSName> email
            = DNSName::createFrom(payload.subspan(name->length()), fullDNSPayload);
        if (!email.has_value() || 
            name->length() + email->length() + sizeof(DNSSOARecord) > payload.size()) {
            return {};
        }
        res->email = *email;

        const auto soa = reinterpret_cast<const DNSSOARecord*>(
            payload.data() + name->length() + email->length());
        res->serialNumber = ntohl(soa->serialNumber);
        res->refreshInterval = ntohl(soa->refreshInterval);
        res->retryInterval = ntohl(soa->retryInterval);
        res->expireLimit = ntohl(soa->expireLimit);
        res->minimumTTL = ntohl(soa->minimumTTL);

        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;
    	oss << name.toString() << " " << email.toString();

	    oss << " " << serialNumber << " " << refreshInterval << " "
		<< retryInterval << " " << expireLimit << " "
		<< minimumTTL;

        return oss.str();
    }

};

} // namespace ipxp
