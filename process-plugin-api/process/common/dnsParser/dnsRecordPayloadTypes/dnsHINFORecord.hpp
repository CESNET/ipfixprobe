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
    
struct DNSHINFORecord {
    DNSName cpu;
    DNSName operatingSystem;

    constexpr static std::optional<DNSHINFORecord> createFrom(
        std::span<const std::byte> payload,
        std::span<const std::byte> fullDNSPayload) noexcept
    {
        auto res = std::make_optional<DNSHINFORecord>();

        const std::optional<DNSName> cpu 
            = DNSName::createFrom(payload, fullDNSPayload);
        if (!cpu.has_value()) {
            return std::nullopt;
        }
        res->cpu = *cpu;

        const std::optional<DNSName> operatingSystem
            = DNSName::createFrom(payload.subspan(cpu->length()), fullDNSPayload);
        if (!operatingSystem.has_value()) {
            return std::nullopt;
        }
        res->operatingSystem = *operatingSystem;

        return res;
    }

    std::string toDNSString() const noexcept
    {
        return cpu.toString() + " " + operatingSystem.toString();
    }

};

} // namespace ipxp
