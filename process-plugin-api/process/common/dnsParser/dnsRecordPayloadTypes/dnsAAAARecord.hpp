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
    
struct DNSAAAARecord {
    std::span<const std::byte, 16> address;

    constexpr static std::optional<DNSAAAARecord> createFrom(
        std::span<const std::byte> payload) noexcept
    {
        auto res = std::make_optional<DNSAAAARecord>(payload.first<16>());
        if (payload.size() < res->address.size()) {
            return std::nullopt;
        }

        res->address = payload.first<16>();
        return res;
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;

        std::array<char, INET6_ADDRSTRLEN> addressStr;
        inet_ntop(AF_INET6, address.data(), addressStr.data(), INET6_ADDRSTRLEN);
        oss << address.data();

        return oss.str();
    }

};

} // namespace ipxp
