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
        if (payload.size() < address.size()) {
            return std::nullopt;
        }

        address = payload.first<16>();
    }

    std::string toDNSString() const noexcept
    {
        std::ostringstream oss;

        std::array<char, INET6_ADDRSTRLEN> address;
        inet_ntop(AF_INET6, address.data(), address.data(), INET6_ADDRSTRLEN);
        oss << address.data();

        return oss.str();
    }

};

} // namespace ipxp
