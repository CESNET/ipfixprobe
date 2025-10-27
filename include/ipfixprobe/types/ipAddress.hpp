#pragma once

#include <algorithm>
#include <array>
#include <compare>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <limits>

#include <ipfixprobe/ipaddr.hpp>

namespace ipxp {

union IPAddress {
	std::array<uint8_t, 16> u8;
	std::array<uint16_t, 8> u16;
	std::array<uint32_t, 4> u32;
	std::array<uint64_t, 2> u64;

	constexpr IPAddress() noexcept { std::memset(&u8, 0, sizeof(IPAddress)); }

	constexpr IPAddress(const uint32_t ipv4) noexcept
	{
		u32[0] = ipv4;
		u32[1] = 0;
		u32[2] = u32[3] = std::numeric_limits<uint32_t>::max();
	}

	constexpr IPAddress(const std::span<const std::byte, 16>& ipv6) noexcept
	{
		std::memcpy(&u8, ipv6.data(), sizeof(u8));
	}

	constexpr IPAddress(const ipaddr_t address, IP version) noexcept
		: IPAddress(address.v4)
	{
		if (version == IP::v6) {
			std::memcpy(&u8, address.v6, 16);
		}
	}

	// TODO remove. Added because of AMON compatibility
	constexpr IPAddress(const auto& container)
	{
		if (container.size() != 4 && container.size() != 16) {
			throw std::invalid_argument("IPAddress: container must have size 4 or 16");
		}

		std::memcpy(&u8, container.data(), container.size());
		if (container.size() == 4) {
			u32[1] = 0;
			u32[2] = u32[3] = std::numeric_limits<uint32_t>::max();
		}
	}

	constexpr IPAddress(const IPAddress& other) noexcept { u8 = other.u8; }

	constexpr bool isIPv4() const noexcept
	{
		return u32[1] == 0 && u32[2] == std::numeric_limits<uint32_t>::max()
			&& u32[3] == std::numeric_limits<uint32_t>::max();
	}

	constexpr bool isIPv6() const noexcept { return !isIPv4(); }

	// constexpr bool operator==(const IPAddress&) const noexcept = default;

	constexpr auto operator<=>(const IPAddress& other) const noexcept { return u64 <=> other.u64; }

	constexpr bool operator==(const IPAddress& other) const noexcept { return u64 == other.u64; }

	// constexpr std::strong_ordering operator<=>(const IPAddress& other) const noexcept = default;

	constexpr IPAddress& operator=(const IPAddress& other) noexcept
	{
		if (this != &other) {
			u8 = other.u8;
		}

		return *this;
	}

	constexpr std::size_t size() const noexcept { return isIPv4() ? 4 : 16; }

	std::string toString() const noexcept
	{
		std::string res;
		constexpr std::size_t MAX_IP_AS_TEXT_SIZE = 30;
		res.reserve(MAX_IP_AS_TEXT_SIZE);

		if (isIPv4()) {
			std::for_each_n(
				reinterpret_cast<const std::byte*>(u8.data()),
				size(),
				[&](const std::byte ipByte) {
					std::format_to(std::back_inserter(res), "{}.", static_cast<int>(ipByte));
				});
		} else {
			std::for_each_n(
				reinterpret_cast<const std::byte*>(u8.data()),
				size(),
				[&](const std::byte ipByte) {
					std::format_to(std::back_inserter(res), "{:02x}:", static_cast<int>(ipByte));
				});
		}
		res.pop_back();
		return res;
	}
};

/*friend constexpr auto operator<=>(const IPAddress& lhs, const IPAddress& rhs) noexcept
{
	return lhs.u64 <=> rhs.u64;
}*/

inline std::ostream& operator<<(std::ostream& os, const IPAddress& ip)
{
	return os << ip.toString();
}

} // namespace ipxp
