#pragma once

#include <iostream>
#include <array>
#include <span>
#include <cstddef>
#include <cstdint>

namespace ipxp {

struct MACAddress {
	std::array<std::byte, 6> address;

	constexpr MACAddress() noexcept
	: address{}
	{
	}

	constexpr MACAddress(std::span<const std::byte, 6> address) noexcept
	: address{}
	{
		std::ranges::copy(address, this->address.begin());
	}
};

inline std::ostream& operator<<(std::ostream& os, const MACAddress& mac)
{
	(void) mac;

	os << "MacAddress{}";
	return os;
}

} // namespace ipxp
