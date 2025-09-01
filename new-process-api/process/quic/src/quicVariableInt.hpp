#pragma once

#include <span>
#include <optional>
#include <arpa/inet.h>

#include <utils/variableLengthType.hpp>
#include <utils/toHostByteOrder.hpp>

namespace ipxp
{

using VariableLengthInt = VariableLengthType<uint64_t>;

constexpr inline
std::optional<VariableLengthInt> readQUICVariableLengthInt(std::span<const std::byte> data) noexcept
{
	auto res = std::make_optional<VariableLengthInt>();
    if (data.empty()) {
        return std::nullopt;
    }
	const uint8_t twoBits = static_cast<uint8_t>(data[0]) & 0xC0;

	switch (twoBits) {
	case 0:
        if (data.size() < sizeof(uint8_t)) {
            return std::nullopt;
        }
        res->length = sizeof(uint8_t);
        res->value = static_cast<uint8_t>(data[0]) & 0x3F;
		return res;
	case 64:
		if (data.size() < sizeof(uint16_t)) {
			return std::nullopt;
		}
		res->value 
            = ntohs(*reinterpret_cast<const uint16_t*>(data.data())) & 0x3FFF;
        res->length = sizeof(uint16_t);
		return res;
	case 128:
		if (data.size() < sizeof(uint32_t)) {
			return std::nullopt;
		}
		res->value = ntohl(
            *reinterpret_cast<const uint32_t*>(data.data())) & 0x3FFFFFFF;
		res->length = sizeof(uint32_t);
		return res;
	case 192:
		if (data.size() < sizeof(uint64_t)) {
			return std::nullopt;
		}
		res->value = toHostByteOrder(*reinterpret_cast<const uint64_t*>(
            data.data())) & 0x3FFFFFFFFFFFFFFF;
		res->length = sizeof(uint64_t);
		return res;
	default:
		return std::nullopt;
	}
} 

} // namespace ipxp
