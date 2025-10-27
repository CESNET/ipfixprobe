/**
 * @file
 * @brief Provides DNS name structure and parsing functionality.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "dnsName.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <optional>
#include <span>
#include <string>

#include <arpa/inet.h>
#include <boost/container/static_vector.hpp>
#include <boost/static_string.hpp>
#include <utils/stringViewUtils.hpp>
#include <utils/toHostByteOrder.hpp>

namespace ipxp {

constexpr static bool isPointer(const std::byte byte) noexcept
{
	constexpr uint8_t pointerMask = 0xC0;
	return (static_cast<uint8_t>(byte) & pointerMask) == pointerMask;
}

constexpr static uint16_t getPointerOffset(const std::byte* pointer) noexcept
{
	constexpr uint16_t pointerMask = 0x3FFF;
	return toHostByteOrder(*reinterpret_cast<const uint16_t*>(pointer)) & pointerMask;
}

constexpr static std::size_t calculateElementsLength(auto&& container) noexcept
{
	return std::accumulate(
		container.begin(),
		container.end(),
		std::size_t {0},
		[](std::size_t sum, auto&& element) { return sum + element.size(); });
}

std::optional<DNSName> DNSName::createFrom(
	std::span<const std::byte> payload,
	std::span<const std::byte> fullDNSpayload) noexcept
{
	auto dnsName = std::make_optional<DNSName>();
	while (!payload.empty()) {
		if (isPointer(*payload.data())) {
			if (payload.size() < sizeof(uint16_t)) {
				return std::nullopt;
			}
			const uint16_t pointerOffset = getPointerOffset(payload.data());
			if (pointerOffset >= fullDNSpayload.size()) {
				return std::nullopt;
			}

			const std::size_t lengthBytesCount
				= dnsName->m_labels.empty() ? 0 : dnsName->m_labels.size();
			dnsName->m_length = calculateElementsLength(dnsName->m_labels) + lengthBytesCount
				+ sizeof(pointerOffset);

			payload = fullDNSpayload.subspan(pointerOffset);
			continue;
		}

		const auto labelLength = static_cast<uint8_t>(*payload.data());
		if (labelLength + sizeof(uint8_t) > payload.size()) {
			return std::nullopt;
		}
		if (labelLength == 0) {
			return dnsName;
		}

		if (dnsName->m_labels.size() == dnsName->m_labels.capacity()) {
			return std::nullopt;
		}

		dnsName->m_labels.push_back(toStringView(payload.subspan(sizeof(uint8_t), labelLength)));

		payload = payload.subspan(labelLength + sizeof(uint8_t));
	}

	return std::nullopt;
}

bool DNSName::operator==(const DNSName& other) const noexcept
{
	return std::equal(
		m_labels.begin(),
		m_labels.end(),
		other.m_labels.begin(),
		other.m_labels.end());
}

std::string DNSName::toString(const char delimiter) const noexcept
{
	std::string res;
	std::ranges::for_each(m_labels, [&res, delimiter](std::string_view label) {
		res += label;
		res += delimiter;
	});

	if (!res.empty()) {
		res.pop_back();
	}
	return res;
}

} // namespace ipxp
