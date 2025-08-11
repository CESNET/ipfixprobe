#pragma once

#include "dnsName.hpp"

namespace ipxp
{

constexpr static bool isPointer(const std::byte byte) noexcept
{
	constexpr uint8_t pointerMask = 0xC0;
	return (static_cast<uint8_t>(byte) & pointerMask) == pointerMask;
}

constexpr static uint16_t getPointerOffset(const std::byte* pointer) noexcept
{
	constexpr uint16_t pointerMask = 0x3FFF;
	return ntohs(*reinterpret_cast<const uint16_t*>(pointer)) & pointerMask;
}

constexpr static std::size_t calculateElementsLength(auto&& container) noexcept
{
    return std::ranges::accumulate(container, std::size_t{0},
        [](std::size_t sum, auto&& element) {
            return sum + element.size();
        });
}

constexpr
std::optional<DNSName> DNSName::createFrom(
    std::span<const std::byte> payload, const std::byte* dnsBegin) noexcept
{
    auto dnsName = std::make_optional<DNSName>();
    uint16_t labelCount = 0;
    while (!payload.empty()) {
        if (isPointer(*payload.data())) {
            if (payload.size() < sizeof(uint16_t)) {
                return std::nullopt;
            }
            const uint16_t pointerOffset = getPointerOffset(payload.data());
            if (pointerOffset >= payload.size()) {
                return std::nullopt;
            }

            const std::size_t lengthBytesCount = 
                dnsName->m_labels.empty() ? 0 : dnsName->m_labels.size();
            dnsName->m_length = calculateElementsLength(
                dnsName->m_labels) + lengthBytesCount + sizeof(pointerOffset);

            payload = std::span<const std::byte>(
                dnsBegin + pointerOffset, payload.end());

            continue;
        }

        const auto labelLength = static_cast<uint8_t>(*payload.data());
        if (labelLength + sizeof(uint8_t) > payload.size()) {
            return std::nullopt;
        }
        if (labelLength == 0) {
            break;
        }

        if (!dnsName->m_labels.full()) {
            dnsName->m_labels.push_back(toStringView(
                payload.subspan(sizeof(uint8_t), labelLength)));
        }

        payload = payload.subspan(labelLength + sizeof(uint8_t));
    }

    return dnsName;
}

constexpr std::string DNSName::toString(const char delimiter) const noexcept
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
