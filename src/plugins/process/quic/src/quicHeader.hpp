#pragma once

#include <cstdint>
#include <optional>
#include <span>

#include <arpa/inet.h>

namespace ipxp {

struct PrimaryQUICHeader {
	uint8_t headerForm;
	uint32_t version;
	uint8_t destConnectionIdLength;

	constexpr static std::optional<PrimaryQUICHeader>
	createFromPayload(std::span<const std::byte> payload) noexcept
	{
		if (payload.size() < sizeof(PrimaryQUICHeader)) {
			return std::nullopt;
		}
		return PrimaryQUICHeader {
			.headerForm = static_cast<uint8_t>(payload[0]),
			.version = ntohl(*reinterpret_cast<const uint32_t*>(&payload[1])),
			.destConnectionIdLength = static_cast<uint8_t>(payload[5])};
	}

} __attribute__((packed));

static_assert(sizeof(FirstQUICHeader) == 6, "FirstQUICHeader size mismatch");

} // namespace ipxp
