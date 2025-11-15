/**
 * @file
 * @brief Provides a reader for parsing TLS extensions.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "../tlsExtension.hpp"

#include <optional>
#include <ranges>
#include <span>

#include <arpa/inet.h>
#include <readers/rangeReader/generator.hpp>
#include <readers/rangeReader/rangeReader.hpp>

namespace ipxp::process {

/**
 * @class ExtensionReader
 * @brief A reader for parsing TLS extensions from a byte span.
 *
 * This class provides functionality to parse TLS extensions from a given payload.
 * It uses a generator to yield each parsed extension as a `TLSExtension` struct.
 */
class ExtensionReader : public RangeReader {
public:
	auto getRange(std::span<const std::byte> payload) noexcept
	{
		return Generator([payload, this]() mutable -> std::optional<TLSExtension> {
			if (payload.empty()) {
				setSuccess();
				return std::nullopt;
			}
			if (payload.size() < 2 * sizeof(uint16_t)) {
				return std::nullopt;
			}

			const auto type = static_cast<TLSExtensionType>(
				ntohs(*reinterpret_cast<const uint16_t*>(payload.data())));
			const uint16_t length
				= ntohs(*reinterpret_cast<const uint16_t*>(payload.data() + sizeof(type)));
			if (length > payload.size()) {
				return std::nullopt;
			}

			if (sizeof(type) + sizeof(length) + length > payload.size()) {
				return std::nullopt;
			}
			payload = payload.subspan(sizeof(type) + sizeof(length) + length);

			const std::byte* extensionBegin = payload.data() + sizeof(type) + sizeof(length);
			return TLSExtension {type, {extensionBegin, length}};
		});
	}
};

} // namespace ipxp::process