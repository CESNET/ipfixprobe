/**
 * @file
 * @brief Provides a reader for parsing User-Agent extensions in TLS.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "../../../quic/src/quicVariableInt.hpp"

#include <optional>
#include <ranges>
#include <span>

#include <readers/rangeReader/generator.hpp>
#include <readers/rangeReader/rangeReader.hpp>

namespace ipxp::process {

/**
 * @struct UserAgent
 * @brief Represents a User-Agent with an ID and value.
 */
struct UserAgent {
	uint64_t id;
	std::string_view value;
};

/**
 * @class UserAgentReader
 * @brief A reader for parsing User-Agent extensions from a byte span.
 *
 * This class provides functionality to parse User-Agent extensions from a given payload.
 * It uses a generator to yield each parsed User-Agent as a `UserAgent` struct.
 */
struct UserAgentReader : public RangeReader {
	auto getRange(std::span<const std::byte> userAgentExtension) noexcept
	{
		return Generator([this, userAgentExtension]() mutable -> std::optional<UserAgent> {
			if (userAgentExtension.empty()) {
				setSuccess();
				return std::nullopt;
			}
			const std::optional<quic::VariableLengthInt> id
				= quic::readQUICVariableLengthInt(userAgentExtension);
			if (!id.has_value()) {
				return std::nullopt;
			}

			const std::size_t lengthOffset = id->length;
			const std::optional<quic::VariableLengthInt> userAgentLength
				= quic::readQUICVariableLengthInt(userAgentExtension.subspan(lengthOffset));
			if (!userAgentLength.has_value()) {
				return std::nullopt;
			}
			if (id->length + userAgentLength->length + userAgentLength->value
				> userAgentExtension.size()) {
				return std::nullopt;
			}

			const std::size_t userAgentOffset = lengthOffset + userAgentLength->length;
			const auto userAgent
				= reinterpret_cast<const char*>(userAgentExtension.data() + userAgentOffset);

			userAgentExtension
				= userAgentExtension.subspan(userAgentOffset + userAgentLength->length);

			return UserAgent {id->value, {userAgent, userAgentLength->value}};
		});
	}
};

/*
class TLSUserAgentReader : public RangeReader<UserAgentReaderFactory> {
public:
	TLSUserAgentReader(std::span<const std::byte> userAgentExtension)
		: RangeReader(userAgentExtension, UserAgentReaderFactory{this}) {}
};*/

} // namespace ipxp::process