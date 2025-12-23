/**
 * @file ipfixTemplate.hpp
 * @brief Structure that represents an IPFIX template.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <chrono>
#include <optional>

namespace ipxp::output::ipfix {

class IPFIXTemplateBuilder;

/**
 * @struct IPFIXTemplate
 * @brief Structure representing an IPFIX template.
 */
struct IPFIXTemplate {
	const std::vector<std::byte>
		serializedTemplate; /// Serialized representation of the template to be sent
	const std::vector<uint8_t>
		requiredProtocolIndices; /// Indices of protocols required by this template
	const uint16_t staticSize; /// Size of the static part of the template
	std::chrono::steady_clock::time_point
		lastSendTime; /// Last time this template was sent to the collector

private:
	friend class IPFIXTemplateBuilder;

	IPFIXTemplate(
		std::vector<std::byte> serializedTemplate,
		std::vector<uint8_t> requiredProtocolIndices,
		const uint16_t staticSize)
		: serializedTemplate(std::move(serializedTemplate))
		, requiredProtocolIndices(std::move(requiredProtocolIndices))
		, staticSize(staticSize)
	{
	}
};

} // namespace ipxp::output::ipfix