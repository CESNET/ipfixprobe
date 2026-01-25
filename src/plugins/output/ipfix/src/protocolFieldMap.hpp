/**
 * @file protocolFieldMap.hpp
 * @brief Class that maps protocols to their fields.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "utils/heterogeneousStringHash.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <ipfixprobe/processPlugin/fieldDescriptor.hpp>

namespace ipxp::output::ipfix {

/**
 * @class ProtocolFieldMap
 * @brief Class that maps protocols to their associated fields.
 *
 * This class provides functionality to organize and retrieve fields based on their associated
 * protocols. It allows efficient access to fields belonging to specific protocols.
 */
class ProtocolFieldMap {
public:
	/**
	 * @brief Constructs a ProtocolFieldMap from a vector of FieldDescriptor pointers.
	 * @param fields A vector of pointers to FieldDescriptor objects.
	 */
	ProtocolFieldMap(const std::vector<const process::FieldDescriptor*>& fields) noexcept
	{
		for (const process::FieldDescriptor* fieldDescriptor : fields) {
			protocolNames.try_emplace(
				std::string(fieldDescriptor->getGroup()),
				protocolFields.size());
			protocolFields[protocolNames.find(fieldDescriptor->getGroup())->second].push_back(
				fieldDescriptor);
		}
	}

	/**
	 * @brief Retrieves the fields associated with a specific protocol. Should not be used in
	 * time-critical paths.
	 * @param protocolName The name of the protocol.
	 * @return A span of pointers to FieldDescriptor objects associated with the protocol.
	 */
	std::span<const process::FieldDescriptor* const>
	getFieldsOfProtocol(std::string_view protocolName) const
	{
		const std::vector<const process::FieldDescriptor*>& fields
			= protocolFields[protocolNames.find(protocolName)->second];
		return std::span<const process::FieldDescriptor* const>(fields.data(), fields.size());
	}

	/**
	 * @brief Retrieves the fields at a specific index.
	 * @param index The index of the protocol.
	 * @return A span of pointers to FieldDescriptor objects at the specified index.
	 */
	std::span<const process::FieldDescriptor* const>
	getFieldsOnIndex(const std::size_t index) const noexcept
	{
		return std::span<const process::FieldDescriptor* const>(
			protocolFields[index].data(),
			protocolFields[index].size());
	}

	/**
	 * @brief Gets the number of protocols in the map.
	 * @return The number of protocols.
	 */
	std::size_t getProtocolCount() const noexcept { return protocolFields.size(); }

private:
	std::vector<std::vector<const process::FieldDescriptor*>> protocolFields;
	std::unordered_map<std::string, std::size_t, utils::HeterogeneousStringHash, std::equal_to<>>
		protocolNames;
};

} // namespace ipxp::output::ipfix