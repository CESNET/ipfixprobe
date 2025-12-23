/**
 * @file
 * @brief Declaration of OutputConfigurationParser.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "../processPlugin/fieldDescriptor.hpp"
#include "outputAction.hpp"

#include <vector>

namespace ipxp {

/**
 * @class OutputConfigurationParser
 * @brief Parses output field configuration and provides selected fields.
 */
class OutputConfigurationParser {
public:
	/**
	 * @brief Constructs the parser with the given configuration content.
	 * @param configurationContent The configuration content as a string view.
	 */
	OutputConfigurationParser(std::string_view configurationContent);

	/**
	 * @brief Retrieves the output fields based on the available fields.
	 * @param availableFields The list of available field descriptors.
	 * @return A vector of pointers to the selected field descriptors.
	 */
	std::vector<const process::FieldDescriptor*>
	getOutputFields(const std::vector<process::FieldDescriptor>& availableFields) const;

private:
	std::vector<OutputAction> m_configuredActions;
};

}; // namespace ipxp