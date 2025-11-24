/**
 * @file
 * @brief Implementation of OutputFieldConfigurationParser.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "fieldMap.hpp"
#include "outputAction.hpp"

#include <fstream>
#include <regex>

#include <outputFieldConfigurationParser.hpp>

namespace ipxp {

std::vector<const process::FieldDescriptor*> OutputFieldParser::getOutputFields(
	const std::vector<process::FieldDescriptor>& availableFields,
	std::string_view configurationFilePath)
{
	std::ifstream configurationFile(configurationFilePath.data());
	if (!configurationFile.is_open()) {
		throw std::invalid_argument(
			"Could not open configuration file: " + std::string(configurationFilePath));
	}

	const std::string configurationContent(
		(std::istreambuf_iterator<char>(configurationFile)),
		std::istreambuf_iterator<char>());

	return FieldMap(availableFields).applyActions(parseActions(configurationContent));
}

} // namespace ipxp
