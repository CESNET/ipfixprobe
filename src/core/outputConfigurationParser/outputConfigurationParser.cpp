/**
 * @file
 * @brief Implementation of OutputConfigurationParser.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "fieldMap.hpp"
#include "outputAction.hpp"

#include <fstream>
#include <regex>

#include <outputConfigurationParser.hpp>

namespace ipxp {

OutputConfigurationParser::OutputConfigurationParser(std::string_view configurationContent)
	: m_configuredActions(parseActions(configurationContent))
{
}

std::vector<const process::FieldDescriptor*> OutputConfigurationParser::getOutputFields(
	const std::vector<process::FieldDescriptor>& availableFields) const
{
	return FieldMap(availableFields).applyActions(m_configuredActions);
}

} // namespace ipxp
