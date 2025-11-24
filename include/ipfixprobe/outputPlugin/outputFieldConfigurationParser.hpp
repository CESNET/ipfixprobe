/**
 * @file
 * @brief Declaration of OutputFieldConfigurationParser.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "../processPlugin/fieldDescriptor.hpp"

#include <vector>

namespace ipxp {

class OutputFieldParser {
public:
	static std::vector<const process::FieldDescriptor*> getOutputFields(
		const std::vector<process::FieldDescriptor>& availableFields,
		std::string_view configurationFilePath);
};

}; // namespace ipxp