/**
 * @file
 * @brief Declaration of OutputOptionsParser.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "../options.hpp"
#include "../processPlugin/fieldManager.hpp"
#include "outputConfigurationParser.hpp"

#include <fstream>

namespace ipxp {

/**
 * @class OutputOptionsParser
 * @brief Parses and holds output plugin options.
 */
struct OutputOptionsParser : public OptionsParser {
public:
	/**
	 * @enum ExportMode
	 * @brief An export mode that determines how data is exported.
	 */
	enum class ExportMode : uint8_t { BIFLOW, UNIFLOW };

	OutputOptionsParser(const std::string& name, const std::string& description)
		: OptionsParser(name, description)
	{
		register_option(
			"c",
			"configuration",
			"TEXT",
			"Configuration string for the output plugin.",
			[this](const char* arg) {
				if (outputFieldConfigParser.has_value()) {
					throw std::invalid_argument(
						"Output field configuration already set via another option.");
				}
				outputFieldConfigParser.emplace(arg);
				return true;
			},
			OptionFlags::OptionalArgument);

		register_option(
			"cf",
			"configuration-file",
			"FILE",
			"Configuration file for the output plugin.",
			[this](const char* arg) {
				if (outputFieldConfigParser.has_value()) {
					throw std::invalid_argument(
						"Output field configuration already set via another option.");
				}

				std::ifstream configurationFile(arg);
				if (!configurationFile.is_open()) {
					throw std::invalid_argument(
						"Could not open configuration file: " + std::string(arg));
				}

				const std::string configurationContent(
					(std::istreambuf_iterator<char>(configurationFile)),
					std::istreambuf_iterator<char>());
				outputFieldConfigParser.emplace(configurationContent);
				return true;
			},
			OptionFlags::OptionalArgument);

		register_option(
			"m",
			"mode",
			"MODE",
			"Sets the export mode for the output plugin (BIFLOW or UNIFLOW).",
			[this](const char* arg) {
				std::string_view mode(arg);
				if (mode == "biflow" || mode == "BIFLOW" || mode == "b") {
					exportMode = ExportMode::BIFLOW;
				} else if (mode == "uniflow" || mode == "UNIFLOW" || mode == "u") {
					exportMode = ExportMode::UNIFLOW;
				} else {
					throw std::invalid_argument(
						"Invalid export mode: " + std::string(arg)
						+ ". Valid options are BIFLOW/biflow/b or UNIFLOW/uniflow/u.");
				}
				return true;
			},
			OptionFlags::OptionalArgument);
	}

	virtual ~OutputOptionsParser() = default;

	std::pair<
		std::vector<const process::FieldDescriptor*>,
		std::vector<const process::FieldDescriptor*>>
	getOutputFields(const process::FieldManager& fieldManager) const
	{
		std::vector<const process::FieldDescriptor*> forwardFields;
		std::vector<const process::FieldDescriptor*> reverseFields;
		const OutputConfigurationParser& outputConfigurationParser
			= outputFieldConfigParser.has_value() ? *outputFieldConfigParser
												  : OutputConfigurationParser("");

		if (exportMode == OutputOptionsParser::ExportMode::UNIFLOW) {
			forwardFields
				= outputConfigurationParser.getOutputFields(fieldManager.getUniflowForwardFields());
			reverseFields
				= outputConfigurationParser.getOutputFields(fieldManager.getUniflowReverseFields());
		} else {
			forwardFields
				= outputConfigurationParser.getOutputFields(fieldManager.getBiflowFields());
			reverseFields
				= outputConfigurationParser.getOutputFields(fieldManager.getReverseBiflowFields());
		}

		// Should never happen
		if (forwardFields.size() != reverseFields.size()) {
			throw std::runtime_error(
				"Number of forward and reverse output fields must be the same.");
		}
		return {forwardFields, reverseFields};
	}

	std::optional<OutputConfigurationParser> outputFieldConfigParser;
	ExportMode exportMode = ExportMode::BIFLOW;
};

} // namespace ipxp