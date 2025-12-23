/**
 * @file
 * @brief Declaration of OutputPlugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "../api.hpp"
#include "../processPlugin/fieldManager.hpp"
#include "flowRecord.hpp"
#include "outputOptionsParser.hpp"
#include "outputStats.hpp"
#include "processPluginEntry.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ipxp {

/**
 * @class OutputPlugin
 * @brief Base class for output plugins.
 *
 * Provides an interface for output plugins to process flow records and manage output fields.
 */
class IPXP_API OutputPlugin {
public:
	OutputPlugin(const process::FieldManager& manager, const OutputOptionsParser& optionsParser)
		: m_fieldManager(manager)
	{
		std::tie(m_forwardFields, m_reverseFields) = optionsParser.getOutputFields(manager);
	}

	/**
	 * @brief Processes a flow record for output.
	 * @param flowRecord The flow record to be processed.
	 */
	virtual void processRecord(const FlowRecord& flowRecord) = 0;

	/**
	 * @brief Retrieves the current output statistics.
	 * @return Output statistics.
	 */
	const OutputStats& getStats() const noexcept { return m_stats; }

	/**
	 * @brief Sends a signal to stop exporting data and finalize output.
	 */
	virtual void terminateExport() noexcept = 0;

	/**
	 * @brief Virtual destructor.
	 */
	virtual ~OutputPlugin() = default;

protected:
	/**
	 * @brief Sets the output fields based on the provided options parser.
	 * @param optionsParser The output options parser containing configuration.
	 */
	void setOutputFields(const OutputOptionsParser& optionsParser) {}

	const std::vector<const process::FieldDescriptor*>& getForwardFields() const noexcept
	{
		return m_forwardFields;
	}

	const std::vector<const process::FieldDescriptor*>& getReverseFields() const noexcept
	{
		return m_reverseFields;
	}

	OutputStats m_stats;

private:
	const process::FieldManager& m_fieldManager;
	std::vector<const process::FieldDescriptor*> m_forwardFields;
	std::vector<const process::FieldDescriptor*> m_reverseFields;
};

template<typename Base, typename... Args>
class IPXP_API PluginFactory;

/**
 * @brief Type alias for the OutputPlugin factory.
 *
 * Provides a factory for creating OutputPlugin instances using a string-based constructor.
 */
using OutputPluginFactory = PluginFactory<
	OutputPlugin,
	const std::string&,
	const process::FieldManager&,
	const std::vector<process::ProcessPluginEntry>&>;

} // namespace ipxp
