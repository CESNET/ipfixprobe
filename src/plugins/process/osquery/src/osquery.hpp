/**
 * @file
 * @brief Plugin for parsing osquery traffic.
 * @author Anton Aheyeu aheyeant@fit.cvut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that queries OS to obtain info about flows,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "osqueryFields.hpp"
#include "osqueryRequestManager.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::osquery {

/**
 * @class OSQueryPlugin
 * @brief A plugin for querying OS and flow information.
 */
class OSQueryPlugin : public ProcessPlugin {
public:
	/**
	 * @brief Constructs the OSQuery plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	OSQueryPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `OSQueryContext` in `pluginContext` and fills it with information
	 * about the OS and flow.
	 * Removes plugin if failed to obtain data.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Adds OS version information to the flow record.
	 *
	 * @param flowRecord Reference to the flow record being processed.
	 * @param pluginContext Pointer to `OSQueryContext`.
	 * @return Result of the export process, always `OnExportResult::NoAction`.
	 */
	OnExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `OSQueryContext`.
	 * @param pluginContext Pointer to `OSQueryContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `OSQueryContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<OSQueryFields> m_fieldHandlers;
	OSQueryRequestManager m_requestManager;

	std::optional<JsonParser::AboutOSVersion> m_osVersionInfo;
};

} // namespace ipxp::process::osquery
