/**
 * @file
 * @brief Plugin for parsing mpls traffic.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts MPLS top label from packets,
 * stores them in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "mplsFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::mpls {

/**
 * @class MPLSPlugin
 * @brief A plugin for parsing MPLS traffic.
 */
class MPLSPlugin : public ProcessPluginCRTP<MPLSPlugin> {
public:
	/**
	 * @brief Constructs the MPLS plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	MPLSPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `MPLSContext` in `pluginContext` and initializes it with
	 * the top label from the packet if present.
	 * Removes export data if packet does not contain MPLS label.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `MPLSContext`.
	 * @param pluginContext Pointer to `MPLSContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `MPLSContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<MPLSFields> m_fieldHandlers;
};

} // namespace ipxp::process::mpls
