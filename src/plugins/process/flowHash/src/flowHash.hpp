/**
 * @file
 * @brief Plugin for processing flow_hash value.
 * @author Jakub Antonín Štigler xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts hashes of flows,
 * stores them in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "flowHashFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::flowHash {

/**
 * @class FlowHashPlugin
 * @brief A plugin for exporting flow hash values.
 */
class FlowHashPlugin : public ProcessPluginCRTP<FlowHashPlugin> {
public:
	/**
	 * @brief Constructs the FlowHashPlugin plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	FlowHashPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `FlowHashContext` in `pluginContext` and initializes it with
	 * flow hash value from the flow context.
	 * Requires only one packet to obtain the flow hash.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `FlowHashContext`.
	 * @param pluginContext Pointer to `FlowHashContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `FlowHashContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<FlowHashFields> m_fieldHandlers;
};

} // namespace ipxp::process::flowHash
