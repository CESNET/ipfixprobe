/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <sstream>
#include <string>

#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "basicPlusData.hpp"
#include "basicPlusFields.hpp"

namespace ipxp {

/**
 * @class BasicPlusPlugin
 * @brief A plugin for collecting basic statistics about the flow: IP TTL, flags, TCP window, options, MSS and SYN length.
 *
 * @note Duplicate and empty packets can be optionally skipped.
 */
class BasicPlusPlugin : public ProcessPlugin {
public:
	/**
	 * @brief Constructs the BasicPlus plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	BasicPlusPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `BasicPlusData` in `pluginContext` and initializes it with
	 * the first packet's IP TTL and flags. If flow is TCP also adds MSS, options
	 * and window. If TCP SYN packet, also adds SYN length.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `BasicPlusData` to obtain minimum IP TTL and TCP options cumulative
	 * from `pluginContext`. Also updates same fields as `onInit` from reverse direction.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `BasicPlusData`.
	 * @return Result of the update, may not require new packets if both directions are observed.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `BasicPlusData`.
	 * @param pluginContext Pointer to `BasicPlusData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `BasicPlusData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<BasicPlusFields> m_fieldHandlers;
};

} // namespace ipxp
