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

#include "wireguardData.hpp"
#include "wireguardFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp {

class WireguardPlugin : public ProcessPlugin {
public:
	/**
	 * @brief Constructs the Wireguard plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	WireguardPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `WireguardExport` in `pluginContext` and makes first transition.
	 * Removes plugin if Wireguard parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Parses Wireguard and make consequent transitions in `WireguardData`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `WireguardData`.
	 * @return Result of the update, may not require new packets if the packet storage is full.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `WireguardData` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `WireguardData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides memory layout information for `WireguardData`.
	 *
	 * Returns the size and alignment requirements of `WireguardData`.
	 *
	 * @return Memory layout details for `WireguardData`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	PluginUpdateResult parseWireguard(
		std::span<const std::byte> payload,
		const Direction direction,
		WireguardData& pluginData,
		FlowRecord& flowRecord) noexcept;

	FieldHandlers<WireguardFields> m_fieldHandlers;
};

} // namespace ipxp
