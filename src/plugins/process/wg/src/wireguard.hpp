/**
 * @file
 * @brief Plugin for parsing wg traffic.
 * @author Pavel Valach <valacpav@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses Wireguard traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "wireguardContext.hpp"
#include "wireguardFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::wireguard {

/**
 * @class WireguardPlugin
 * @brief A plugin for detecting and parsing Wireguard traffic.
 */
class WireguardPlugin : public ProcessPluginCRTP<WireguardPlugin> {
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
	 * Constructs `WireguardContext` in `pluginContext` and makes first transition.
	 * Removes plugin if Wireguard parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Parses Wireguard and make consequent transitions in `WireguardContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `WireguardContext`.
	 * @return Result of the update, may not require new packets if the packet storage is full.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	BeforeUpdateResult
	beforeUpdate(const FlowContext& flowContext, const void* pluginContext) const override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `WireguardContext` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `WireguardContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides memory layout information for `WireguardContext`.
	 *
	 * Returns the size and alignment requirements of `WireguardContext`.
	 *
	 * @return Memory layout details for `WireguardContext`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool parseWireguard(
		std::span<const std::byte> payload,
		const Direction direction,
		WireguardContext& wireguardContext,
		FlowRecord& flowRecord) noexcept;

	FieldHandlers<WireguardFields> m_fieldHandlers;
};

} // namespace ipxp::process::wireguard
