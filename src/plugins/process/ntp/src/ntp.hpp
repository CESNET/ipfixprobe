/**
 * @file
 * @brief Plugin for parsing ntp traffic.
 * @author Alejandro Robledo <robleale@fit.cvut.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses NTP packets and extracts relevant fields,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ntpContext.hpp"
#include "ntpFields.hpp"
#include "ntpHeader.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::ntp {

/**
 * @class NetworkTimePlugin
 * @brief A plugin for parsing NTP traffic.
 */
class NetworkTimePlugin : public ProcessPluginCRTP<NetworkTimePlugin> {
public:
	/**
	 * @brief Constructs the NetworkTime plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	NetworkTimePlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `NetworkTimePlugin` in `pluginContext` and initializes it
	 * with parsed NTP values of the first packet.
	 * Removes plugin data if NTP parsing fails.
	 * Immediately flushes the flow if parsed successfully.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `NetworkTimePlugin`.
	 * @param pluginContext Pointer to `NetworkTimePlugin`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `NetworkTimePlugin`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void makeAllFieldsAvailable(FlowRecord& flowRecord) noexcept;
	bool parseNTP(
		FlowRecord& flowRecord,
		std::span<const std::byte> payload,
		NetworkTimeContext& ntpContext) noexcept;

	FieldHandlers<NetworkTimeFields> m_fieldHandlers;
};

} // namespace ipxp::process::ntp
