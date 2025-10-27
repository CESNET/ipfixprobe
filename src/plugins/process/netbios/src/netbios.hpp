/**
 * @file
 * @brief Plugin for parsing netbios traffic.
 * @author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Provides a plugin that extracts NetBIOS suffix and name from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "netbiosContext.hpp"
#include "netbiosFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::netbios {

/**
 * @class NetBIOSPlugin
 * @brief A plugin for parsing NetBIOS traffic.
 */
class NetBIOSPlugin : public ProcessPluginCRTP<NetBIOSPlugin> {
public:
	/**
	 * @brief Constructs the NetBIOS plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	NetBIOSPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `NetBIOSContext` in `pluginContext` and initializes it with
	 * data from the packet.
	 * Removes plugin if neither source nor destination port is 137 or parsing failed.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `NetBIOSContext`.
	 * @param pluginContext Pointer to `NetBIOSContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `NetBIOSContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void parseNetBIOS(
		FlowRecord& flowRecord,
		std::span<const std::byte> payload,
		NetBIOSContext& netbiosContext) noexcept;

	FieldHandlers<NetBIOSFields> m_fieldHandlers;
};

} // namespace ipxp::process::netbios
