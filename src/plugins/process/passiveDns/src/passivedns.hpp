/**
 * @file
 * @brief Plugin for parsing DNS responses.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses DNS A, AAAA, PTR responses,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 * 
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <sstream>
#include <string>
#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "passivednsData.hpp"
#include "passivednsFields.hpp"

namespace ipxp {

/**
 * @class PassiveDNSPlugin
 * @brief A plugin for parsing DNS responses.
 */
class PassiveDNSPlugin : public ProcessPlugin {
public:

	/**
	 * @brief Constructs the PassiveDNS plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	PassiveDNSPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Removes plugin if neither source nor destination port is 53.
	 * Constructs `PassiveDNSData` in `pluginContext`.
	 * Tries to parse DNS if its a response and updates `PassiveDNSData` with parsed values.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Parses DNS responses to fill `PassiveDNSData`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `PassiveDNSData`.
	 * @return Result of the update, may not require new packets if burst storage is full.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `PassiveDNSData`.
	 * @param pluginContext Pointer to `PassiveDNSData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `PassiveDNSData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void parseDNS(
		std::span<const std::byte> payload,
		FlowRecord& flowRecord,
		const uint8_t l4Protocol,
		PassiveDNSData& pluginData) noexcept;

	FieldHandlers<PassiveDNSFields> m_fieldHandlers;
};

} // namespace ipxp
