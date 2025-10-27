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

#include "passivednsContext.hpp"
#include "passivednsFields.hpp"

#include <sstream>
#include <string>

#include <dnsParser/dnsRecord.hpp>
#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::passivedns {

/**
 * @class PassiveDNSPlugin
 * @brief A plugin for parsing DNS responses.
 */
class PassiveDNSPlugin : public ProcessPluginCRTP<PassiveDNSPlugin> {
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
	 * Constructs `PassiveDNSContext` in `pluginContext`.
	 * Tries to parse DNS if its a response and updates `PassiveDNSContext` with parsed values.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Parses DNS responses to fill `PassiveDNSContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `PassiveDNSContext`.
	 * @return Result of the update, may not require new packets if burst storage is full.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `PassiveDNSContext`.
	 * @param pluginContext Pointer to `PassiveDNSContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `PassiveDNSContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void parseDNS(
		std::span<const std::byte> payload,
		FlowRecord& flowRecord,
		const uint8_t l4Protocol,
		PassiveDNSContext& passiveDNSContext) noexcept;
	bool parseAnswer(
		const DNSRecord& record,
		FlowRecord& flowRecord,
		PassiveDNSContext& passiveDNSContext) noexcept;

	FieldHandlers<PassiveDNSFields> m_fieldHandlers;
};

} // namespace ipxp::process::passivedns
