/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts DNS fields from packets,
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

#include "dnsFields.hpp"
#include "dnsData.hpp"

namespace ipxp {

/**
 * @class DNSPlugin
 * @brief A plugin for parsing DNS traffic. Obtains DNS ID, number of answers, response code, 
 * first question name, type and class, UDP payload size and DNSSEC OK bit.
 */
class DNSPlugin : public ProcessPlugin {
public:
	
	/**
	 * @brief Constructs the DNS plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	DNSPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `DNSData` in `pluginContext` and tries to parse DNS data. 
	 * Discards consequent traffic if neither source nor destination port is 53.
	 * Immediately flushes the flow if parsing was successful.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Parses DNS and updates `DNSData` with parsed values.
	 * Flushes the flow if parsing was successful.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `DNSData`.
	 * @return Flush if parsed successfully, otherwise requires more packets.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `DNSData`.
	 * @param pluginContext Pointer to `DNSData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `DNSData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:

	constexpr bool parseDNS(
	std::span<const std::byte> payload, const bool isDNSOverTCP, FlowRecord& flowRecord, DNSData& pluginData) noexcept;

	FieldHandlers<DNSFields> m_fieldHandlers;
};

} // namespace ipxp
