/**
 * @file
 * @brief Plugin for parsing dnssd traffic.
 * @author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts DNS-SD data from packets,
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

#include "dnssdData.hpp"
#include "dnssdFields.hpp"
#include "serviceFilter.hpp"

namespace ipxp {

/**
 * @class DNSSDPlugin
 * @brief A plugin for processing DNS-SD packets.
 */
class DNSSDPlugin : public ProcessPlugin {
public:

	/**
	 * @brief Constructs the DNSSD plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	DNSSDPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `DNSSDData` in `pluginContext` and initializes it with
	 * parsed DNSSD data.
	 * Discards consequent traffic if neither source nor destination port is 5353.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts newly parsed DNSSD data into `DNSSDData`.
	 * Discard consequent traffic if failed to parse.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `DNSSDData`.
	 * @return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data.
	 *
	 * Concatenates DNSSD records into a request and response strings.
	 *
	 * @param flowRecord The flow record containing flow data.
	 * @param pluginContext Pointer to `DNSSDData`.
	 * @return RemovePlugin if no requests were stored, else no action is required.
	 */
	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `DNSSDData`.
	 * @param pluginContext Pointer to `DNSSDData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `DNSSDData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool parseDNSSD(
		std::span<const std::byte> payload, 
		const bool isDNSoverTCP,
		DNSSDData& pluginData) noexcept;
	bool parseAnswer(const DNSRecord& answer, DNSSDData& pluginData) noexcept;

	//std::optional<std::string> m_configFilename;
	FieldHandlers<DNSSDFields> m_fieldHandlers;
	std::optional<ServiceFilter> m_serviceFilter;
};

} // namespace ipxp
