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

#include "dnssdContext.hpp"
#include "dnssdFields.hpp"
#include "serviceFilter.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::dnssd {

/**
 * @class DNSSDPlugin
 * @brief A plugin for processing DNS-SD packets.
 */
class DNSSDPlugin : public ProcessPluginCRTP<DNSSDPlugin> {
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
	 * Constructs `DNSSDContext` in `pluginContext` and initializes it with
	 * parsed DNSSD data.
	 * Discards consequent traffic if neither source nor destination port is 5353.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts newly parsed DNSSD data into `DNSSDContext`.
	 * Discard consequent traffic if failed to parse.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `DNSSDContext`.
	 * @return Result of the update.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data.
	 *
	 * Concatenates DNSSD records into a request and response strings.
	 *
	 * @param flowRecord The flow record containing flow data.
	 * @param pluginContext Pointer to `DNSSDContext`.
	 * @return RemovePlugin if no requests were stored, else no action is required.
	 */
	OnExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `DNSSDContext`.
	 * @param pluginContext Pointer to `DNSSDContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `DNSSDContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool parseDNSSD(
		std::span<const std::byte> payload,
		const bool isDNSoverTCP,
		DNSSDContext& dnssdContext) noexcept;
	bool parseAnswer(const DNSRecord& answer, DNSSDContext& dnssdContext) noexcept;

	// std::optional<std::string> m_configFilename;
	FieldHandlers<DNSSDFields> m_fieldHandlers;
	std::optional<ServiceFilter> m_serviceFilter;
};

} // namespace ipxp::process::dnssd
