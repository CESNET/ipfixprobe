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

#include "dnsContext.hpp"
#include "dnsFields.hpp"

#include <sstream>
#include <string>

#include <dnsParser/dnsQuestion.hpp>
#include <dnsParser/dnsRecord.hpp>
#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::dns {

/**
 * @class DNSPlugin
 * @brief A plugin for parsing DNS traffic. Obtains DNS ID, number of answers, response code,
 * first question name, type and class, UDP payload size and DNSSEC OK bit.
 */
class DNSPlugin : public ProcessPluginCRTP<DNSPlugin> {
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
	 * Constructs `DNSContext` in `pluginContext` and tries to parse DNS data.
	 * Discards consequent traffic if neither source nor destination port is 53.
	 * Immediately flushes the flow if parsing was successful.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Parses DNS and updates `DNSContext` with parsed values.
	 * Flushes the flow if parsing was successful.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `DNSContext`.
	 * @return Flush if parsed successfully, otherwise requires more packets.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `DNSContext`.
	 * @param pluginContext Pointer to `DNSContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `DNSContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool parseDNS(
		std::span<const std::byte> payload,
		const bool isDNSOverTCP,
		FlowRecord& flowRecord,
		DNSContext& dnsContext) noexcept;
	bool
	parseQuery(const DNSQuestion& query, FlowRecord& flowRecord, DNSContext& dnsContext) noexcept;
	bool
	parseAnswer(const DNSRecord& answer, FlowRecord& flowRecord, DNSContext& dnsContext) noexcept;
	bool parseAdditional(
		const DNSRecord& record,
		FlowRecord& flowRecord,
		DNSContext& dnsContext) noexcept;

	FieldHandlers<DNSFields> m_fieldHandlers;
};

} // namespace ipxp::process::dns
