/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief ICMP plugin for FlowRecord processing.
 *
 * Provides a plugin that extracts ICMP type and code from IPv4 and IPv6 packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "fieldHandlersEnum.hpp"
#include "fieldManager.hpp"
#include "packet.hpp"
#include "processPlugin.hpp"

#include <cstdint>
#include <string>

namespace ipxp {

/**
 * @struct IcmpPluginData
 * @brief Stores ICMP-specific data for a flow.
 *
 * This structure is used as the per-flow plugin context for ICMP packets.
 */
struct IcmpPluginData {
	uint8_t type; /**< ICMP type field from the packet */
	uint8_t code; /**< ICMP code field from the packet */
};

/**
 * @enum IcmpFields
 * @brief Enumerates the fields exported by the ICMP plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class IcmpFields : uint8_t {
	ICMP_TYPE = 0,
	ICMP_CODE,
	ICMP_TYPE_CODE,
	FIELDS_SIZE,
};

/**
 * @class IcmpPlugin
 * @brief Plugin for extracting ICMP packet information into FlowRecords.
 *
 * This plugin extracts ICMP type and code from packet.
 */
class IcmpPlugin : public ProcessPlugin {
public:
	/**
	 * @brief Constructs the ICMP plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	IcmpPlugin(const std::string& parameters, FieldManager& fieldManager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `IcmpPluginData` in `pluginContext` if the packet is ICMP,
	 * extracts type and code, and returns the plugin state.
	 *
	 * @param flowContext Flow processing context.
	 * @param pluginContext Pointer to pre-allocated plugin data memory.
	 * @return PluginInitResult containing initialization results.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Called when a flow is being destroyed.
	 *
	 * Cleans up plugin context using proper destruction.
	 *
	 * @param pluginContext Pointer to memory containing per-flow plugin data.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Returns memory layout requirements for the plugin's data.
	 *
	 * Used by the framework to allocate per-flow plugin storage.
	 *
	 * @return PluginDataMemoryLayout containing size and alignment.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void parseIcmp(const FlowRecord& flowRecord, const Packet& packet, IcmpPluginData& pluginData);

	FieldHandlers<IcmpFields> m_fieldHandlers;
};

} // namespace ipxp
