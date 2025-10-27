/**
 * @file
 * @brief Plugin for parsing ssdp traffic.
 * @author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses SSDP traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ssdpContext.hpp"
#include "ssdpFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::ssdp {

class SSDPPlugin : public ProcessPluginCRTP<SSDPPlugin> {
public:
	/**
	 * @brief Constructs the SSDP plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	SSDPPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `SSDPContext` in `pluginContext` and initializes it with
	 * parsed SSDP values.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed SSDP values into `SSDPContext` from `pluginContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SSDPContext`.
	 * @return Result of the update.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up resources associated with the plugin data.
	 *
	 * Calls the destructor of `SSDPContext` to free any allocated resources.
	 *
	 * @param pluginContext Pointer to `SSDPContext` to be destroyed.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `SSDPContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr void
	parseSSDP(std::string_view payload, SSDPContext& ssdpContext, FlowRecord& flowRecord) noexcept;

	void parseSSDPMSearch(
		std::string_view headerFields,
		SSDPContext& ssdpContext,
		FlowRecord& flowRecord) noexcept;

	void parseSSDPNotify(
		std::string_view headerFields,
		SSDPContext& ssdpContext,
		FlowRecord& flowRecord) noexcept;

	FieldHandlers<SSDPFields> m_fieldHandlers;
};

} // namespace ipxp::process::ssdp
