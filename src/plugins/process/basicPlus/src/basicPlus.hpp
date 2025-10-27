/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts basic IP and TCP fields from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "basicPlusContext.hpp"
#include "basicPlusFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::basicPlus {

/**
 * @class BasicPlusPlugin
 * @brief A plugin for collecting basic statistics about the flow: IP TTL, flags, TCP window,
 * options, MSS and SYN length.
 */
class BasicPlusPlugin : public ProcessPluginCRTP<BasicPlusPlugin> {
public:
	/**
	 * @brief Constructs the BasicPlus plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	BasicPlusPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `BasicPlusContext` in `pluginContext` and initializes it with
	 * the first packet's IP TTL and flags. If flow is TCP also adds MSS, options
	 * and window. If TCP SYN packet, also adds SYN length.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Updates `BasicPlusContext` to obtain minimum IP TTL and TCP options cumulative
	 * from `pluginContext`. Also updates same fields as `onInit` from reverse direction.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `BasicPlusContext`.
	 * @return Result of the update, may not require new packets if both directions are observed.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `BasicPlusContext`.
	 * @param pluginContext Pointer to `BasicPlusContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `BasicPlusContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	void extractInitialData(
		const FlowContext& flowContext,
		BasicPlusContext& basicPlusContext,
		const uint8_t ttl) noexcept;

	void updateReverseDirectionData(
		const FlowContext& flowContext,
		BasicPlusContext& basicPlusContext,
		uint8_t ttl,
		const amon::layers::TCPView& tcp,
		const std::optional<TCPOptions>& tcpOptions) noexcept;

	FieldHandlers<BasicPlusFields> m_fieldHandlers;
};

} // namespace ipxp::process::basicPlus
