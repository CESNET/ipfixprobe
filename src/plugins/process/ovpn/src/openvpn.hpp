/**
 * @file
 * @brief Plugin for parsing ovpn traffic.
 * @author Karel Hynek <hynekkar@fit.cvut.cz>
 * @author Martin Ctrnacty <ctrnama2@fit.cvut.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that calculates confidence level that given flow is OpenVPN,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "openvpnContext.hpp"
#include "openvpnFields.hpp"
#include "openvpnProcessingState.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::ovpn {

/**
 * @class OpenVPNPlugin
 * @brief A plugin for detecting OpenVPN traffic.
 */
class OpenVPNPlugin : public ProcessPluginCRTP<OpenVPNPlugin> {
public:
	/**
	 * @class OpenVPNPlugin
	 * @brief A plugin for parsing OpenVPN traffic.
	 */
	OpenVPNPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `OpenVPNContext` in `pluginContext` and initializes state machine
	 * to initial state.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Handles transitions in `OpenVPNContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `OpenVPNContext`.
	 * @return Result of the update, removes plugin if parsing fails.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Prepare the export data.
	 *
	 * Removes record if confidence level is too low.
	 *
	 * @param flowRecord The flow record containing aggregated flow data.
	 * @param pluginContext Pointer to `OpenVPNContext`.
	 * @return Result of the export process.
	 */
	OnExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `OpenVPNContext`.
	 * @param pluginContext Pointer to `OpenVPNContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `OpenVPNContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool updateConfidenceLevel(
		const amon::Packet& packet,
		const FlowRecord& flowRecord,
		const Direction direction,
		OpenVPNContext& openVPNContext) noexcept;

	FieldHandlers<OpenVPNFields> m_fieldHandlers;
};

} // namespace ipxp::process::ovpn
