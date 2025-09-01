/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <sstream>
#include <string>
#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <fieldHandlersEnum.hpp>

#include "quicData.hpp"
#include "quicFields.hpp"
#include "quicTemporalStorage.hpp"
#include "quicHeaderView.hpp"
#include "quicInitialHeaderView.hpp"

namespace ipxp {

class QUICPlugin : public ProcessPlugin {
public:
	QUICPlugin(const std::string& params, FieldManager& manager);

	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	PluginExportResult onExport(const FlowRecord& flowRecord, void* pluginContext) override;

	void onDestroy(void* pluginContext) override;

	std::string getName() const noexcept override;

	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	
	FlowAction parseQUIC(
		FlowRecord& flowRecord, 
		std::span<const std::byte> payload,
		Direction packetDirection
	) noexcept;

	constexpr void tryToSetOCCIDandSCID(
		const QUICDirection quicDirection,
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId
	) noexcept;

	void processInitial(
		const std::optional<QUICDirection> quicDirection,
		const Direction flowDirection,
		const QUICHeaderView& headerView,
		const QUICInitialHeaderView& initialHeaderView
	) noexcept;

	constexpr bool setConnectionIds(
		const std::optional<QUICDirection> quicDirection,
		const Direction flowDirection,
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId
	) noexcept;

	constexpr void parseRetry(
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId
	) noexcept;


	

	FieldHandlers<QUICFields> m_fieldHandlers;

};

} // namespace ipxp
