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

#include "quicExport.hpp"
#include "quicFields.hpp"
#include "quicTemporalStorage.hpp"
#include "quicHeaderView.hpp"
#include "quicInitialHeaderView.hpp"

namespace ipxp {

class QUICPlugin : public ProcessPlugin {
public:
	QUICPlugin(const std::string& params, FieldManager& manager);

	FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet) override;

	FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet) override;

	void onFlowExport(FlowRecord& flowRecord) override;

	ProcessPlugin* clone(std::byte* constructAtAddress) const override;

	const void* getExportData() const noexcept override;

	std::string getName() const override;

	~QUICPlugin() override = default;

	QUICPlugin(const QUICPlugin& other) = default;
	QUICPlugin(QUICPlugin&& other) = delete;

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

	QUICExport m_exportData;
	FieldHandlers<QUICFields> m_fieldHandlers;

	QUICTemporalStorage m_temporalCIDStorage;
	std::size_t m_retryPacketCount = 0;

	QUICExport::ConnectionId m_initialConnectionId;
};

} // namespace ipxp
