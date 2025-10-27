/**
 * @file
 * @brief Plugin for parsing QUIC traffic.
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses QUIC traffic and extracts various QUIC fields,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "quicContext.hpp"
#include "quicFields.hpp"
#include "quicHeaderView.hpp"
#include "quicInitialHeaderView.hpp"
#include "quicParser.hpp"
#include "quicTemporalStorage.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::quic {

/**
 * @class QUICPlugin
 * @brief A plugin for parsing QUIC traffic and exporting various QUIC fields.
 *
 * Collects connection ids, token, server port, server name, user agent, used versions etc.
 *
 * @note All seen TLS payloads can be saved.
 */
class QUICPlugin : public ProcessPluginCRTP<QUICPlugin> {
public:
	/**
	 * @brief Constructs the QUICPlugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	QUICPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `QUICContext` in `pluginContext` and fills it with parsed QUIC values.
	 * Removes plugin if QUIC parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Update `QUICContext` with QUIC parsed values.
	 * Removes plugin if QUIC parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `QUICContext`.
	 * @return Result of the update.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `QUICContext`.
	 * @param pluginContext Pointer to `QUICContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `QUICContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	OnUpdateResult parseQUIC(
		FlowRecord& flowRecord,
		const QUICParser& quicParser,
		Direction packetDirection,
		QUICContext& quicContext) noexcept;

	constexpr void tryToSetOCCIDandSCID(
		const QUICDirection quicDirection,
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId,
		QUICContext& quicContext) noexcept;

	void processInitial(
		const std::optional<QUICDirection> quicDirection,
		const Direction flowDirection,
		const QUICHeaderView& headerView,
		const QUICInitialHeaderView& initialHeaderView,
		QUICContext& quicContext) noexcept;

	constexpr bool setConnectionIds(
		const std::optional<QUICDirection> quicDirection,
		const Direction flowDirection,
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId,
		QUICContext& quicContext) noexcept;

	constexpr void parseRetry(
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId,
		QUICContext& quicContext) noexcept;

	FieldHandlers<QUICFields> m_fieldHandlers;
};

} // namespace ipxp::process::quic
