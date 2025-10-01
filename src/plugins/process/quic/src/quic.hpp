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
#include "quicParser.hpp"

namespace ipxp {

/**
 * @class QUICPlugin
 * @brief A plugin for parsing QUIC traffic and exporting various QUIC fields.
 *
 * Collects connection ids, token, server port, server name, user agent, used versions etc.
 *
 * @note All seen TLS payloads can be saved.
 */
class QUICPlugin : public ProcessPlugin {
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
	 * Constructs `QUICData` in `pluginContext` and fills it with parsed QUIC values.
	 * Removes plugin if QUIC parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Update `QUICData` with QUIC parsed values.
	 * Removes plugin if QUIC parsing fails.
	 * 
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `QUICData`.
	 * @return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `QUICData`.
	 * @param pluginContext Pointer to `QUICData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides the memory layout of `QUICData`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	PluginUpdateResult parseQUIC(
		FlowRecord& flowRecord, 
		const QUICParser& quicParser,
		Direction packetDirection,
		QUICData& pluginData
	) noexcept;
	/*PluginUpdateResult parseQUIC(
		FlowRecord& flowRecord, 
		std::span<const std::byte> payload,
		Direction packetDirection,
		QUICData& pluginData
	) noexcept;*/

	constexpr
	void tryToSetOCCIDandSCID(
		const QUICDirection quicDirection,
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId,
		QUICData& pluginData
	) noexcept;

	void processInitial(
		const std::optional<QUICDirection> quicDirection,
		const Direction flowDirection,
		const QUICHeaderView& headerView,
		const QUICInitialHeaderView& initialHeaderView,
		QUICData& pluginData
	) noexcept;

	constexpr
	bool setConnectionIds(
		const std::optional<QUICDirection> quicDirection,
		const Direction flowDirection,
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId,
		QUICData& pluginData
	) noexcept;

	constexpr
	void parseRetry(
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId,
		QUICData& pluginData
	) noexcept;

	FieldHandlers<QUICFields> m_fieldHandlers;
};

} // namespace ipxp
