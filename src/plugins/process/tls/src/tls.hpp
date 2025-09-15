/**
 * @file
 * @brief Plugin for enriching flows for tls data.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>
#include <span>

#include <processPlugin.hpp>
#include <fieldManager.hpp>
#include <tlsParser/tlsParser.hpp>
#include <fieldHandlersEnum.hpp>

#include "tlsData.hpp"
#include "tlsFields.hpp"

namespace ipxp {

/**
 * \brief Flow cache plugin for parsing TLs packets.
 */
class TLSPlugin : public ProcessPlugin {
public:

	/**
	 * \brief Constructs the TLS plugin and initializes field handlers.
	 * \param params String with plugin-specific parameters for configuration(currently unused).
	 * \param manager Reference to the FieldManager for field handler registration.
	 */
	TLSPlugin(const std::string& params, FieldManager& manager);

	/**
	 * \brief Initializes plugin data for a new flow.
	 *
	 * Constructs `TLSData` in `pluginContext` and initializes it with parsed TLS values.
	 *
	 * \param flowContext Contextual information about the flow to fill new record.
	 * \param pluginContext Pointer to pre-allocated memory to create record.
	 * \return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * \brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed TLS values into `TLSData` from `pluginContext`.
	 *
	 * \param flowContext Contextual information about the flow to be updated.
	 * \param pluginContext Pointer to `TLSData`.
	 * \return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * \brief Destroys plugin data.
	 *
	 * Calls the destructor of `TLSData` in `pluginContext`.
	 *
	 * \param pluginContext Pointer to `TLSData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * \brief Provides memory layout information for `TLSData`.
	 *
	 * \return Size and alignment requirements for `TLSData`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr bool parseTLS(
		std::span<const std::byte> payload, const uint8_t l4Protocol, TLSData& pluginData, FlowRecord& flowRecord) noexcept;
	
	void saveJA3(const TLSParser& parser, TLSData& pluginData, FlowRecord& flowRecord) noexcept;

	void saveJA4(const TLSParser& parser, const uint8_t l4Protocol, TLSData& pluginData, FlowRecord& flowRecord) noexcept;

	bool parseClientHelloExtensions(TLSParser& parser, TLSData& pluginData, FlowRecord& flowRecord) noexcept;

	bool parseServerHelloExtensions(TLSParser& parser, TLSData& pluginData, FlowRecord& flowRecord) noexcept;

	FieldHandlers<TLSFields> m_fieldHandlers;
};

} // namespace ipxp
