/**
 * @file
 * @brief Plugin for enriching flows for tls data.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Andrej Lukacovic lukacan1@fit.cvut.cz
 * @author Jonas Mücke <jonas.muecke@tu-dresden.de>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 *
 * Provides a plugin that parses TLS traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "tlsContext.hpp"
#include "tlsFields.hpp"

#include <span>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>
#include <tlsParser/tlsParser.hpp>

namespace ipxp::process::tls {

/**
 * \brief Flow cache plugin for parsing TLS packets.
 */
class TLSPlugin : public ProcessPluginCRTP<TLSPlugin> {
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
	 * Constructs `TLSContext` in `pluginContext` and initializes it with parsed TLS values.
	 *
	 * \param flowContext Contextual information about the flow to fill new record.
	 * \param pluginContext Pointer to pre-allocated memory to create record.
	 * \return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * \brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed TLS values into `TLSContext` from `pluginContext`.
	 *
	 * \param flowContext Contextual information about the flow to be updated.
	 * \param pluginContext Pointer to `TLSContext`.
	 * \return Result of the update.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * \brief Destroys plugin data.
	 *
	 * Calls the destructor of `TLSContext` in `pluginContext`.
	 *
	 * \param pluginContext Pointer to `TLSContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * \brief Provides memory layout information for `TLSContext`.
	 *
	 * \return Size and alignment requirements for `TLSContext`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool parseTLS(
		std::span<const std::byte> payload,
		const uint8_t l4Protocol,
		TLSContext& tlsContext,
		FlowRecord& flowRecord) noexcept;

	void saveJA3(const TLSParser& parser, TLSContext& tlsContext, FlowRecord& flowRecord) noexcept;

	void saveJA4(
		const TLSParser& parser,
		const uint8_t l4Protocol,
		TLSContext& tlsContext,
		FlowRecord& flowRecord) noexcept;

	bool parseClientHelloExtensions(
		TLSParser& parser,
		TLSContext& tlsContext,
		FlowRecord& flowRecord) noexcept;

	bool parseServerHelloExtensions(
		TLSParser& parser,
		TLSContext& tlsContext,
		FlowRecord& flowRecord) noexcept;

	FieldHandlers<TLSFields> m_fieldHandlers;
};

} // namespace ipxp::process::tls
