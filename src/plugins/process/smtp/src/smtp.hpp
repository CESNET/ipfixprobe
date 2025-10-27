/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts SMTP fields from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "smtpContext.hpp"
#include "smtpFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::smtp {

/**
 * @class SMTPPlugin
 * @brief A plugin for parsing SMTP traffic.
 *
 * Collects and exports SMTP response codes, command flags, mail command and recipient counts,
 * mail code flags, domain, first sender, and first recipient.
 */
class SMTPPlugin : public ProcessPluginCRTP<SMTPPlugin> {
public:
	/**
	 * @brief Constructs the SMTP plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	SMTPPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `SMTPContext` in `pluginContext` and initializes it with
	 * parsed SMTP values.
	 * Skip consequent packets if SMTP parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed SMTP values into `SMTPContext` from `pluginContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SMTPContext`.
	 * @return Result of the update.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `SMTPContext` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `SMTPContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides memory layout information for `SMTPContext`.
	 *
	 * Returns the size and alignment requirements of `SMTPContext`.
	 *
	 * @return Memory layout details for `SMTPContext`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	constexpr bool parseResponse(
		std::string_view payload,
		SMTPContext& smtpContext,
		FlowRecord& flowRecord) noexcept;

	constexpr bool parseCommand(
		std::string_view payload,
		SMTPContext& smtpContext,
		FlowRecord& flowRecord) noexcept;

	constexpr OnUpdateResult updateSMTPData(
		std::span<const std::byte> payload,
		const uint16_t srcPort,
		const uint16_t dstPort,
		SMTPContext& smtpContext,
		FlowRecord& flowRecord) noexcept;

	FieldHandlers<SMTPFields> m_fieldHandlers;
};

} // namespace ipxp::process::smtp
