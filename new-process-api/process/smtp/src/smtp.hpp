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

#include "smtpData.hpp"
#include "smtpFields.hpp"

namespace ipxp {

class SMTPPlugin : public ProcessPlugin {
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
	 * Constructs `SMTPData` in `pluginContext` and initializes it with
	 * parsed SMTP values.
	 * Skip consequent packets if SMTP parsing fails.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts parsed SMTP values into `SMTPData` from `pluginContext`.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `SMTPData`.
	 * @return Result of the update.
	 */
	PluginUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `SMTPData` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `SMTPData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides memory layout information for `SMTPData`.
	 *
	 * Returns the size and alignment requirements of `SMTPData`.
	 *
	 * @return Memory layout details for `SMTPData`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

	private:
	constexpr
	bool parseResponse(std::string_view payload, SMTPData& pluginData, FlowRecord& flowRecord) noexcept;
	
	constexpr
	bool parseCommand(std::string_view payload, SMTPData& pluginData, FlowRecord& flowRecord) noexcept;

	constexpr PluginUpdateResult updateSMTPData(
	std::span<const std::byte> payload, const uint16_t srcPort, const uint16_t dstPort, SMTPData& pluginData, FlowRecord& flowRecord) noexcept;

	FieldHandlers<SMTPFields> m_fieldHandlers;
};

} // namespace ipxp
