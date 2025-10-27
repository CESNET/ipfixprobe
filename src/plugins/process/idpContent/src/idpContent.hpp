/**
 * @file
 * @brief Plugin for parsing idpcontent traffic.
 * @author Karel Hynek <Karel.Hynek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that exports packet payloads as IDP content,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "idpContentContext.hpp"
#include "idpContentFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::idpContent {

/**
 * @class IDPContentPlugin
 * @brief A plugin for collecting IDP content.
 */
class IDPContentPlugin : public ProcessPluginCRTP<IDPContentPlugin> {
public:
	/**
	 * @brief Constructs the IDPContent plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	IDPContentPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `IDPContentContext` in `pluginContext` and initializes it with
	 * payload of initial packet.
	 * Requires packet from another direction to finish processing.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Updates plugin data with values from new packet.
	 *
	 * Inserts payload from reverse direction into `IDPContentContext` and finish processing.
	 *
	 * @param flowContext Contextual information about the flow to be updated.
	 * @param pluginContext Pointer to `IDPContentContext`.
	 * @return Result of the update, requires updates if packet has forward direction.
	 */
	OnUpdateResult onUpdate(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `IDPContentContext`.
	 * @param pluginContext Pointer to `IDPContentContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `IDPContentContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	bool updateContent(
		FlowRecord& flowRecord,
		const amon::Packet& packet,
		const Direction direction,
		IDPContentContext& idpContext) noexcept;

	FieldHandlers<IDPContentFields> m_fieldHandlers;
};

} // namespace ipxp::process::idpContent
