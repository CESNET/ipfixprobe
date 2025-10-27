/**
 * @file
 * @brief Plugin for parsing icmp traffic.
 * @author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that extracts ICMP typecode from packets,
 * stores them in per-flow plugin data, and exposes fields via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "icmpFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::icmp {

/**
 * @class ICMPPlugin
 * @brief A plugin for parsing ICMP traffic and exporting typecodes.
 */
class ICMPPlugin : public ProcessPluginCRTP<ICMPPlugin> {
public:
	/**
	 * @brief Constructs the ICMP plugin.
	 *
	 * @param parameters Plugin parameters as a string (currently unused).
	 * @param fieldManager Reference to the FieldManager for field registration.
	 */
	ICMPPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `ICMPContext` in `pluginContext` and sets typecode if flow is ICMP and parsed
	 * successfully.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Cleans up and destroys `ICMPContext`.
	 * @param pluginContext Pointer to `ICMPContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides the memory layout of `ICMPContext`.
	 * @return Memory layout description for the plugin data.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<ICMPFields> m_fieldHandlers;
};

} // namespace ipxp::process::icmp
