/**
 * @file
 * @brief Plugin for parsing basicplus traffic.
 * @author Jakub Antonín Štigler xstigl00@xstigl00@stud.fit.vut.cz
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Provides a plugin that parses VLAN traffic,
 * stores it in per-flow plugin data, and exposes that field via FieldManager.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "vlanFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp::process::vlan {

/**
 * @class VLANPlugin
 * @brief A plugin for parsing VLAN traffic.
 *
 * Collects and exports VLAN ID.
 */
class VLANPlugin : public ProcessPluginCRTP<VLANPlugin> {
public:
	/**
	 * @brief Constructs the VLAN plugin and initializes field handlers.
	 * @param params String with plugin-specific parameters for configuration(currently unused).
	 * @param manager Reference to the FieldManager for field handler registration.
	 */
	VLANPlugin(const std::string& params, FieldManager& manager);

	/**
	 * @brief Initializes plugin data for a new flow.
	 *
	 * Constructs `VLANExport` in `pluginContext` and sets VLAN value.
	 *
	 * 0 VLAN value means no VLAN tag present.
	 *
	 * @param flowContext Contextual information about the flow to fill new record.
	 * @param pluginContext Pointer to pre-allocated memory to create record.
	 * @return Result of the initialization process.
	 */
	OnInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `VLANContext` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `VLANContext`.
	 */
	void onDestroy(void* pluginContext) noexcept override;

	/**
	 * @brief Provides memory layout information for `VLANContext`.
	 *
	 * Returns the size and alignment requirements of `VLANContext`.
	 *
	 * @return Memory layout details for `VLANContext`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<VLANFields> m_fieldHandlers;
};

} // namespace ipxp::process::vlan
