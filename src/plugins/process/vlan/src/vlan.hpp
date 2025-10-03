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

#include "vlanFields.hpp"

#include <sstream>
#include <string>

#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <processPlugin.hpp>

namespace ipxp {

class VLANPlugin : public ProcessPlugin {
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
	PluginInitResult onInit(const FlowContext& flowContext, void* pluginContext) override;

	/**
	 * @brief Destroys plugin data.
	 *
	 * Calls the destructor of `VLANData` in `pluginContext`.
	 *
	 * @param pluginContext Pointer to `VLANData`.
	 */
	void onDestroy(void* pluginContext) override;

	/**
	 * @brief Provides memory layout information for `VLANData`.
	 *
	 * Returns the size and alignment requirements of `VLANData`.
	 *
	 * @return Memory layout details for `VLANData`.
	 */
	PluginDataMemoryLayout getDataMemoryLayout() const noexcept override;

private:
	FieldHandlers<VLANFields> m_fieldHandlers;
};

} // namespace ipxp
