/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Common interfaces and data structures for flow-processing plugins.
 *
 * This header defines the `ProcessPlugin` base class and related types
 * that form the contract between plugins and the flow-processing framework.
 *
 * Plugins built on this interface can observe and modify flows throughout
 * their lifecycle: initialization, per-packet updates, record export,
 * and destruction. The API ensures consistent integration while allowing
 * each plugin to manage its own per-flow state and memory layout.
 */

#pragma once

#include <cstdint>

#include "packet.hpp"
#include "fieldManager.hpp"
#include "../api.hpp"

namespace ipxp {

/**
 * @brief Forward declarations for packet processing classes.
 */
class FlowRecord;
class Packet;
class PacketFeatures;

/**
 * @brief Context passed to plugin methods, containing references to flow and packet.
 *
 * This structure provides access to the current flow record, packet, and extracted packet features.
 * It is passed to plugin methods to allow them to inspect and modify flow and packet data.
 */
struct FlowContext {
	/**< Reference to the flow record being processed. */
	FlowRecord& flowRecord;
	/**< Reference to the current packet being processed. */
	Packet& packet;
	/**< Reference to extracted features of the current packet. */
	PacketFeatures& features;
};

/**
 * @brief Indicates whether a plugin was successfully constructed for a flow.
 */
enum class ConstructionState : uint8_t {
	/**< Plugin was constructed and is active for the flow. */
	Constructed = 0,
	/**< Plugin was not constructed for the flow. */
	NotConstructed,
};

/**
 * @brief Describes whether a plugin requires further updates for a flow.
 */
enum class UpdateRequirement : uint8_t {
	/**< Plugin wants to continue processing packets for the flow. */
	RequiresUpdate = 0,
	/**< Plugin does not require further updates for the flow. */
	NoUpdateNeeded,
};

/**
 * @brief Action to be taken for a flow or plugin after processing.
 */
enum class FlowAction : uint8_t {
	/**< No special action required. */
	NoAction = 0,
	/**< Flow should be flushed (exported). */
	Flush,
	/**< Plugin should be removed from the flow. */
	RemovePlugin,
};

/**
 * @brief Result of plugin initialization for a flow.
 *
 * Contains information about whether the plugin was constructed, if it requires updates,
 * and what action should be taken for the flow or plugin.
 */
struct PluginInitResult {
	/**< Indicates if the plugin was constructed for the flow. */
	ConstructionState constructionState;
	/**< Specifies if the plugin requires further updates. */
	UpdateRequirement updateRequirement;
	/**< Action to be taken for the flow or plugin after initialization. */
	FlowAction flowAction;
};

/**
 * @brief Result of plugin update for a flow.
 *
 * Contains information about whether the plugin requires further updates and what action should be
 * taken.
 */
struct PluginUpdateResult {
	/**< Specifies if the plugin requires further updates. */
	UpdateRequirement updateRequirement;
	/**< Action to be taken for the flow or plugin after update. */
	FlowAction flowAction;
};

/**
 * @brief Result of plugin export for a flow.
 *
 * Contains information about what action should be taken for the flow or plugin after export.
 */
struct PluginExportResult {
	/**< Action to be taken for the flow or plugin after export. */
	FlowAction flowAction;
};

/**
 * @brief Describes memory layout for plugin-specific data.
 *
 * This structure specifies the size and alignment requirements for memory allocated
 * for plugin-specific context data. Plugins should use this information to allocate
 * and access their per-flow state.
 */
struct PluginDataMemoryLayout {
	/**< Size in bytes required for the plugin's context data. */
	std::size_t size;
	/**< Alignment in bytes required for the plugin's context data. */
	std::size_t alignment;
};

/**
 * @brief Abstract base class for all flow-processing plugins.
 *
 * Provides a common interface for plugins that react to flow lifecycle events.
 * All custom flow-processing plugins should inherit from this class and implement its methods.
 */
class IPXP_API ProcessPlugin {
public:
	ProcessPlugin() = default;
	virtual ~ProcessPlugin() noexcept = default;

	ProcessPlugin(const ProcessPlugin&) = delete;
	ProcessPlugin& operator=(const ProcessPlugin&) = delete;
	ProcessPlugin(ProcessPlugin&&) = delete;
	ProcessPlugin& operator=(ProcessPlugin&&) = delete;

	/**
	 * @brief Called to attempt plugin construction for a flow.
	 *
	 * This method is called repeatedly for a flow until the plugin is either constructed
	 * (returns ConstructionState::Constructed) or no longer requires updates (returns
	 * UpdateRequirement::NoUpdateNeeded). If the plugin is constructed and update is required, the
	 * framework will then call onUpdate().
	 *
	 * Typical plugin lifecycle: Init → Update → Export → Destroy.
	 *
	 * @param flowContext Context containing references to the flow and packet.
	 * @param pluginContext Pointer to plugin-specific context memory.
	 * @return PluginInitResult describing construction and update requirements.
	 */
	[[nodiscard]] virtual PluginInitResult
	onInit(const FlowContext& flowContext, void* pluginContext)
		= 0;

	/**
	 * @brief Called to update plugin state for a constructed flow.
	 *
	 * This method is called for each packet of a flow after the plugin has been constructed
	 * (onInit returned ConstructionState::Constructed and RequiresUpdate). It allows the plugin
	 * to process packets and update its internal state. If the plugin no longer requires updates,
	 * it should return UpdateRequirement::NoUpdateNeeded. The method can also request actions such
	 * as flushing or removing the plugin from the flow.
	 *
	 * @param flowContext Context containing references to the flow and packet.
	 * @param pluginContext Pointer to plugin-specific context memory.
	 * @return PluginUpdateResult describing update requirements and actions.
	 */
	[[nodiscard]] virtual PluginUpdateResult
	onUpdate(const FlowContext& flowContext, void* pluginContext)
	{
		(void) flowContext;
		(void) pluginContext;
		return {
			.updateRequirement = UpdateRequirement::NoUpdateNeeded,
			.flowAction = FlowAction::NoAction,
		};
	}

	/**
	 * @brief Called to export the flow record processed by the plugin.
	 *
	 * This method is called when the flow record is being exported. It allows the plugin to
	 * perform any final processing or cleanup before the flow is exported. The plugin can also
	 * request to be removed from the flow by returning FlowAction::RemovePlugin.
	 *
	 * @param flowRecord Reference to the flow record being exported.
	 * @param pluginContext Pointer to plugin-specific context memory.
	 * @return PluginExportResult containing the flow action to be taken.
	 */
	[[nodiscard]] virtual PluginExportResult
	onExport(const FlowRecord& flowRecord, void* pluginContext)
	{
		(void) flowRecord;
		(void) pluginContext;
		return {
			.flowAction = FlowAction::NoAction,
		};
	}

	/**
	 * @brief Called when the plugin is destroyed for a flow.
	 *
	 * This method is called when the plugin is being detached from a flow and should clean up any
	 * resources. It is only called if the plugin was successfully constructed (i.e., onInit
	 * returned ConstructionState::Constructed).
	 *
	 * @param pluginContext Pointer to plugin-specific context memory.
	 */
	virtual void onDestroy(void* pluginContext) = 0;

	/**
	 * @brief Returns memory layout for plugin-specific data.
	 *
	 * This method should return the size and alignment requirements for the plugin's context data.
	 *
	 * @return PluginDataMemoryLayout structure describing memory layout.
	 */
	[[nodiscard]] virtual PluginDataMemoryLayout getDataMemoryLayout() const noexcept = 0;
};

/**
 * @brief Factory template for creating plugins.
 *
 * This template allows dynamic creation of plugin instances based on the specified
 * base class and constructor argument types.
 *
 * @tparam Base The base class for the plugin.
 * @tparam Args The argument types required for the plugin constructor.
 */
template<typename Base, typename... Args>
class IPXP_API PluginFactory;

/**
 * @brief Type alias for the ProcessPlugin factory.
 *
 * Provides a factory for creating ProcessPlugin instances using a string-based constructor.
 */
using ProcessPluginFactory = PluginFactory<ProcessPlugin, const std::string&, FieldManager&>;

} // namespace ipxp
