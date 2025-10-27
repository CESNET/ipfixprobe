/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Compact interface for flow processing plugins (init / update / export / destroy).
 *
 * This header defines a minimal and efficient interface for flow-processing plugins.
 * Each plugin operates on a per-flow context and may observe or modify its state
 * during various stages of the flow lifecycle.
 *
 * Lifecycle (if implemented):
 *   onInit → beforeUpdate → onUpdate → onExport → onDestroy
 *
 * Each instance corresponds to one flow, with its own memory region described
 * by `PluginDataMemoryLayout`. The framework guarantees proper construction and
 * destruction via `onInit()` and `onDestroy()`.
 *
 * Inherit from `ProcessPluginCRTP<YourPlugin>` to automatically detect which
 * optional callbacks are overridden.
 */

#pragma once

#include "directionalField.hpp"
#include "tcpOptions.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <type_traits>

#include <amon/Packet.hpp>
#include <amon/layers/IPv4.hpp>
#include <amon/layers/IPv6.hpp>
#include <amon/layers/TCP.hpp>
#include <ipfixprobe/api.hpp>

namespace ipxp::process {

struct PacketFeatures {
	// src_ip
	// dst_ip
	uint16_t srcPort;
	uint16_t dstPort;
	uint8_t l4Protocol;
};

} // namespace ipxp::process

namespace ipxp {

// Forward declarations (to avoid unnecessary dependencies)

class FlowRecord;

struct PacketContext {
	amon::Packet* packet; ///< Reference to the current packet.
	process::PacketFeatures* features; ///< Extracted packet features for plugin use.
};

/**
 * @brief Generic plugin factory for runtime construction.
 *
 * @tparam Base Base class of the plugin hierarchy.
 * @tparam Args Constructor argument types.
 *
 * The factory enables dynamic instantiation of plugins by name,
 * forwarding constructor arguments as needed.
 */
template<typename Base, typename... Args>
class IPXP_API PluginFactory;

} // namespace ipxp

namespace ipxp::process {

/** Flow record alias (shorter name inside this namespace). */
using FlowRecord = ::ipxp::FlowRecord;

/** Packet alias (shorter name inside this namespace). */
using PacketContext = ::ipxp::PacketContext;

/**
 * @brief Context passed to all processing callbacks.
 *
 * Contains references to the currently processed flow, packet,
 * and its logical direction. Used to access packet metadata
 * or update flow-level state.
 */
struct FlowContext {
	const PacketContext& packetContext; ///< Reference to the current packet context.
	Direction packetDirection; ///< Direction of the packet within the flow.
	FlowRecord& flowRecord; ///< Reference to the flow record being processed.
};

/**
 * @brief Result codes returned by onInit().
 *
 * The result determines how the framework proceeds after the plugin's
 * initialization attempt for a given flow.
 *
 * Each plugin receives a call to `onInit()` when a new flow is first observed.
 * The plugin can construct its internal context and indicate whether it should
 * continue receiving packets for this flow, wait for more data, or be ignored.
 */
enum class OnInitResult : uint8_t {
	/**
	 * @brief Plugin was successfully constructed and wants further updates.
	 *
	 * The plugin has recognized that it applies to this flow and has initialized
	 * its per-flow context. The framework will call `onUpdate()` (and optionally
	 * `beforeUpdate()`) for every subsequent packet belonging to this flow.
	 */
	ConstructedNeedsUpdate,

	/**
	 * @brief Plugin was successfully constructed but requires no further updates.
	 *
	 * The plugin has completed all necessary work during initialization and does
	 * not need to process additional packets. It will remain attached until flow
	 * export, and `onExport()` will still be invoked before removal.
	 */
	ConstructedFinal,

	/**
	 * @brief Plugin cannot decide yet and requests more packets.
	 *
	 * The plugin needs additional packets before it can confirm applicability.
	 * The framework will call `onInit()` again when more packets arrive.
	 *
	 * No per-flow memory is allocated at this stage.
	 */
	PendingConstruction,

	/**
	 * @brief Plugin is not applicable for this flow and should not be reattached.
	 *
	 * The plugin determined that it is irrelevant for the given flow (e.g., wrong
	 * protocol, port, or payload type). The framework will not attempt to attach
	 * this plugin to the same flow again.
	 */
	Irrelevant,
};

/**
 * @brief Result codes controlling behavior of the beforeUpdate() hook.
 *
 * This return value determines how the framework should proceed
 * after the plugin’s early read-only inspection of a packet.
 */
enum class BeforeUpdateResult : uint8_t {
	/**
	 * @brief Continue normal processing.
	 *
	 * The plugin did not request any special action.
	 * The framework will proceed with standard packet processing,
	 * calling `onUpdate()` and other plugins as usual.
	 */
	NoAction,

	/**
	 * @brief Export the current flow and start a new one for this packet.
	 *
	 * The plugin indicates that the current flow should be finalized and exported.
	 * The inspected packet itself is **not** included in the exported flow;
	 * instead, it will be reprocessed as the first packet of a new flow.
	 * Typical use cases include protocol transitions or flow-splitting logic.
	 */
	FlushFlowAndReinsert,

	/**
	 * @brief Remove this plugin instance immediately.
	 *
	 * The plugin is no longer relevant for this flow and should be detached.
	 * The flow itself continues processing normally with the remaining plugins.
	 */
	Remove,
};

/**
 * @brief Result codes controlling behavior of the onUpdate() hook.
 *
 * Returned by a plugin after processing a packet during normal per-flow updates.
 * These codes determine whether the plugin remains active, finalizes its state,
 * or triggers immediate flow export.
 */
enum class OnUpdateResult : uint8_t {
	/**
	 * @brief Continue updating with future packets.
	 *
	 * The plugin remains active and expects to receive more packets
	 * for this flow. Normal processing continues.
	 */
	NeedsUpdate,

	/**
	 * @brief Plugin has reached its final state.
	 *
	 * The plugin no longer requires per-packet updates but should remain
	 * attached until the flow is exported (to contribute data during export).
	 */
	Final,

	/**
	 * @brief Remove this plugin immediately.
	 *
	 * Indicates an invalid or irrelevant state (e.g., parsing error or
	 * early termination). The plugin is destroyed and detached from
	 * the flow; other plugins continue normally.
	 */
	Remove,

	/**
	 * @brief Export the entire flow immediately.
	 *
	 * The plugin requests that the framework finalize and export
	 * the current flow immediately.
	 * The current packet **is included** in the exported flow.
	 */
	FlushFlow,
};

/**
 * @brief Result codes controlling plugin behavior during flow export.
 *
 * Returned by a plugin when the flow is being finalized.
 */
enum class OnExportResult : uint8_t {
	/**
	 * @brief Perform final calculations; flow is exported normally.
	 *
	 * The plugin can update the flow record (e.g., compute averages or finalize metrics)
	 * before the framework completes the export. The plugin remains attached for this flow
	 * until the export finishes.
	 */
	NoAction,

	/**
	 * @brief Remove the plugin from the flow.
	 *
	 * The framework will call onExport(), then detach and destroy the plugin,
	 * freeing its per-flow context. Use this when the plugin should not remain
	 * attached to the flow after export.
	 */
	Remove,
};

/**
 * @brief Summary of which optional callbacks are provided by the plugin.
 *
 * Filled automatically by `ProcessPluginCRTP<Derived>`.
 */
struct ProcessPluginOverrides {
	bool hasBeforeUpdate; ///< True if Derived supplies beforeUpdate().
	bool hasOnUpdate; ///< True if Derived supplies onUpdate().
	bool hasOnExport; ///< True if Derived supplies onExport().
};

/**
 * @brief Size and alignment of the plugin's per-flow context.
 *
 * Describes memory requirements for the plugin's internal state.
 * The memory region is owned and managed by the framework.
 */
struct PluginDataMemoryLayout {
	std::size_t size; ///< Size of the per-flow context (in bytes).
	std::size_t alignment; ///< Alignment requirement (in bytes).
};

/**
 * @brief Abstract base class for flow-processing plugins.
 *
 * Defines the full plugin lifecycle and the interface plugins must implement
 * to integrate with the flow-processing framework.
 *
 * Plugin lifecycle:
 * 1. **onInit()** – Determine if the plugin wants to attach to the flow. PluginContext
 *    memory is allocated only if plugin attaches.
 * 2. **beforeUpdate()** – Optional read-only pre-update inspection, for flow control.
 * 3. **onUpdate()** – Main per-packet processing and state updates.
 * 4. **onExport()** – Optional finalization and computed metrics before export.
 * 5. **onDestroy()** – Cleanup allocated resources and plugin state.
 *
 * Notes:
 * - Optional hooks (`beforeUpdate`, `onExport`) are invoked only if implemented.
 * - `onDestroy()` is guaranteed to be called if `onInit()` successfully constructed the plugin.
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
	 * @brief Attempt plugin construction and decide applicability for a flow.
	 *
	 * Called repeatedly for incoming packets until the plugin either attaches
	 * to the flow or determines it's not applicable. Initializes plugin-specific
	 * context if constructed.
	 *
	 * Key points:
	 * - Decide if the plugin should handle the flow.
	 * - Initialize pluginContext.
	 * - Called for each packet until constructed or abandoned.
	 * - The packet triggering construction is not processed by onUpdate().
	 *
	 * Typical use cases:
	 * - Protocol detection (HTTP, DNS, TLS, etc.).
	 * - Context setup: counters, state machines, tracking structures.
	 * - Early flow filtering based on criteria.
	 *
	 * Example (HTTP plugin):
	 * 1. Packet arrives on TCP port 80/443.
	 * 2. onInit() inspects payload for HTTP headers.
	 * 3. If matched → return OnInitResult::ConstructedNeedsUpdate.
	 * 4. If uncertain → return OnInitResult::PendingConstruction.
	 * 5. If irrelevant → return OnInitResult::Irrelevant.
	 *
	 * @param flowContext Context containing references to the flow and current packet.
	 * @param pluginContext Pointer to uninitialized plugin-specific memory.
	 * @return One of OnInitResult values.
	 *
	 * @warning Must initialize pluginContext when returning Constructed*.
	 * @note Returning Irrelevant tells the framework not to reattempt attaching
	 *       this plugin to the same flow for any subsequent packets.
	 */
	[[nodiscard]] virtual OnInitResult onInit(const FlowContext& flowContext, void* pluginContext)
		= 0;

	/**
	 * @brief Read-only hook for flow control before state update.
	 *
	 * Called for each packet **before** `onUpdate()` to allow plugins to inspect
	 * the packet and decide flow-level actions (flush, split, remove) without
	 * modifying plugin state.
	 *
	 * Key points:
	 * - Read-only access to flow and plugin context; **do not modify state**.
	 * - Invoked only for flows that were constructed and requested per-packet updates
	 *   (i.e. `onInit()` returned `OnInitResult::ConstructedNeedsUpdate`).
	 * - Additionally, the framework will call this only if the plugin actually
	 *   implements `beforeUpdate()` (override detected).
	 * - Runs before statistics/state updates and before `onUpdate()` of this or other plugins.
	 *
	 * Typical use cases:
	 * - Detect packet that marks a flow boundary (e.g. new HTTP request) and request
	 *   export+reinsert.
	 * - Detect protocol-level termination (SYN) and trigger flow actions.
	 * - Decide to remove the plugin early if it becomes irrelevant.
	 *
	 * Example:
	 * 1. Packet looks like start of a new request
	 * 2. beforeUpdate() returns BeforeUpdateResult::FlushFlowAndReinsert
	 * 3. Framework exports the current flow (without this packet) and reprocesses the packet
	 *    as the first packet of a new flow
	 *
	 * @param flowContext Read-only context of the current flow and packet.
	 * @param pluginContext Read-only pointer to plugin-specific memory.
	 * @return One of BeforeUpdateResult values.
	 *
	 * @note Override only when you need flow-control logic; use `onUpdate()` to modify state.
	 */
	[[nodiscard]] virtual BeforeUpdateResult beforeUpdate(
		[[maybe_unused]] const FlowContext& flowContext,
		[[maybe_unused]] const void* pluginContext) const
	{
		throw std::logic_error("Unexpected call to Base::beforeUpdate().");
	}

	/**
	 * @brief Main per-packet processing for a constructed flow.
	 *
	 * Called for each packet after the plugin was successfully constructed and
	 * requested updates (`OnInitResult::ConstructedNeedsUpdate`). This is the
	 * primary place to update plugin state, extract features, and compute metrics.
	 *
	 * Key points:
	 * - Modify plugin context and flow state as needed.
	 * - Invoked only for flows where updates are required.
	 * - Determines whether the plugin continues receiving packets or requests removal.
	 *
	 * Common use cases:
	 * - Extract protocol fields, parse headers, track session state.
	 * - Update counters, compute averages, detect anomalies.
	 * - Decide to remove plugin early if flow becomes irrelevant.
	 *
	 * Example:
	 * 1. HTTP plugin constructed on first packet
	 * 2. onUpdate() processes subsequent HTTP packets
	 * 3. Extract metrics, update counters
	 * 4. Return NeedsUpdate to continue, Final when done, Remove to stop immediately
	 *
	 * @param flowContext Context with references to the current flow and packet.
	 * @param pluginContext Pointer to plugin-specific memory (modifiable).
	 * @return One of OnUpdateResult values indicating continuation or flow action.
	 *
	 * @note Only override this method if the plugin needs per-packet processing.
	 */
	[[nodiscard]] virtual OnUpdateResult
	onUpdate([[maybe_unused]] const FlowContext& flowContext, [[maybe_unused]] void* pluginContext)
	{
		throw std::logic_error("Unexpected call to Base::onUpdate().");
	}

	/**
	 * @brief Finalize plugin data during flow export.
	 *
	 * Called when a flow is being exported, allowing the plugin to compute
	 * final metrics, modify the flow record, and optionally request removal.
	 *
	 * Key points:
	 * - Last chance to update the flow record before export.
	 * - Compute derived fields, averages, ratios, or classifications.
	 * - Plugin may indicate it should be removed after export.
	 *
	 * **Invocation:** Only called if the derived plugin class overrides this method.
	 *
	 * Example:
	 * 1. TCP flow reaches timeout or FIN packet
	 * 2. onExport() calculates metrics like average RTT
	 * 3. Add computed fields to flow record
	 * 4. Return NoAction to stay or Remove to detach plugin
	 *
	 * @param flowRecord Read-only reference to the flow record.
	 * @param pluginContext Pointer to plugin-specific context memory.
	 * @return One of OnExportResult indicating whether the plugin remains attached.
	 */
	[[nodiscard]] virtual OnExportResult
	onExport([[maybe_unused]] const FlowRecord& flowRecord, [[maybe_unused]] void* pluginContext)
	{
		throw std::logic_error("Unexpected call to Base::onExport().");
	}

	/**
	 * @brief Cleanup callback.
	 *
	 * Called after the plugin instance is no longer needed
	 * (after successful initialization and before memory release).
	 *
	 * Must never throw exceptions.
	 *
	 * @param pluginContext Pointer to plugin-specific storage block.
	 */
	virtual void onDestroy(void* pluginContext) noexcept = 0;

	/**
	 * @brief Reports which callbacks are implemented.
	 *
	 * Used internally by the framework to determine which hooks to call.
	 */
	// TODO abstract?
	virtual ProcessPluginOverrides getOverrides() const noexcept { return {}; };

	/**
	 * @brief Reports memory requirements for per-flow plugin data.
	 *
	 * Must describe the size and alignment of the plugin's state structure.
	 */
	[[nodiscard]] virtual PluginDataMemoryLayout getDataMemoryLayout() const noexcept = 0;
};

/**
 * @brief CRTP helper for automatic override detection.
 *
 * Inherit as `ProcessPluginCRTP<Derived>` to automatically detect which callbacks
 * the derived plugin overrides (`beforeUpdate`, `onUpdate`, `onExport`) and
 * fill `ProcessPluginOverrides` accordingly.
 *
 * Example:
 * @code
 * class MyPlugin : public ProcessPluginCRTP<MyPlugin> { ... };
 * @endcode
 *
 * @note Detection is done at compile-time with no runtime overhead.
 */
template<typename Derived>
class IPXP_API ProcessPluginCRTP : public ProcessPlugin {
public:
	ProcessPluginCRTP() = default;
	virtual ~ProcessPluginCRTP() noexcept = default;

	/**
	 * @brief Returns which callbacks the derived plugin overrides.
	 *
	 * Automatically detects if the derived class provides its own implementation of
	 * `beforeUpdate()`, `onUpdate()`, and `onExport()` using compile-time CRTP checks.
	 *
	 * This information is used by the framework to decide which hooks to invoke.
	 *
	 * @return ProcessPluginOverrides flags indicating which callbacks are overridden.
	 */
	ProcessPluginOverrides getOverrides() const noexcept override final
	{
		return ProcessPluginOverrides {
			.hasBeforeUpdate = isBeforeUpdateOverridden,
			.hasOnUpdate = isOnUpdateOverridden,
			.hasOnExport = isOnExportOverridden,
		};
	}

private:
	static constexpr bool isOnExportOverridden
		= !std::is_same_v<decltype(&Derived::onExport), decltype(&ProcessPlugin::onExport)>;

	static constexpr bool isOnUpdateOverridden
		= !std::is_same_v<decltype(&Derived::onUpdate), decltype(&ProcessPlugin::onUpdate)>;

	static constexpr bool isBeforeUpdateOverridden
		= !std::is_same_v<decltype(&Derived::beforeUpdate), decltype(&ProcessPlugin::beforeUpdate)>;
};

/** Forward declaration of FieldManager class. */
class FieldManager;

constexpr std::span<const std::byte> getPayload(const amon::Packet& packet) noexcept
{
	return packet.data.subspan(
		std::get<amon::PacketLayer>(packet.layers[*packet.layout.l7]).offset);
}

template<typename ViewType>
constexpr std::optional<ViewType>
getLayerView(const amon::Packet& packet, const std::optional<uint8_t>& layer) noexcept
{
	if (!layer.has_value()) {
		return std::nullopt;
	}
	if (std::holds_alternative<amon::ErrorLayer>(packet.layers[*layer])) {
		return std::nullopt;
	}

	return packet.getLayerView<ViewType>(std::get<amon::PacketLayer>(packet.layers[*layer]));
}

constexpr inline std::optional<std::size_t> getIPPayloadLength(const amon::Packet& packet) noexcept
{
	if (auto ipv4 = getLayerView<amon::layers::IPv4View>(packet, packet.layout.l3);
		ipv4.has_value()) {
		return ipv4->totalLength() - ipv4->headerLength();
	} else if (auto ipv6 = getLayerView<amon::layers::IPv6View>(packet, packet.layout.l4);
			   ipv6.has_value()) {
		return ipv6->payloadLength();
	}

	return std::nullopt;
}

/**
 * @brief Factory type for creating `ProcessPlugin` instances.
 *
 * Used by the framework to instantiate plugins dynamically
 * using a name-based lookup and constructor arguments.
 */
using ProcessPluginFactory
	= ::ipxp::PluginFactory<ProcessPlugin, const std::string&, FieldManager&>;

} // namespace ipxp::process
