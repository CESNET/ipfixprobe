/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Plugin registration entry for the flow-processing framework.
 *
 * This header defines the ProcessPluginEntry structure used to register and manage
 * flow-processing plugins within the framework. Each entry contains plugin metadata,
 * memory requirements, activation state, and the plugin instance itself.
 *
 * The entry serves as a bridge between plugin registration and runtime execution,
 * allowing the framework to efficiently manage plugin lifecycle and resource allocation.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace ipxp::process {

class ProcessPlugin;

/**
 * @brief Plugin operational state controlling flow context allocation.
 */
enum class PluginState : uint8_t {
	/** @brief New flows will not allocate context for this plugin. */
	Disabled = 0,
	/** @brief New flows will allocate context and use this plugin. */
	Enabled,
};

/**
 * @brief Registration entry for a flow-processing plugin.
 *
 * This structure represents a complete plugin registration within the framework.
 * It combines plugin metadata, memory requirements, runtime control, and the
 * actual plugin instance into a single manageable entity.
 */
struct ProcessPluginEntry {
	/** @brief Human-readable plugin name (unique identifier). */
	std::string name;

	/** @brief Required size of the plugin's per-flow context in bytes. */
	std::size_t contextSize;

	/** @brief Required alignment for the plugin's context. */
	std::size_t contextAlignment;

	/** @brief Current state of the plugin in the framework. */
	PluginState state;

	/** @brief Shared pointer to the actual plugin implementation. */
	std::shared_ptr<ProcessPlugin> plugin;
};

} // namespace ipxp::process
