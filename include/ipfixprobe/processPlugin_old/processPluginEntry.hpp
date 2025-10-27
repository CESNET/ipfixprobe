/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Defines the ProcessPluginEntry structure used for plugin registration.
 *
 * The ProcessPluginEntry structure stores metadata and runtime information
 * about a specific flow-processing plugin. It is used by the framework to
 * manage plugin lifecycle, context allocation, and activation state.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "../api.hpp"

namespace ipxp {

class ProcessPlugin;

/**
 * @brief Metadata and runtime handle for a registered ProcessPlugin.
 *
 * This structure associates a plugin instance with its configuration
 * and runtime requirements. It contains the plugin's name, context
 * memory requirements, and activation state.
 */
struct IPXP_API ProcessPluginEntry {
	/**< @brief Human-readable plugin name (unique identifier). */
	std::string name;

	/**< @brief Required size of the plugin's per-flow context in bytes. */
	std::size_t contextSize;

	/**< @brief Required alignment for the plugin's context. */
	std::size_t contextAlignment;

	/**< @brief Whether the plugin is currently enabled in the framework. */
	bool enabled;

	/**< @brief Shared pointer to the actual plugin implementation. */
	std::shared_ptr<ProcessPlugin> plugin;
};

} // namespace ipxp
