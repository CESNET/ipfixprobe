/**
 * @file
 * @brief Base class and factory for packet input plugins
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * This file defines the base class for input plugins, responsible for processing
 * incoming packets, maintaining statistics, and integrating with the telemetry system.
 * It also includes a factory template for plugin creation.
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "api.hpp"
#include "packet.hpp"
#include "parser-stats.hpp"
#include "plugin.hpp"
#include "telemetry-utils.hpp"

#include <cstdint>
#include <memory>
#include <string>

#include <telemetry.hpp>

namespace ipxp {

/**
 * \brief Base class for packet receivers.
 *
 * InputPlugin is an abstract base class for processing network packets.
 * It provides functionality for handling telemetry directories and maintains
 * statistics on processed packets.
 */
class IPXP_API InputPlugin
	: public TelemetryUtils
	, public Plugin {
public:
	enum class Result {
		TIMEOUT = 0,
		PARSED,
		NOT_PARSED,
		END_OF_FILE,
		ERROR,
	};

	virtual ~InputPlugin() = default;

	/**
	 * @brief Retrieves a block of packets.
	 * @param packets Reference to a PacketBlock to store received packets.
	 * @return The result of the packet retrieval operation.
	 */
	virtual Result get(PacketBlock& packets) = 0;

	/**
	 * @brief Sets the telemetry directories for this plugin.
	 * @param plugin_dir Shared pointer to the plugin-specific telemetry directory.
	 * @param queues_dir Shared pointer to the telemetry directory for queues.
	 * @param summary_dir Shared pointer to the telemetry directory for summary statistics.
	 * @param pipeline_dir Shared pointer to the telemetry directory for the pipeline.
	 */
	void set_telemetry_dirs(
		std::shared_ptr<telemetry::Directory> plugin_dir,
		std::shared_ptr<telemetry::Directory> queues_dir,
		std::shared_ptr<telemetry::Directory> summary_dir,
		std::shared_ptr<telemetry::Directory> pipeline_dir);

	/// Number of packets seen by the plugin.
	uint64_t m_seen = 0;
	/// Number of packets successfully parsed.
	uint64_t m_parsed = 0;
	/// Number of packets dropped.
	uint64_t m_dropped = 0;

protected:
	/**
	 * @brief Configures the telemetry directories.
	 *
	 * This method can be overridden by derived classes to perform additional
	 * setup for telemetry directories.
	 *
	 * @param plugin_dir Shared pointer to the plugin-specific telemetry directory.
	 * @param queues_dir Shared pointer to the telemetry directory for queues.
	 */
	virtual void configure_telemetry_dirs(
		std::shared_ptr<telemetry::Directory> plugin_dir,
		std::shared_ptr<telemetry::Directory> queues_dir)
	{
		(void) plugin_dir;
		(void) queues_dir;
	};

	/// Statistics related to packet parsing.
	ParserStats m_parser_stats {10};

private:
	void create_parser_stats_telemetry(
		std::shared_ptr<telemetry::Directory> queues_dir,
		std::shared_ptr<telemetry::Directory> summaryDirectory,
		std::shared_ptr<telemetry::Directory> pipelineDirectory);
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
 * @brief Type alias for the InputPlugin factory.
 *
 * Provides a factory for creating InputPlugin instances using a string-based constructor.
 */
using InputPluginFactory = PluginFactory<InputPlugin, const std::string&>;

} // namespace ipxp
