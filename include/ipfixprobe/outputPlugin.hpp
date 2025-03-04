/**
 * @file
 * @brief Generic interface of output plugin
 * @author Pavel Siska <siska@cesnet.cz>
 * @author Vaclav Bartos <bartos@cesnet.cz>
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "api.hpp"
#include "flowifc.hpp"
#include "plugin.hpp"
#include "process.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ipxp {

#define DEFAULT_EXPORTER_ID 1

/**
 * \brief Base class for flow exporters.
 */
class IPXP_API OutputPlugin : public Plugin {
public:
	using ProcessPlugins = std::vector<std::pair<std::string, std::shared_ptr<ProcessPlugin>>>;
	uint64_t m_flows_seen; /**< Number of flows received to export. */
	uint64_t m_flows_dropped; /**< Number of flows that could not be exported. */

	OutputPlugin()
		: m_flows_seen(0)
		, m_flows_dropped(0)
	{
	}
	virtual ~OutputPlugin() {}

	virtual void init(const char* params, ProcessPlugins& plugins) = 0;

	enum class Result { EXPORTED = 0, DROPPED };
	/**
	 * \brief Send flow record to output interface.
	 * \param [in] flow Flow to send.
	 * \return 0 on success
	 */
	virtual int export_flow(const Flow& flow) = 0;

	/**
	 * \brief Force exporter to flush flows to collector.
	 */
	virtual void flush() {}
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
 * @brief Type alias for the OutputPlugin factory.
 *
 * Provides a factory for creating OutputPlugin instances using a string-based constructor.
 */
using OutputPluginFactory
	= PluginFactory<OutputPlugin, const std::string&, OutputPlugin::ProcessPlugins&>;

} // namespace ipxp
