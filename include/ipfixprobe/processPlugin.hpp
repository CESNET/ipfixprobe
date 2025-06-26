/**
 * @file
 * @brief Generic interface of processing plugin
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

#include "flowifc.hpp"
#include "packet.hpp"
#include "plugin.hpp"

#include <atomic>

namespace ipxp {

/**
 * \brief Class template for flow cache plugins.
 */
class IPXP_API ProcessPlugin : public Plugin {
public:
	enum FlowAction : int {
		/**
		 * \brief Tell storage plugin that process plugin requires all incoming data for given flow.
		 */
		GET_ALL_DATA = 0,
		/**
		 * \brief Tell storage plugin that process plugin requires only metadata.
		 * Used to offload the cache when all process plugin return GET_METADATA.
		 */
		GET_ONLY_METADATA = 0x2,
		/**
		 * \brief Tell storage plugin that process plugin has ended up its work and doesn't require
		 * any new data. Used to offload the cache when all process plugin return NO_PROCESS.
		 */
		GET_NO_DATA = 0x4,
		/**
		 * \brief Tell storage plugin to flush (immediately export) current flow.
		 * Behavior when called from post_create, pre_update and post_update: flush current Flow and
		 * erase FlowRecord.
		 */
		FLUSH = 0x1,

		/**
		 * \brief Tell storage plugin to flush (immediately export) current flow.
		 * Behavior when called from post_create: flush current Flow and erase FlowRecord.
		 * Behavior when called from pre_update and post_update: flush current Flow, erase
		 * FlowRecord and call post_create on packet.
		 */
		FLUSH_WITH_REINSERT = 0x7
	};
	
	ProcessPlugin(int pluginID)
		: m_pluginID(pluginID)
	{
	}

	virtual ~ProcessPlugin() {}
	virtual ProcessPlugin* copy() = 0;

	virtual RecordExt* get_ext() const { return nullptr; }

	/**
	 * \brief Called before a new flow record is created.
	 * \param [in] pkt Parsed packet.
	 * \return 0 on success or FLOW_FLUSH option.
	 */
	virtual FlowAction pre_create([[maybe_unused]] Packet& pkt)
    {
        return FlowAction::GET_ALL_DATA;
    }

	/**
	 * \brief Called after a new flow record is created.
	 * \param [in,out] rec Reference to flow record.
	 * \param [in] pkt Parsed packet.
	 * \return 0 on success or FLOW_FLUSH option.
	 */
	virtual FlowAction post_create([[maybe_unused]] Flow& rec, [[maybe_unused]] const Packet& pkt)
    {
        return FlowAction::GET_ALL_DATA;
    }
	/**
	 * \brief Called before an existing record is update.
	 * \param [in,out] rec Reference to flow record.
	 * \param [in,out] pkt Parsed packet.
	 * \return 0 on success or FLOW_FLUSH option.
	 */
	virtual FlowAction pre_update([[maybe_unused]] Flow& rec, [[maybe_unused]] Packet& pkt)
    {
        return FlowAction::GET_ALL_DATA;
    }

	/**
	 * \brief Called after an existing record is updated.
	 * \param [in,out] rec Reference to flow record.
	 * \param [in,out] pkt Parsed packet.
	 * \return 0 on success or FLOW_FLUSH option.
	 */
	virtual FlowAction post_update([[maybe_unused]] Flow& rec, [[maybe_unused]] const Packet& pkt)
    {
        return FlowAction::GET_ALL_DATA;
    }

	/**
	 * \brief Called before a flow record is exported from the cache.
	 * \param [in,out] rec Reference to flow record.
	 */
	virtual void pre_export([[maybe_unused]] Flow& rec) {}

protected:
	int m_pluginID;
};

/**
 * @brief A class for generating unique plugin IDs.
 *
 * This class is designed to ensure atomic generation of unique IDs for process plugins.
 * The ID is incremented and stored using an atomic variable, ensuring thread-safe access
 * even with concurrent calls from multiple threads. The class is implemented as a Singleton.
 */
class IPXP_API ProcessPluginIDGenerator {
public:
	/**
	 * @brief Gets the instance of the ProcessPluginIDGenerator (Singleton).
	 * @return A reference to the single instance of the ProcessPluginIDGenerator.
	 *
	 * This method ensures that there is only one instance of the ProcessPluginIDGenerator
	 * class throughout the application's lifecycle.
	 */
	static ProcessPluginIDGenerator& instance()
	{
		static ProcessPluginIDGenerator instance;
		return instance;
	}

	/**
	 * @brief Generates a unique plugin ID.
	 * @return The generated plugin ID.
	 *
	 * This method atomically increments the internal counter and returns the ID
	 * that was generated before the increment. This ensures that each call produces
	 * a unique, thread-safe ID.
	 */

	int generatePluginID() { return m_id.fetch_add(1, std::memory_order_relaxed); }

	/**
	 * @brief Gets the current count of generated plugin IDs.
	 * @return The total count of generated plugin IDs.
	 *
	 * This method returns the current value of the ID counter, representing the
	 * total number of plugin IDs that have been generated so far.
	 */
	int getPluginsCount() const { return m_id.load(std::memory_order_relaxed); }

private:
	std::atomic<int> m_id = 0;
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
using ProcessPluginFactory = PluginFactory<ProcessPlugin, const std::string&, int>;

} // namespace ipxp
