/**
 * @file
 * @brief Generic interface of storage plugin
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
#include "packet.hpp"
#include "plugin.hpp"
#include "ring.h"

#include <memory>
#include <string>

#include <processPlugin.hpp>
#include <processPluginManager.hpp>
#include <telemetry.hpp>

namespace ipxp {

/**
 * \brief Base class for flow caches.
 */
class IPXP_API StoragePlugin : public Plugin {
public:
	StoragePlugin(ProcessPluginManager& manager)
		: m_export_queue(nullptr)
		, m_manager(manager)
	//, m_plugins(nullptr)
	//, m_plugin_cnt(0)
	{
	}

	virtual ~StoragePlugin()
	{
		/*if (m_plugins != nullptr) {
			delete[] m_plugins;
		}*/
	}

	/**
	 * \brief Put packet into the cache (i.e. update corresponding flow record or create a new one)
	 * \param [in] pkt Input parsed packet.
	 * \return 0 on success.
	 */
	virtual int put_pkt(Packet& pkt) = 0;

	/**
	 * \brief Set export queue
	 */
	virtual void set_queue(ipx_ring_t* queue) { m_export_queue = queue; }

	/**
	 * \brief Get export queue
	 */
	const ipx_ring_t* get_queue() const { return m_export_queue; }

	virtual void export_expired(time_t ts) { (void) ts; }
	virtual void finish() {}

	/**
	 * \brief set telemetry directory for the storage
	 */
	virtual void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) { (void) dir; }

	/**
	 * \brief Add plugin to internal list of plugins.
	 * Plugins are always called in the same order, as they were added.
	 */
	/*void add_plugin(ProcessPlugin* plugin)
	{
		if (m_plugins == nullptr) {
			m_plugins = new ProcessPlugin*[8];
		} else {
			if (m_plugin_cnt % 8 == 0) {
				ProcessPlugin** tmp = new ProcessPlugin*[m_plugin_cnt + 8];
				for (unsigned int i = 0; i < m_plugin_cnt; i++) {
					tmp[i] = m_plugins[i];
				}
				delete[] m_plugins;
				m_plugins = tmp;
			}
		}
		m_plugins[m_plugin_cnt++] = plugin;
	}*/

protected:
	// Every StoragePlugin implementation should call these functions at appropriate places

	/**
	 * \brief Call pre_create function for each added plugin.
	 * \param [in] pkt Input parsed packet.
	 * \return Options for flow cache.
	 */
	/*int plugins_pre_create(Packet& pkt)
	{
		int ret = 0;
		for (unsigned int i = 0; i < m_plugin_cnt; i++) {
			ret |= m_plugins[i]->pre_create(pkt);
		}
		return ret;
	}*/

	/**
	 * \brief Call post_create function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 * \param [in] pkt Input parsed packet.
	 * \return Options for flow cache.
	 */
	int plugins_post_create(Flow& rec, const Packet& pkt)
	{
		int ret = 0;
		// for (unsigned int i = 0; i < m_plugin_cnt; i++) {
		//	ret |= m_plugins[i]->post_create(rec, pkt);
		// }
		return ret;
	}

	/**
	 * \brief Call pre_update function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 * \param [in] pkt Input parsed packet.
	 * \return Options for flow cache.
	 */
	/*int plugins_pre_update(Flow& rec, Packet& pkt)
	{
		int ret = 0;
		for (unsigned int i = 0; i < m_plugin_cnt; i++) {
			ret |= m_plugins[i]->pre_update(rec, pkt);
		}
		return ret;
	}*/

	/**
	 * \brief Call post_update function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 * \param [in] pkt Input parsed packet.
	 */
	int plugins_post_update(Flow& rec, const Packet& pkt)
	{
		int ret = 0;
		// for (unsigned int i = 0; i < m_plugin_cnt; i++) {
		//	ret |= m_plugins[i]->post_update(rec, pkt);
		// }
		return ret;
	}

	/**
	 * \brief Call pre_export function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 */
	void plugins_pre_export(Flow& rec)
	{
		//	for (unsigned int i = 0; i < m_plugin_cnt; i++) {
		//			m_plugins[i]->pre_export(rec);
		//}
	}

	ipx_ring_t* m_export_queue;

protected:
	ProcessPluginManager& m_manager;
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
 * @brief Type alias for the StoragePlugin factory.
 *
 * Provides a factory for creating StoragePlugin instances using a string-based constructor.
 */
using StoragePluginFactory
	= PluginFactory<StoragePlugin, const std::string&, ipx_ring_t*, ProcessPluginManager&>;

} // namespace ipxp
