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
#include "processPlugin.hpp"
#include "ring.h"
#include "cttConfig.hpp"

#include <memory>
#include <string>
#include <telemetry.hpp>

namespace ipxp {

/**
 * \brief Base class for flow caches.
 */
class IPXP_API StoragePlugin : public Plugin {
public:
	StoragePlugin()
		: m_export_queue(nullptr)
		, m_plugins(nullptr)
		, m_plugin_cnt(0)
	{
	}

	virtual ~StoragePlugin()
	{
		if (m_plugins != nullptr) {
			delete[] m_plugins;
		}
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
	 * \brief Send signal that no new flows should be created
	 */
	virtual void terminate_input() { m_input_terminted = true; }

	/**
	 * \brief Check if input is still required by the storage plugin
	 * \return True if input is required, false otherwise.
	 */
	virtual bool requires_input() const { return !m_input_terminted; }

    virtual void init_ctt([[maybe_unused]]const CttConfig& ctt_config)
    {
        throw PluginError("CTT is not supported in this storage plugin");
    }

	/**
	 * \brief set telemetry directory for the storage
	 */
	virtual void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) { (void) dir; }

	/**
	 * \brief Add plugin to internal list of plugins.
	 * Plugins are always called in the same order, as they were added.
	 */
	void add_plugin(ProcessPlugin* plugin)
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
	}

	/**
     * \brief Checks if process plugins require all available data.
     * \param [in] flow Stored flow record.
     * \return True if all data required, false otherwise.
    */
	bool all_data_required(const Flow& flow) const noexcept
	{
		return flow.plugins_status.get_all_data.any();
	}

   /**
     * \brief Checks if process plugins don't require any data.
     * \param [in] flow Stored flow record.
     * \return True if no data required, false otherwise.
    */
	bool no_data_required(const Flow& flow) const noexcept
	{
		return flow.plugins_status.get_no_data.all();
	}

   /**
     * \brief Checks if process plugins require only flow metadata.
     * \param [in] rec Stored flow record.
     * \return True if only metadata required, false otherwise.
    */
	bool only_metadata_required(const Flow& flow) const noexcept
	{
		return !all_data_required(flow);
	}

protected:
	//Every StoragePlugin implementation should call these functions at appropriate places

    /**
     * \brief Call pre_create function for each added plugin.
     * \param [in] pkt Input parsed packet.
     * \return Options for flow cache.
     */
    int plugins_pre_create(Packet& pkt)
    {
        PluginStatusConverter plugin_status_converter(m_plugins_status);
        plugin_status_converter.reset(m_plugin_cnt);
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            auto flow_action = m_plugins[i]->pre_create(pkt);
            plugin_status_converter.set_flow_status(i, flow_action);
            ret |= flow_action;
        }
        return ret;
    }

    /**
     * \brief Call post_create function for each added plugin.
     * \param [in,out] rec Stored flow record.
     * \param [in] pkt Input parsed packet.
     * \return Options for flow cache.
     */
    int plugins_post_create(Flow& rec, const Packet& pkt)
    {
        PluginStatusConverter plugin_status_converter(m_plugins_status);
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            if (plugin_status_converter.plugin_gets_no_data(i))
                continue;

            auto flow_action = m_plugins[i]->post_create(rec, pkt);
            plugin_status_converter.set_flow_status(i, flow_action);
            ret |= flow_action;
        }

        PluginStatusConverter(rec.plugins_status) = plugin_status_converter;
        return ret;
    }

    /**
     * \brief Call pre_update function for each added plugin.
     * \param [in,out] rec Stored flow record.
     * \param [in] pkt Input parsed packet.
     * \return Options for flow cache.
     */
    int plugins_pre_update(Flow& rec, Packet& pkt)
    {
        PluginStatusConverter plugin_status_converter(rec.plugins_status);
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            if (plugin_status_converter.plugin_gets_no_data(i))
                continue;

            auto flow_action = m_plugins[i]->pre_update(rec, pkt);
            plugin_status_converter.set_flow_status(i, flow_action);
            ret |= flow_action;
        }
        return ret;
    }

    /**
     * \brief Call post_update function for each added plugin.
     * \param [in,out] rec Stored flow record.
     * \param [in] pkt Input parsed packet.
     */
    int plugins_post_update(Flow& rec, const Packet& pkt)
    {
        PluginStatusConverter plugin_status_converter(rec.plugins_status);
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            if (plugin_status_converter.plugin_gets_no_data(i))
                continue;

            auto flow_action = m_plugins[i]->post_update(rec, pkt);
            plugin_status_converter.set_flow_status(i, flow_action);
            ret |= flow_action;
        }
        return ret;
    }

    /**
     * \brief Call pre_export function for each added plugin.
     * \param [in,out] rec Stored flow record.
     */
    void plugins_pre_export(Flow& rec)
    {
        PluginStatusConverter plugin_status_converter(rec.plugins_status);
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            //if (plugin_status_converter.plugin_gets_no_data(i))
            //    continue;
            m_plugins[i]->pre_export(rec);
        }
    }

	/**
     * \brief Auxiliary class for manipulations plugins status.
     */
    class PluginStatusConverter {
	public:
		PluginStatusConverter(Flow::PluginsStatus& plugins_status) noexcept
			: m_plugins_status(plugins_status)
		{
		}

		/**
		 * \brief Resets all kept plugins status to the initial state.
		 * \param [in] plugin_count Count of process plugins.
		 */
		void reset(size_t plugin_count) noexcept
		{
			m_plugins_status.get_all_data.reset();
			m_plugins_status.get_no_data = (uint64_t) -1 << plugin_count;
		}

		/**
		 * \brief Sets process plugin status at the given index.
		 * \param [in] index Index of the process plugin.
		 * \param [in] flow_action Given flow action to set.
		 */
		void set_flow_status(size_t index, ProcessPlugin::FlowAction flow_action) noexcept
		{
			if (flow_action == ProcessPlugin::FlowAction::GET_NO_DATA) {
				m_plugins_status.get_all_data[index] = false;
				m_plugins_status.get_no_data[index] = true;
			} else if (flow_action == ProcessPlugin::FlowAction::GET_ONLY_METADATA) {
				m_plugins_status.get_all_data[index] = false;
			} else if (flow_action == ProcessPlugin::FlowAction::GET_ALL_DATA) {
				m_plugins_status.get_all_data[index] = true;
			}
		}

		/**
		 * \brief Checks if the process plugin at the given index doesn't require any data.
		 * \param [in] index Index of the process plugin.
		 * \return True, if the process plugin doesn't require any data.
		 */
		bool plugin_gets_no_data(size_t index) noexcept
		{
			return m_plugins_status.get_no_data[index];
		}

		PluginStatusConverter&
		operator=(const PluginStatusConverter& plugin_status_converter) noexcept
		{
			m_plugins_status.get_all_data = plugin_status_converter.m_plugins_status.get_all_data;
			m_plugins_status.get_no_data = plugin_status_converter.m_plugins_status.get_no_data;
			return *this;
		}

	private:
		Flow::PluginsStatus& m_plugins_status;
	};

	ipx_ring_t* m_export_queue;
	bool m_input_terminted = false; 

private:
	ProcessPlugin **m_plugins; /**< Array of plugins. */
	uint32_t m_plugin_cnt;
	Flow::PluginsStatus
		m_plugins_status; /**< Keeps statuses of the process plugin before flow is created. */
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
using StoragePluginFactory = PluginFactory<StoragePlugin, const std::string&, ipx_ring_t*>;

} // namespace ipxp
