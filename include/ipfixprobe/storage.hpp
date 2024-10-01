/**
 * \file storage.hpp
 * \brief Generic interface of storage plugin
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */

#ifndef IPXP_STORAGE_HPP
#define IPXP_STORAGE_HPP

#include "flowifc.hpp"
#include "packet.hpp"
#include "plugin.hpp"
#include "process.hpp"
#include "ring.h"

#include <array>
#include <bitset>
#include <cstring>
#include <memory>
#include <string>
#include <telemetry.hpp>

namespace ipxp {

/**
 * \brief Base class for flow caches.
 */
class StoragePlugin : public Plugin {
protected:
    ipx_ring_t* m_export_queue;

private:
    ProcessPlugin** m_plugins; /**< Array of plugins. */
    uint32_t m_plugin_cnt;
    Flow::PluginsStatus m_plugins_status; /**< Keeps statuses of the process plugin before flow is created. */

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

    virtual void export_expired(time_t ts) {}
    virtual void finish() {}

    /**
     * \brief set telemetry directory for the storage
     */
    virtual void set_telemetry_dir(std::shared_ptr<telemetry::Directory> dir) {}

    /**
     * \brief Add plugin to internal list of plugins.
     * Plugins are always called in the same order, as they were added.
     */
    void add_plugin(ProcessPlugin* plugin)
    {
        if (m_plugin_cnt == Flow::MAXIMAL_PROCESS_PLUGIN_COUNT){
            throw PluginError("No more process plugins could be added.");
        }
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

protected:
    // Every StoragePlugin implementation should call these functions at appropriate places

    /**
     * \brief Call pre_create function for each added plugin.
     * \param [in] pkt Input parsed packet.
     * \return Options for flow cache.
     */
    int plugins_pre_create(Packet& pkt)
    {
        m_plugins_status.get_all_data.reset();
        m_plugins_status.get_no_data = (uint64_t) -1 << m_plugin_cnt;
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            auto flowAction = m_plugins[i]->pre_create(pkt);
            if (flowAction == ProcessPlugin::FlowAction::NO_PROCESS) {
                m_plugins_status.get_no_data[i] = true;
            } else if (flowAction == ProcessPlugin::FlowAction::GET_ALL_DATA) {
                m_plugins_status.get_all_data[i] = true;
            }

            ret |= flowAction;
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
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            if (m_plugins_status.get_no_data[i])
                continue;

            auto flowAction = m_plugins[i]->post_create(rec, pkt);
            if (flowAction == ProcessPlugin::FlowAction::NO_PROCESS) {
                m_plugins_status.get_all_data[i] = false;
                m_plugins_status.get_no_data[i] = true;
            } else if (flowAction == ProcessPlugin::FlowAction::GET_METADATA) {
                m_plugins_status.get_all_data[i] = false;
            } else if (flowAction == ProcessPlugin::FlowAction::GET_ALL_DATA) {
                m_plugins_status.get_all_data[i] = true;
            }

            ret |= flowAction;
        }

        rec.plugins_status.get_all_data = m_plugins_status.get_all_data;
        rec.plugins_status.get_no_data = m_plugins_status.get_no_data;
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
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            if (rec.plugins_status.get_no_data[i])
                continue;

            auto flowAction = m_plugins[i]->pre_update(rec, pkt);
            if (flowAction == ProcessPlugin::FlowAction::NO_PROCESS) {
                rec.plugins_status.get_all_data[i] = false;
                rec.plugins_status.get_no_data[i] = true;
            } else if (flowAction == ProcessPlugin::FlowAction::GET_METADATA) {
                rec.plugins_status.get_all_data[i] = false;
            } else if (flowAction == ProcessPlugin::FlowAction::GET_ALL_DATA) {
                rec.plugins_status.get_all_data[i] = true;
            }

            ret |= flowAction;
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
        int ret = 0;
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            if (rec.plugins_status.get_no_data[i])
                continue;

            auto flowAction = m_plugins[i]->post_update(rec, pkt);
            if (flowAction == ProcessPlugin::FlowAction::NO_PROCESS) {
                rec.plugins_status.get_all_data[i] = false;
                rec.plugins_status.get_no_data[i] = true;
            } else if (flowAction == ProcessPlugin::FlowAction::GET_METADATA) {
                rec.plugins_status.get_all_data[i] = false;
            } else if (flowAction == ProcessPlugin::FlowAction::GET_ALL_DATA) {
                rec.plugins_status.get_all_data[i] = true;
            }

            ret |= flowAction;
        }
        return ret;
    }

    /**
     * \brief Call pre_export function for each added plugin.
     * \param [in,out] rec Stored flow record.
     */
    void plugins_pre_export(Flow& rec)
    {
        for (unsigned int i = 0; i < m_plugin_cnt; i++) {
            if (rec.plugins_status.get_no_data[i])
                continue;
            m_plugins[i]->pre_export(rec);
        }
    }

    /**
     * \brief Checks if process plugins require all available data.
     * \param [in] rec Stored flow record.
     * \return True if all data required, false otherwise.
     */
    bool all_data_required(const Flow& flow) const noexcept
    {
        return m_plugins_status.get_all_data.any();
    }

    /**
     * \brief Checks if process plugins don't require any data.
     * \param [in] rec Stored flow record.
     * \return True if no data required, false otherwise.
     */
    bool no_data_required(const Flow& flow) const noexcept
    {
        return m_plugins_status.get_no_data.all();
    }

    /**
     * \brief Checks if process plugins require only flow metadata.
     * \param [in] rec Stored flow record.
     * \return True if only metadata required, false otherwise.
     */
    bool only_metadata_required(const Flow& flow) const noexcept
    {
        return !all_data_required(flow) && !no_data_required(flow);
    }
};

} // namespace ipxp
#endif /* IPXP_STORAGE_HPP */
