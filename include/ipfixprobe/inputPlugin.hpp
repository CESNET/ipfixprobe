/**
 * @file
 * @brief Input plugin interface
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <telemetry.hpp>

#include "api.hpp"
#include "packet.hpp"
#include "parser-stats.hpp"
#include "plugin.hpp"
#include "telemetry-utils.hpp"

namespace ipxp {

class IPXP_API InputPlugin
    : public TelemetryUtils
    , public Plugin {
public:
    enum class Result { TIMEOUT = 0, PARSED, NOT_PARSED, END_OF_FILE, ERROR };

    uint64_t m_seen;
    uint64_t m_parsed;
    uint64_t m_dropped;

    virtual ~InputPlugin() {}

    virtual Result get(PacketBlock& packets) = 0;

    void set_telemetry_dirs(
        std::shared_ptr<telemetry::Directory> plugin_dir,
        std::shared_ptr<telemetry::Directory> queues_dir);

protected:
    virtual void configure_telemetry_dirs(
        std::shared_ptr<telemetry::Directory> plugin_dir,
        std::shared_ptr<telemetry::Directory> queues_dir)
    {
        (void) plugin_dir;
        (void) queues_dir;
    };

    ParserStats m_parser_stats;

private:
    void create_parser_stats_telemetry(std::shared_ptr<telemetry::Directory> queues_dir);
};

/**
 * @brief Factory template for creating plugins.
 *
 * @tparam Base The base class for the plugin.
 * @tparam Args The argument types for the factory.
 */
template<typename Base, typename... Args>
class IPXP_API PluginFactory;

/**
 * @brief Type alias for the InputPlugin factory.
 */
using InputPluginFactory = PluginFactory<InputPlugin, const std::string&>;

} // namespace ipxp