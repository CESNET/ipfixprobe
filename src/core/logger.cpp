/**
 * @file
 * @brief Logger based on spdlog library
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ipfixprobe/logger.hpp>

#include <mutex>
#include <stdexcept>

#include <spdlog/cfg/env.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace ipxp::logger {

static std::mutex g_loggerMutex;

void init()
{
    const std::lock_guard<std::mutex> guard(g_loggerMutex);

    spdlog::cfg::load_env_levels();
    spdlog::set_pattern("[%^%L%$] %n: %v");
}

void setGlobalVerbosity(spdlog::level::level_enum level)
{
    spdlog::set_level(level);
}

Logger get(std::string_view name)
{
    const std::lock_guard<std::mutex> guard(g_loggerMutex);

    const std::string tmp {name};
    auto logger = spdlog::get(tmp);

    if (logger) {
        // Logger already exists
        return logger;
    }

    return spdlog::stdout_color_mt(tmp);
}

} // namespace ipxp::logger
