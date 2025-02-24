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

#pragma once

#include <cstdint>
#include <string_view>

#include <spdlog/spdlog.h>

namespace ipxp::logger {

/**
 * Type alias for shared pointer to spdlog::logger
 */
using Logger = std::shared_ptr<spdlog::logger>;

/**
 * @brief Perform default initialization of spdlog library.
 *
 * The function loads logger configuration from environment and modifies
 * default output message format. This function should be called before
 * first use of any logger.
 */
void init();

/**
 * @brief Set the global verbosity level.
 *
 * @param[in] level log level
 */
void setGlobalVerbosity(spdlog::level::level_enum level);

/**
 * @brief Get a logger of the given name.
 *
 * If the logger doesn't exists, a new logger of default type is created.
 * Otherwise, the existing one is returned.
 *
 * @param[in] name Name of the logger.
 * @return Pointer to logger instance.
 */
Logger get(std::string_view name);

} // namespace ipxp::logger
