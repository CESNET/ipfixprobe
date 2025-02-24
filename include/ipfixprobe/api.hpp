/**
 * @file
 * @brief Definitions for API functions
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 * 
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

/**
 * \brief Make an interface public outside
 *
 * If the compiler supports attribute to mark objects as hidden, mark all
 * objects as hidden and export only objects explicitly marked to be part of
 * the public API.
 */
#define IPXP_API [[gnu::visibility("default")]]

