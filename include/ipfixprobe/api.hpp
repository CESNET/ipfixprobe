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
 * \def IPXP_API
 * \brief Macro for exporting public API symbols
 *
 * This macro is used to explicitly mark symbols that are part of the public API.
 * If the compiler supports visibility attributes, it ensures that only symbols
 * marked with this macro are exported, while others remain hidden.
 *
 * Using this macro helps reduce the symbol table size, improves load time,
 * and minimizes symbol conflicts by keeping internal symbols hidden.
 *
 * Example usage:
 * \code
 * class IPXP_API MyClass {
 * public:
 *     void doSomething();
 * };
 * \endcode
 */
#define IPXP_API [[gnu::visibility("default")]]
