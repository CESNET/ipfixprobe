/**
 * @file
 * @brief Export fields of basicplus plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstddef>

namespace ipxp {

/**
 * @enum BasicPlusFields
 * @brief Enumerates the fields exported by the BasicPlus plugin.
 *
 * These enum values are used to index field handlers for this plugin.
 */
enum class BasicPlusFields : std::size_t {
	IP_TTL = 0,
	IP_TTL_REV,
	IP_FLG,
	IP_FLG_REV,
	TCP_WIN,
	TCP_WIN_REV,
	TCP_OPT,
	TCP_OPT_REV,
	TCP_MSS,
	TCP_MSS_REV,
	TCP_SYN_SIZE,
	FIELDS_SIZE,
};

} // namespace ipxp
