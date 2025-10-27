/**
 * @file
 * @brief Export data of basicplus plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <directionalField.hpp>

namespace ipxp::process::basicPlus {

/**
 * @struct BasicPlusContext
 * @brief Structure representing extended basic flow export fields.
 *
 * Contains directional fields for various IP and TCP header values, as well as
 * additional TCP-specific metrics.
 */
struct BasicPlusContext {
	ipxp::process::DirectionalField<uint8_t> ipTTL; ///< Directional IP Time-To-Live value
	ipxp::process::DirectionalField<uint8_t> ipFlag; ///< Directional IP flag value
	ipxp::process::DirectionalField<uint16_t> tcpWindow; ///< Directional TCP window size
	ipxp::process::DirectionalField<uint64_t> tcpOption; ///< Directional TCP option value
	ipxp::process::DirectionalField<uint32_t> tcpMSS; ///< Directional TCP Maximum Segment Size
	uint16_t tcpSynSize {0}; ///< Size of TCP SYN packet
};

} // namespace ipxp::process::basicPlus
