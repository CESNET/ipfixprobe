#pragma once

#include <directionalField.hpp>

namespace ipxp
{

/**
 * @struct BasicPlusExport
 * @brief Structure representing extended basic flow export fields.
 *
 * Contains directional fields for various IP and TCP header values, as well as
 * additional TCP-specific metrics.
 */
struct BasicPlusData {
	DirectionalField<uint8_t> ipTTL;        ///< Directional IP Time-To-Live value
	DirectionalField<uint8_t> ipFlag;       ///< Directional IP flag value
	DirectionalField<uint16_t> tcpWindow;   ///< Directional TCP window size
	DirectionalField<uint64_t> tcpOption;   ///< Directional TCP option value
	DirectionalField<uint32_t> tcpMSS;      ///< Directional TCP Maximum Segment Size
	uint16_t tcpSynSize{0};                 ///< Size of TCP SYN packet
};  

} // namespace ipxp

