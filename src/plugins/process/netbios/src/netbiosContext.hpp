/**
 * @file
 * @brief Export data of netbios plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <string>

namespace ipxp::process::netbios {

/**
 * @struct NetBIOSContext
 * @brief Struct representing NetBIOS export context.
 */
struct NetBIOSContext {
	std::string name;
	char suffix;
};

} // namespace ipxp::process::netbios
