/**
 * @file
 * @brief Export data of osquery plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <array>
#include <boost/container/static_vector.hpp>
#include <optional>
#include <span>

namespace ipxp
{

/**
 * @struct OSQueryData
 * @brief Struct representing OS query data. Contains information about the OS query process.
 */
struct OSQueryData {
    constexpr static std::string_view defaultFillText = "UNDEFINED";

	std::string programName{defaultFillText};
	std::string username{defaultFillText};
	std::string osName;
	uint16_t majorNumber;
	uint16_t minorNumber;
	std::string osBuild;
	std::string osPlatform;
	std::string osPlatformLike;
	std::string osArch;
	std::string kernelVersion;
	std::string systemHostname;
};  

} // namespace ipxp

