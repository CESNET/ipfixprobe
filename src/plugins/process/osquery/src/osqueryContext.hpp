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
#include <optional>
#include <span>

#include <boost/container/static_vector.hpp>

namespace ipxp::process::osquery {

/**
 * @struct OSQueryContext
 * @brief Struct representing OS query data. Contains information about the OS query process.
 */
struct OSQueryContext {
	constexpr static std::string_view defaultFillText = "UNDEFINED";

	// static string?
	std::string programName {defaultFillText};
	std::string username {defaultFillText};
	std::string osName;
	std::string majorNumber;
	std::string minorNumber;
	std::string osBuild;
	std::string osPlatform;
	std::string osPlatformLike;
	std::string osArch;
	std::string kernelVersion;
	std::string systemHostname;
};

} // namespace ipxp::process::osquery
