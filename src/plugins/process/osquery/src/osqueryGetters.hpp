/**
 * @file osqueryGetters.hpp
 * @brief Getters for OSQuery plugin fields.
 * @author Damir Zainullin <damir.zainullin@example.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "osqueryContext.hpp"

#include <utils/stringViewUtils.hpp>

namespace ipxp::process::osquery {

inline constexpr const OSQueryContext& asOSQueryContext(const void* context) noexcept
{
	return *static_cast<const OSQueryContext*>(context);
}

// OSQueryField::OSQUERY_PROGRAM_NAME
inline constexpr auto getOSQueryProgramNameField
	= [](const void* context) { return toStringView(asOSQueryContext(context).programName); };

// OSQueryField::OSQUERY_USERNAME
inline constexpr auto getOSQueryUsernameField
	= [](const void* context) { return toStringView(asOSQueryContext(context).username); };

// OSQueryField::OSQUERY_OS_NAME
inline constexpr auto getOSQueryOSNameField
	= [](const void* context) { return toStringView(asOSQueryContext(context).osName); };

// OSQueryField::OSQUERY_OS_MAJOR
inline constexpr auto getOSQueryOSMajorField
	= [](const void* context) { return toStringView(asOSQueryContext(context).majorNumber); };

// OSQueryField::OSQUERY_OS_MINOR
inline constexpr auto getOSQueryOSMinorField
	= [](const void* context) { return toStringView(asOSQueryContext(context).minorNumber); };

// OSQueryField::OSQUERY_OS_BUILD
inline constexpr auto getOSQueryOSBuildField
	= [](const void* context) { return toStringView(asOSQueryContext(context).osBuild); };

// OSQueryField::OSQUERY_OS_PLATFORM
inline constexpr auto getOSQueryOSPlatformField
	= [](const void* context) { return toStringView(asOSQueryContext(context).osPlatform); };

// OSQueryField::OSQUERY_OS_PLATFORM_LIKE
inline constexpr auto getOSQueryOSPlatformLikeField
	= [](const void* context) { return toStringView(asOSQueryContext(context).osPlatformLike); };

// OSQueryField::OSQUERY_OS_ARCH
inline constexpr auto getOSQueryOSArchField
	= [](const void* context) { return toStringView(asOSQueryContext(context).osArch); };

// OSQueryField::OSQUERY_KERNEL_VERSION
inline constexpr auto getOSQueryKernelVersionField
	= [](const void* context) { return toStringView(asOSQueryContext(context).kernelVersion); };

// OSQueryField::OSQUERY_SYSTEM_HOSTNAME
inline constexpr auto getOSQuerySystemHostnameField
	= [](const void* context) { return toStringView(asOSQueryContext(context).systemHostname); };

} // namespace ipxp::process::osquery
