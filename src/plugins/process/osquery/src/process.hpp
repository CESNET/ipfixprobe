/**
 * @file
 * @brief Process wrapper class to help maintain its lifetime.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <optional>
#include <string_view>

#include <fileDescriptor/fileDescriptor.hpp>
#include <sys/types.h>

namespace ipxp::process::osquery {

struct Process {
	pid_t pid;
	FileDescriptor inputFileDescriptor;
	FileDescriptor outputFileDescriptor;

	static std::optional<Process> popen2(std::string_view creationCommand) noexcept;

	Process(Process&&) = default;
	Process& operator=(Process&& other) = default;

private:
	Process(const pid_t pid, const int inputFD, const int outputFD)
		: pid(pid)
		, inputFileDescriptor(inputFD)
		, outputFileDescriptor(outputFD)
	{
	}
};

} // namespace ipxp::process::osquery
