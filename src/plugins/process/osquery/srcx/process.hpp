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
#include <sys/types.h>

#include "fileDescriptor.hpp"

namespace ipxp
{
    
struct Process {
    pid_t pid;
    FileDescriptor inputFileDescriptor;
    FileDescriptor outputFileDescriptor;

    static std::optional<Process> popen2(std::string_view creationCommand) noexcept;

    Process& operator=(Process&& other) = delete;
private:
    Process() = default; 
};


} // namespace ipxp
