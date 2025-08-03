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
