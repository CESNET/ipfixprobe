#pragma once

#include "process.hpp"

#include <array>

namespace ipxp
{

std::optional<Process>
Process::popen2(std::string_view command) noexcept
{
    constexpr std::size_t READ_FD = 0;
    constexpr std::size_t WRITE_FD = 1;

    Process process;
	std::array<int, 2> pipeStdin;
    std::array<int, 2> pipeStdout;
	//pid_t pid;

	if (pipe(pipeStdin.data()) != 0 || pipe(pipeStdout.data()) != 0) {
		return std::nullopt;
	}

    process.pid = fork();

	if (process.pid < 0) {
		return std::nullopt;
	} else if (process.pid == 0) {
		close(pipeStdin[WRITE_FD]);
		dup2(pipeStdin[READ_FD], READ_FD);
		close(pipeStdout[READ_FD]);
		dup2(pipeStdout[WRITE_FD], WRITE_FD);
		execl("/bin/sh", "sh", "-c", command, nullptr);
		perror("execl");
		exit(1);
	}

    process.inputFileDescriptor = pipeStdin[WRITE_FD];
    process.outputFileDescriptor = pipeStdout[READ_FD];

	return process;
}


} // namespace ipxp
