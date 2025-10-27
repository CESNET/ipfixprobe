/**
 * @file
 * @brief Process wrapper class to help maintain its lifetime.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "process.hpp"

#include <array>

namespace ipxp::process::osquery {

std::optional<Process> Process::popen2(std::string_view command) noexcept
{
	constexpr std::size_t READ_FD = 0;
	constexpr std::size_t WRITE_FD = 1;

	std::array<int, 2> pipeStdin;
	std::array<int, 2> pipeStdout;
	// pid_t pid;

	if (pipe(pipeStdin.data()) != 0 || pipe(pipeStdout.data()) != 0) {
		return std::nullopt;
	}

	const pid_t pid = fork();
	if (pid < 0) {
		return std::nullopt;
	} else if (pid == 0) {
		close(pipeStdin[WRITE_FD]);
		dup2(pipeStdin[READ_FD], READ_FD);
		close(pipeStdout[READ_FD]);
		dup2(pipeStdout[WRITE_FD], WRITE_FD);
		execl("/bin/sh", "sh", "-c", command, nullptr);
		perror("execl");
		exit(1);
	}

	return Process {pid, pipeStdin[WRITE_FD], pipeStdout[READ_FD]};
}

} // namespace ipxp::process::osquery
