#pragma once

#include <fileDescriptor/fileDescriptor.hpp>

namespace ipxp::output::ipfix {

class ConnectionResult {
public:
	ConnectionResult(std::string errorMessage)
		: m_errorMessage(std::move(errorMessage))
	{
	}

	ConnectionResult(process::FileDescriptor fileDescriptor)
		: m_fileDescriptor(std::move(fileDescriptor)) {};

	bool isSuccess() const noexcept { return static_cast<bool>(m_fileDescriptor); }

	std::string_view getErrorMessage() const noexcept { return m_errorMessage; }

	process::FileDescriptor getFileDescriptor() noexcept
	{
		return process::FileDescriptor(std::move(m_fileDescriptor));
	}

private:
	std::string m_errorMessage;
	process::FileDescriptor m_fileDescriptor;
};

} // namespace ipxp::output::ipfix