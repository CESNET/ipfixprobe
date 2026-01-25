#pragma once

#include "connection.hpp"
#include "connectionResult.hpp"

namespace ipxp::output::ipfix {

static bool setNonBlockingMode(ipxp::process::FileDescriptor& fileDescriptor) noexcept
{
	const int flags = ::fcntl(fileDescriptor.get(), F_GETFL, 0);
	if (flags == -1) {
		return false;
	}

	if (::fcntl(fileDescriptor.get(), F_SETFL, flags | O_NONBLOCK) == -1) {
		return false;
	}
	return true;
}

class ConnectionFactory;

class TCPConnection : public Connection {
	friend class ConnectionFactory;

	TCPConnection(
		std::string host,
		const uint16_t port,
		const std::chrono::duration<uint32_t> reconnectionTimeout,
		const bool verbose,
		const bool blocking = false) noexcept
		: Connection(std::move(host), port, TransportProtocol::TCP, reconnectionTimeout, verbose)
		, m_blocking(blocking)
	{
	}

protected:
	ConnectionResult connect(const AddressInfoList& addressInfoList) noexcept override
	{
		for (const addrinfo* addressInfo :
			 addressInfoList.getAddressInfoRange() | AddressInfoList::skipNonInetFamily()) {
			std::optional<process::FileDescriptor> fileDescriptor = makeSocket(*addressInfo);
			if (!fileDescriptor.has_value()) {
				continue;
			}

			if (!m_blocking) {
				setNonBlockingMode(*fileDescriptor);
			}

			return ConnectionResult(process::FileDescriptor(std::move(*fileDescriptor)));
		}

		return ConnectionResult("Could not resolve hostname.");
	}

private:
	const bool m_blocking;
};

} // namespace ipxp::output::ipfix