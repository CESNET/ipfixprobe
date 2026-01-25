
#pragma once

#include "connection.hpp"
#include "connectionResult.hpp"

namespace ipxp::output::ipfix {

class ConnectionFactory;

class UDPConnection : public Connection {
	friend class ConnectionFactory;

	UDPConnection(
		std::string host,
		const uint16_t port,
		const std::chrono::duration<uint32_t> reconnectionTimeout,
		const bool verbose) noexcept
		: Connection(std::move(host), port, TransportProtocol::UDP, reconnectionTimeout, verbose)
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

			return ConnectionResult(process::FileDescriptor(std::move(*fileDescriptor)));
		}

		return ConnectionResult("Could not resolve hostname.");
	}
};

} // namespace ipxp::output::ipfix