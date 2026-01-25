#pragma once

#include "transportProtocol.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <expected>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netdb.h>

namespace ipxp::output::ipfix {

class AddressInfoList {
public:
	static std::expected<AddressInfoList, std::string> makeAddressInfoList(
		std::string_view host,
		std::string_view port,
		const TransportProtocol protocol) noexcept
	{
		std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addressInfo {nullptr, &::freeaddrinfo};
		addrinfo hints {};
		hints.ai_flags = AI_ADDRCONFIG;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = protocol == TransportProtocol::UDP ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = protocol == TransportProtocol::UDP ? IPPROTO_UDP : IPPROTO_TCP;

		if (const int errorCode
			= getaddrinfo(host.data(), port.data(), &hints, std::out_ptr(addressInfo))) {
			return std::unexpected(
				errorCode == EAI_SYSTEM ? ::strerror(errno) : ::gai_strerror(errorCode));
		}

		return AddressInfoList(std::move(addressInfo));
	}

	auto getAddressInfoRange() const noexcept
	{
		return std::views::repeat(std::ignore)
			| std::views::transform([current = m_addressInfo.get()](auto) mutable {
				   const addrinfo* res = current;
				   if (current != nullptr) {
					   current = current->ai_next;
				   }
				   return res;
			   })
			| std::views::take_while([](const addrinfo* current) { return current != nullptr; });
	}

	static auto skipNonInetFamily() noexcept
	{
		return std::views::filter([](const addrinfo* addressInfo) {
			return addressInfo->ai_family == AF_INET || addressInfo->ai_family == AF_INET6;
		});
	}

	explicit AddressInfoList(AddressInfoList&& other) noexcept
	{
		m_addressInfo = std::move(other.m_addressInfo);
	}

private:
	explicit AddressInfoList(
		std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addressInfo) noexcept
		: m_addressInfo(std::move(addressInfo))
	{
	}

	std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> m_addressInfo {nullptr, &::freeaddrinfo};
};

} // namespace ipxp::output::ipfix