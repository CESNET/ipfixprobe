#pragma once

#include <array>
#include <format>
#include <string_view>

#include <arpa/inet.h>
#include <netdb.h>

template<>
struct std::formatter<addrinfo> : std::formatter<string_view> {
	auto parse(format_parse_context& context) { return context.begin(); }

	template<typename FormatContext>
	auto format(const addrinfo& addressInfo, FormatContext& context) const
	{
		std::array<char, INET6_ADDRSTRLEN> addressString;
		inet_ntop(
			addressInfo.ai_family,
			(addressInfo.ai_family == AF_INET)
				? static_cast<void*>(&reinterpret_cast<sockaddr_in*>(addressInfo.ai_addr)->sin_addr)
				: static_cast<void*>(
					  &reinterpret_cast<sockaddr_in6*>(addressInfo.ai_addr)->sin6_addr),
			addressString.data(),
			addressString.size());
		return std::format_to(context.out(), "{}", addressString.data());
	}
};