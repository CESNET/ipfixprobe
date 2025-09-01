#pragma once

#include <array>
#include <optional>
#include <span>
#include <boost/static_string/static_string.hpp>
#include <boost/container/static_vector.hpp>

namespace ipxp
{

struct TLSExport {
	constexpr static std::size_t BUFFER_SIZE = 255;
	constexpr static std::size_t JA3_SIZE = 16;
	constexpr static std::size_t JA4_SIZE = 36;
	constexpr static std::size_t MAX_CONNECTION_ID_LENGTH = 20;
	constexpr static std::size_t MAX_EXTENSIONS = 30;

	uint16_t version{0};
	boost::static_string<BUFFER_SIZE> serverALPNs{};
	boost::static_string<BUFFER_SIZE> serverNames{};
	std::array<char, JA3_SIZE> ja3{};
	boost::static_string<JA4_SIZE> ja4{};

	boost::container::static_vector<uint16_t, MAX_EXTENSIONS> extensionTypes {};
	boost::container::static_vector<uint16_t, MAX_EXTENSIONS> extensionLengths {};
};

} // namespace ipxp

