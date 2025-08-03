#pragma once

#include <boost/container/static_vector.hpp>

namespace ipxp
{

struct PacketStatsExport {
	constexpr static std::size_t MAX_SIZE = 30;

	boost::container::static_vector<uint16_t, MAX_SIZE> lengths;
	boost::container::static_vector<TcpFlags, MAX_SIZE> tcpFlags;
	boost::container::static_vector<uint64_t, MAX_SIZE> timestamps;
	boost::container::static_vector<int8_t, MAX_SIZE> directions;
};  

} // namespace ipxp

