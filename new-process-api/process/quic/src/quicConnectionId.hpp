#pragma once

#include <cstdint>
#include <span>
#include <boost/container/static_vector.hpp>

namespace ipxp
{
    
constexpr static std::size_t MAX_CONNECTION_ID_LENGTH = 20;

using ConnectionId 
    = boost::container::static_vector<uint8_t, MAX_CONNECTION_ID_LENGTH>;

} // namespace ipxp
