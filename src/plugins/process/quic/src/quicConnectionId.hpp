/**
 * @file quicConnectionId.hpp
 * @brief Definition of ConnectionId type for QUIC plugin.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include <cstdint>
#include <span>

#include <boost/container/static_vector.hpp>

namespace ipxp::process::quic {

constexpr static std::size_t MAX_CONNECTION_ID_LENGTH = 20;

using ConnectionId = boost::container::static_vector<uint8_t, MAX_CONNECTION_ID_LENGTH>;

} // namespace ipxp::process::quic
