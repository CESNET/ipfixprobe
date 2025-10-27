/**
 * @file quicTemporalStorage.hpp
 * @brief Definition of QUICTemporalStorage for managing QUIC connection IDs and directions.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * Helps to temporarily store connection IDs until the server/client direction is revealed.
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "quicConnectionId.hpp"
#include "quicDirection.hpp"

#include <directionalField.hpp>

namespace ipxp::process::quic {

class QUICTemporalStorage {
	struct TemporaryConnectionIdBuffer {
		DirectionalField<ConnectionId> ids;
	};

public:
	constexpr bool directionIsRevealed() const noexcept { return m_serverRevealed; }

	constexpr void pairDirections(const QUICDirection quicDirection, const Direction flowDirection)
	{
		if (m_serverRevealed) {
			throw std::runtime_error("QUIC direction already revealed");
		}

		m_serverRevealed = true;
		m_serverIsDestination = (flowDirection == Direction::Forward
								 && quicDirection == QUICDirection::CLIENT_TO_SERVER)
			|| (flowDirection == Direction::Reverse
				&& quicDirection == QUICDirection::SERVER_TO_CLIENT);
	}

	void storeConnectionIds(
		const Direction flowDirection,
		std::span<const uint8_t> sourceConnectionId,
		std::span<const uint8_t> destinationConnectionId) noexcept
	{
		m_buffer[flowDirection].ids[Direction::Forward]
			= ConnectionId(sourceConnectionId.begin(), sourceConnectionId.end());
		m_buffer[flowDirection].ids[Direction::Reverse]
			= ConnectionId(destinationConnectionId.begin(), destinationConnectionId.end());
	}

	constexpr ConnectionId& getSourceCID() noexcept
	{
		return m_buffer[m_serverIsDestination ? Direction::Forward : Direction::Reverse]
			.ids[static_cast<Direction>(!m_serverIsDestination)];
	}

	constexpr ConnectionId& getClientCID() noexcept
	{
		return m_buffer[m_serverIsDestination ? Direction::Forward : Direction::Reverse]
			.ids[static_cast<Direction>(m_serverIsDestination)];
	}

private:
	bool m_serverRevealed {false};
	bool m_serverIsDestination {false};
	DirectionalField<TemporaryConnectionIdBuffer> m_buffer;
};

} // namespace ipxp::process::quic
