#pragma once

#include <directionalField.hpp>

#include "quicExport.hpp"
#include "quicDirection.hpp"
namespace ipxp
{
    
class QUICTemporalStorage {
    struct TemporaryConnectionIdBuffer {
		boost::static_string<QUICExport::MAX_CONNECTION_ID_LENGTH> sourceConnectionId;
		boost::static_string<QUICExport::MAX_CONNECTION_ID_LENGTH> destinationConnectionId;
	};

    constexpr bool directionIsRevealed() const noexcept
    {
        return m_serverRevealed;
    }

    constexpr void pairDirections(
        const QUICDirection quicDirection,
        const Direction flowDirection)
    {
        if (m_serverRevealed) {
            throw std::runtime_error("QUIC direction already revealed");
        }

        m_serverRevealed = true;
        m_serverIsDestination = 
            (flowDirection == Direction::Forward &&
                quicDirection == QUICDirection::CLIENT_TO_SERVER) || 
            (flowDirection == Direction::Reverse &&
                quicDirection == QUICDirection::SERVER_TO_CLIENT);

    }

    constexpr
    std::optional<TemporaryConnectionIdBuffer>& getServerData() 
    {
        if (!m_serverRevealed) {
            throw std::runtime_error("QUIC direction is not revealed");
        }
        return m_buffer[m_serverIsDestination ? Direction::Forward : Direction::Reverse];
    }

    constexpr
    std::optional<TemporaryConnectionIdBuffer>& getClientData() 
    {
        if (!m_serverRevealed) {
            throw std::runtime_error("QUIC direction is not revealed");
        }
        return m_buffer[m_serverIsDestination ? Direction::Reverse : Direction::Forward];
    }

private:
    bool m_serverRevealed{false};
    bool m_serverIsDestination{false};
	DirectionalField<std::optional<TemporaryConnectionIdBuffer>> m_buffer;
};



} // namespace ipxp
