#pragma once

#include <cstdint>
#include <span>
#include <optional>

#include "quicInitialSecrets.hpp"

namespace ipxp
{
    
struct QUICInitialHeaderView {
public:
    constexpr static std::size_t MAX_EXPANDED_LABEL_LENGTH = 40;
    constexpr static std::size_t SAMPLE_LENGTH = 16;
    constexpr static std::size_t SHA2_256_LENGTH = 32;

    constexpr static std::size_t MAX_BUFFER_SIZE = 1500;

    using ReassembledFrame 
        = boost::container::static_vector<std::byte, MAX_BUFFER_SIZE>;

    using TLSExtensionBuffer 
        = boost::container::static_vector<std::byte, MAX_BUFFER_SIZE>;

    enum class FrameType : uint8_t{
		CRYPTO = 0x06,
		PADDING = 0x00,
		PING = 0x01,
		ACK1 = 0x02,
		ACK2 = 0x03,
		CONNECTION_CLOSE1 = 0x1C,
		CONNECTION_CLOSE2 = 0x1D
	};

    constexpr static
    std::optional<QUICInitialHeaderView> createFrom(
        std::span<const std::byte> payload,
        const PacketType packetType,
        const std::byte headerForm,
        std::span<const std::byte> salt,
        std::span<const std::byte> destConnectionId) noexcept;
private:
    constexpr static std::size_t MAX_TLS_EXTENSIONS = 30;

    std::optional<QUICInitialSecrets> m_initialSecrets;
    ReassembledFrame m_reassembledFrame;
    uint16_t m_serverPort;
    bool m_clientHelloParsed{false};
    bool m_saveWholeTLSExtension{false};
    TLSExtensionBuffer m_tlsExtensionBuffer;
    TLSHandshake m_tlsHandshake;
    boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> m_extensionTypes;
    boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> m_extensionLengths;
};

} // namespace ipxp
