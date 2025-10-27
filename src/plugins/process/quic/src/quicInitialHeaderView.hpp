/**
 * @file quicInitialHeaderView.hpp
 * @brief Declaration of QUICInitialHeaderView for parsing QUIC Initial packet headers.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "quicContext.hpp"
#include "quicHeaderView.hpp"
#include "quicInitialSecrets.hpp"

#include <cstdint>
#include <optional>
#include <span>

#include <tlsParser/tlsHandshake.hpp>
#include <tlsParser/tlsParser.hpp>

namespace ipxp::process::quic {

struct QUICInitialHeaderView {
public:
	constexpr static std::size_t MAX_EXPANDED_LABEL_LENGTH = 40;
	constexpr static std::size_t SAMPLE_LENGTH = 16;
	constexpr static std::size_t SHA2_256_LENGTH = 32;

	constexpr static std::size_t MAX_BUFFER_SIZE = 1500;
	constexpr static std::size_t MAX_HEADER_SIZE = 67 + 256;

	using ReassembledFrame = boost::container::static_vector<std::byte, MAX_BUFFER_SIZE>;

	using TLSExtensionBuffer
		= boost::container::static_vector<std::byte, QUICContext::MAX_TLS_PAYLOAD_TO_SAVE>;

	using DeobfuscatedHeader = boost::container::static_vector<std::byte, MAX_HEADER_SIZE>;

	using DecryptedPayload
		= boost::container::static_vector<std::byte, QUICInitialHeaderView::MAX_BUFFER_SIZE>;

	enum class FrameType : uint8_t {
		CRYPTO = 0x06,
		PADDING = 0x00,
		PING = 0x01,
		ACK1 = 0x02,
		ACK2 = 0x03,
		CONNECTION_CLOSE1 = 0x1C,
		CONNECTION_CLOSE2 = 0x1D
	};

	static std::optional<QUICInitialHeaderView> createFrom(
		std::span<const std::byte> payload,
		const std::byte headerForm,
		std::span<const std::byte> salt,
		std::span<const uint8_t> destConnectionId,
		const QUICVersion version,
		const std::size_t primaryHeaderLength) noexcept;

	constexpr static std::size_t MAX_TLS_EXTENSIONS = 30;

	std::optional<QUICInitialSecrets> m_initialSecrets;
	ReassembledFrame m_reassembledFrame;
	// uint16_t m_serverPort;
	bool clientHelloParsed {false};
	bool m_saveWholeTLSExtension {false};

	TLSExtensionBuffer tlsExtensionBuffer;
	TLSHandshake tlsHandshake;
	std::optional<uint64_t> tokenLength;
	std::optional<QUICContext::ServerName> serverName;
	std::optional<QUICContext::UserAgent> userAgent;
	boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> extensionTypes;
	boost::container::static_vector<uint16_t, MAX_TLS_EXTENSIONS> extensionLengths;
	std::vector<std::byte> extensionsPayload;

	std::span<const uint8_t> sourceConnectionId;
	std::span<const uint8_t> destinationConnectionId;

	std::size_t getLength() const noexcept;

private:
	bool parse(
		std::span<const std::byte> payload,
		std::span<const uint8_t> destConnectionId,
		std::span<const std::byte> salt,
		std::span<const std::byte> sample,
		const std::byte headerForm,
		const QUICVersion version,
		const std::byte* encryptedPacketNumber,
		const std::size_t primaryHeaderLength) noexcept;

	bool parseTLS(const ReassembledFrame& reassembledFrame) noexcept;

	bool parseTLSExtensions(TLSParser& parser) noexcept;

	std::size_t m_size {0};
};

} // namespace ipxp::process::quic
