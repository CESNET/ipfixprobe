/**
 * @file ipfixCompressBuffer.cpp
 * @brief Buffer for compressed IPFIX messages
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * IPFIX buffer for storing IPFIX messages before transmission to the collector. Compresses data
 * before passing them to user
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "ipfixCompressBuffer.hpp"

namespace ipxp::output::ipfix {

IPFIXCompressBuffer::IPFIXCompressBuffer(
	const IPFIXCompressBufferConfig& config,
	const uint32_t observationDomainId) noexcept
	: IPFIXBuffer(config.initialUncompressedSize, observationDomainId)
{
	if (!m_lz4Stream) {
		throw std::runtime_error("Failed to create LZ4 stream for IPFIX compressed buffer.");
	}

	m_uncompressedData.reserve(config.initialUncompressedSize);
	m_compressedData.reserve(config.initialCompressedSize);
}

bool IPFIXCompressBuffer::newSetWillFitIntoMTU(const std::size_t newSetLength) const noexcept
{
	return LZ4_compressBound(newBufferLength(newSetLength)) <= MAXIMAL_TRANSMISSION_UNIT;
}

std::span<const std::byte> IPFIXCompressBuffer::getTransmissionBuffer() noexcept
{
	constexpr static uint64_t Lz4MagicNumber = 0x4c5a3463;
	m_compressedData.resize(LZ4_compressBound(m_uncompressedData.size()) + sizeof(LZ4Header));
	*reinterpret_cast<LZ4Header*>(m_compressedData.data()) = LZ4Header {
		.magicNumber = htonl(static_cast<uint32_t>(Lz4MagicNumber)),
		.size = htonl(static_cast<uint32_t>(m_uncompressedData.size()))};

	std::span<char> compressionBuffer(
		reinterpret_cast<char*>(m_compressedData.data() + sizeof(LZ4Header)),
		m_compressedData.size() - sizeof(LZ4Header));
	LZ4_compress_fast_continue(
		m_lz4Stream.get(),
		reinterpret_cast<const char*>(m_uncompressedData.data()),
		compressionBuffer.data(),
		static_cast<int>(m_uncompressedData.size()),
		static_cast<int>(compressionBuffer.size()),
		0 // 0 is default
	);
	return std::span<const std::byte>(m_compressedData.data(), m_compressedData.size());
}

void IPFIXCompressBuffer::reset() noexcept
{
	IPFIXBuffer::reset();
	LZ4_resetStream(m_lz4Stream.get());
}

} // namespace ipxp::output::ipfix