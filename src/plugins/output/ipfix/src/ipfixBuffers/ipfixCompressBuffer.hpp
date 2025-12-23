/**
 * @file ipfixCompressBuffer.hpp
 * @brief Buffer for compressed IPFIX messages
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * IPFIX buffer for storing IPFIX messages before transmission to the collector. Compresses data
 * before passing them to user
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#pragma once

#include "ipfixBuffer.hpp"
#include "lz4Header.hpp"

#include <chrono>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

#include <arpa/inet.h>
#include <lz4.h>

namespace ipxp::output::ipfix {

/**
 * @class IPFIXCompressBuffer
 * @brief Class representing a compressed IPFIX buffer for storing and managing IPFIX messages.
 *
 * This class extends the IPFIXBuffer class to provide functionality for compressing IPFIX data
 * before transmission. It uses LZ4 compression to reduce the size of the data being sent to the
 * collector.
 */
class IPFIXCompressBuffer : public IPFIXBuffer {
public:
	/**
	 * @struct IPFIXCompressBufferConfig
	 * @brief Configuration structure for IPFIXCompressBuffer.
	 */
	struct IPFIXCompressBufferConfig {
		std::size_t initialUncompressedSize; /// Initial size of the uncompressed data buffer.
		std::size_t initialCompressedSize; /// Initial size of the compressed data buffer.
	};

	/**
	 * @brief Constructs an IPFIXCompressBuffer with the specified configuration and observation
	 * domain ID.
	 * @param config Configuration for the IPFIXCompressBuffer.
	 * @param observationDomainId Observation domain ID for the IPFIX messages.
	 */
	IPFIXCompressBuffer(
		const IPFIXCompressBufferConfig& config,
		const uint32_t observationDomainId) noexcept;

	/**
	 * @brief Checks if adding new set to the buffer will make it possible to send it without
	 * fragmentation.
	 * @param newSetLength Length of the new set to be added.
	 * @return True if the new set will fit into the MTU, false otherwise.
	 */
	bool newSetWillFitIntoMTU(const std::size_t newSetLength) const noexcept override;

	/**
	 * @brief Gets the transmission buffer. Contains compressed data to be sent to the collector.
	 * Should be called once before trnasmission.
	 * @return A span of bytes representing the compressed transmission buffer.
	 */
	std::span<const std::byte> getTransmissionBuffer() noexcept override;

	/**
	 * @brief Resets the buffer to an initial state, including the compression stream.
	 */
	void reset() noexcept override;

private:
	std::unique_ptr<LZ4_stream_t, decltype(&LZ4_freeStream)> m_lz4Stream {
		LZ4_createStream(),
		&LZ4_freeStream};

	std::vector<std::byte> m_compressedData;
	// std::size_t m_lastMessageOffset {0};
	// IPFIXMessageHeader* m_lastMessage {nullptr};
};

} // namespace ipxp::output::ipfix