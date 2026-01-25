#pragma once

#include "../utils/byteUtils.hpp"
#include "bufferTransformer.hpp"
#include "lz4Header.hpp"

#include <memory>

#include <arpa/inet.h>
#include <lz4.h>

namespace ipxp::output::ipfix {

/**
 * @class CompressTransformer
 * @brief A buffer transformer that performs compression on the input data before writing to output.
 */
class CompressTransformer : public BufferTransformer {
public:
	explicit CompressTransformer(utils::ByteWriter outputWriter)
		: BufferTransformer(std::move(outputWriter))
	{
		m_buffer.reserve(BUFFER_SIZE);
		CompressTransformer::reset();
	}

	virtual ~CompressTransformer() = default;

	utils::ByteWriter getWriter() noexcept override
	{
		return utils::ByteWriter::makeByteWriter(m_buffer);
	}

	bool transformBuffer() noexcept override
	{
		const std::size_t compressedBufferMaxSize = LZ4_compressBound(m_buffer.size());
		const bool success
			= m_outputWriter.allocateAndWrite(compressedBufferMaxSize, [&](std::byte* buffer) {
				  const uint32_t writtenBytes = LZ4_compress_fast_continue(
					  m_lz4Stream.get(),
					  reinterpret_cast<const char*>(m_buffer.data()),
					  reinterpret_cast<char*>(buffer),
					  static_cast<int>(m_buffer.size()),
					  static_cast<int>(compressedBufferMaxSize),
					  0 // 0 is default
				  );
				  *m_size = htonl(writtenBytes) + ntohl(*m_size);
				  return writtenBytes;
			  });
		m_buffer.clear();
		return success;
	}

	void reset() noexcept override
	{
		m_buffer.clear();
		LZ4_resetStream(m_lz4Stream.get());
		m_outputWriter.allocateAndWrite(sizeof(LZ4Header), [&](std::byte* buffer) {
			*reinterpret_cast<LZ4Header*>(buffer)
				= LZ4Header {.magicNumber = htonl(static_cast<uint32_t>(0x4c5a3463)), .size = 0};
			m_size = &reinterpret_cast<LZ4Header*>(buffer)->size;
			return sizeof(LZ4Header);
		});
	}

private:
	// TODO magic constant
	const static inline std::size_t BUFFER_SIZE = LZ4_compressBound(1500) + sizeof(LZ4Header);
	std::vector<std::byte> m_buffer;
	std::unique_ptr<LZ4_stream_t, decltype(&LZ4_freeStream)> m_lz4Stream {
		LZ4_createStream(),
		&LZ4_freeStream};
	uint32_t* m_size {nullptr};
};

} // namespace ipxp::output::ipfix