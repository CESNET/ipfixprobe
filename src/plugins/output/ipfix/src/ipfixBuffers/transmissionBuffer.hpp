#pragma once

#include "../utils/byteUtils.hpp"

#include <cstddef>
#include <vector>

namespace ipxp::output::ipfix {

class TransmissionBuffer {
public:
	explicit TransmissionBuffer() { m_buffer.reserve(MAXIMAL_TRANSMISSION_UNIT); }

	utils::ByteWriter getWriter() noexcept { return utils::ByteWriter::makeByteWriter(m_buffer); }

    void reset() noexcept { m_buffer.clear(); }

    std::span<const std::byte> getData() const noexcept
    {
        return std::span<const std::byte>(m_buffer.data(), m_buffer.size());
    }

private:
	constexpr static std::size_t MAXIMAL_TRANSMISSION_UNIT = 1500;
	std::vector<std::byte> m_buffer;
};

} // namespace ipxp::output::ipfix