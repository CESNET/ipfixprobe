#pragma once

#include "../utils/byteUtils.hpp"

namespace ipxp::output::ipfix {

class BufferTransformer {
public:
	virtual ~BufferTransformer() = default;

	virtual utils::ByteWriter getWriter() noexcept = 0;

	virtual bool transformBuffer() noexcept = 0;

	virtual void reset() noexcept = 0;

protected:
	explicit BufferTransformer(utils::ByteWriter outputWriter)
		: m_outputWriter(std::move(outputWriter))
	{
	}

	utils::ByteWriter m_outputWriter;
};

} // namespace ipxp::output::ipfix