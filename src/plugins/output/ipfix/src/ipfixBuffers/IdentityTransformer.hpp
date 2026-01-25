#pragma once

#include "../utils/byteUtils.hpp"
#include "bufferTransformer.hpp"

namespace ipxp::output::ipfix {

/**
 * @class IdentityTransformer
 * @brief A buffer transformer that performs no transformation and transits input data to output
 * without any modification.
 */
class IdentityTransformer : public BufferTransformer {
public:
	explicit IdentityTransformer(utils::ByteWriter outputWriter)
		: BufferTransformer(std::move(outputWriter))
	{
	}

	virtual ~IdentityTransformer() = default;

	bool transformBuffer() noexcept override { return true; }

	void reset() noexcept override {}

	utils::ByteWriter getWriter() noexcept override { return m_outputWriter; }
};

} // namespace ipxp::output::ipfix