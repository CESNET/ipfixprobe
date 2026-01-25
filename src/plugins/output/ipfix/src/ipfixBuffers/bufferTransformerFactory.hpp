#pragma once

#include "CompressTransformer.hpp"
#include "IdentityTransformer.hpp"
#include "bufferTransformer.hpp"

#include <memory>

namespace ipxp::output::ipfix {

class BufferTransformerFactory {
public:
	enum class BufferTransformationType { Identity, LZ4 };

	static std::unique_ptr<BufferTransformer>
	createTransformer(BufferTransformationType type, utils::ByteWriter outputWriter)
	{
		switch (type) {
		case BufferTransformationType::Identity:
			return std::make_unique<IdentityTransformer>(std::move(outputWriter));
		case BufferTransformationType::LZ4:
			return std::make_unique<CompressTransformer>(std::move(outputWriter));
		}

		return nullptr;
	}
};

} // namespace ipxp::output::ipfix