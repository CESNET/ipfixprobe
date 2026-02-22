#pragma once

#include "outputStorage.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageReader {
	explicit OutputStorageReader(
		const uint8_t readerIndex,
		std::shared_ptr<OutputStorage<ElementType>> storage) noexcept
		: m_readerIndex(readerIndex)
		, m_storage(std::move(storage))
	{
	}

	ElementType* read() noexcept { return m_storage->read(m_readerIndex); }

	bool finished() noexcept { return m_storage->finished(); }

private:
	const uint8_t m_readerIndex;
	std::shared_ptr<OutputStorage<ElementType>> m_storage;
};

} // namespace ipxp::output