#pragma once

#include "outputStorage.hpp"
#include "outputStorageReader.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageReaderGroup {
public:
	OutputStorageReaderGroup(
		const uint8_t readerGroupIndex,
		std::shared_ptr<OutputStorage<ElementType>> storage) noexcept
		: m_readerGroupIndex(readerGroupIndex)
		, m_storage(std::move(storage))
	{
	}

	OutputStorageReader<ElementType> registerReader() noexcept
	{
		const uint8_t readerIndex = m_readersRegistered++;
		return OutputStorageReader<ElementType>(m_readerGroupIndex, readerIndex, m_storage);
	}

private:
	const uint8_t m_readerGroupIndex;
	std::shared_ptr<OutputStorage<ElementType>> m_storage;
	std::atomic<uint8_t> m_readersRegistered {0};
};

} // namespace ipxp::output