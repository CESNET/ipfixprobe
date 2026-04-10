#pragma once

#include "outputStorage.hpp"
#include "outputStorageReader.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageReaderGroup {
	template<typename T>
	friend class OutputStorageRegistrar;

public:
	OutputStorageReader<ElementType> registerReader() noexcept
	{
		const uint8_t readerIndex = m_readersRegistered++;
		return OutputStorageReader<ElementType>(readerIndex, m_storage);
	}

	OutputStorageReaderGroup(OutputStorageReaderGroup&& other) noexcept
		: m_readerGroupIndex(other.m_readerGroupIndex)
		, m_storage(std::move(other.m_storage))
		, m_readersRegistered(other.m_readersRegistered.load(std::memory_order_acquire))
	{
	}

private:
	OutputStorageReaderGroup(
		const uint8_t readerGroupIndex,
		std::shared_ptr<OutputStorage<ElementType>> storage) noexcept
		: m_readerGroupIndex(readerGroupIndex)
		, m_storage(std::move(storage))
	{
	}

	const uint8_t m_readerGroupIndex;
	std::shared_ptr<OutputStorage<ElementType>> m_storage;
	std::atomic<uint8_t> m_readersRegistered {0};
};

} // namespace ipxp::output