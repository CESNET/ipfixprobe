#pragma once

#include "outputStorage.hpp"
#include "threadAffinitySetter.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageReader {
	template<typename T>
	friend class OutputStorageReaderGroup;

public:
	ElementType* read() noexcept
	{
		if (m_container == nullptr || m_readElements == m_container->storage.size()) {
			m_container = m_storage->read(m_readerIndex);
			m_readAttempts++;
			m_readElements = 0;
		}
		if (m_container == nullptr || m_readElements == m_container->storage.size()) {
			return nullptr;
		}
		/*if (++m_container->readTimes > 1) {
			throw std::runtime_error("Read times limit exceeded");
		}*/
		const std::size_t readPosition = m_readElements++;
		return &m_container->storage[readPosition];
	}

	bool finished() noexcept { return m_storage->finished(); }

	uint8_t getReaderIndex() const noexcept { return m_readerIndex; }

private:
	explicit OutputStorageReader(
		const uint8_t readerIndex,
		std::shared_ptr<OutputStorage<ElementType>> storage) noexcept
		: m_readerIndex(readerIndex)
		, m_storage(std::move(storage))
	{
		m_storage->registerReader(readerIndex);
	}

	const uint8_t m_readerIndex;
	std::shared_ptr<OutputStorage<ElementType>> m_storage;
	OutputContainer<ElementType>* m_container {nullptr};
	uint8_t m_readElements {0};
	std::size_t m_readAttempts {0};
};

} // namespace ipxp::output