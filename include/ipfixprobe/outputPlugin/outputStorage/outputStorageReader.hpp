#pragma once

#include "outputStorage.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageReader {
public:
	explicit OutputStorageReader(
		const uint8_t readerIndex,
		std::shared_ptr<OutputStorage<ElementType>> storage) noexcept
		: m_readerIndex(readerIndex)
		, m_storage(std::move(storage))
	{
		m_storage->registerReader(readerIndex);
	}

	ElementType* read() noexcept
	{
		/*if (m_container != nullptr && m_container->storage.size() == 0) {
			throw std::runtime_error("Attempting to read empty container.");
		}
		if (m_container != nullptr && m_readElements > m_container->storage.size()) {
			throw std::runtime_error("!!!!");
			}*/

		// bool x = false;
		//  while (m_container != nullptr && !m_container->written.load()) {};
		if (m_container == nullptr || m_readElements == m_container->storage.size()) {
			m_container = m_storage->read(m_readerIndex);
			// while (m_container != nullptr && !m_container->written.load()) {};

			m_readAttempts++;
			m_readElements = 0;
			// x = true;
		}
		// while (m_container != nullptr && !m_container->written.load()) {};
		if (m_container == nullptr || m_readElements == m_container->storage.size()) {
			return nullptr;
		}

		/*if (m_container == nullptr || m_readElements >= m_container->storage.size()) {
			throw std::runtime_error("????");
		}*/
		// x = m_container->written.load();
		// while (m_container != nullptr && !m_container->written.load()) {};

		/*if (++m_container->readTimes > 1) {
			throw std::runtime_error("Read times limit exceeded");
		}*/
		const std::size_t readPosition = m_readElements++;
		// static void* dummy = nullptr;
		//  return &dummy;
		return &m_container->storage[readPosition];
	}

	bool finished() noexcept { return m_storage->finished(); }

	uint8_t getReaderIndex() const noexcept { return m_readerIndex; }

private:
	const uint8_t m_readerIndex;
	std::shared_ptr<OutputStorage<ElementType>> m_storage;
	OutputContainer<ElementType>* m_container {nullptr};
	uint8_t m_readElements {0};
	std::size_t m_readAttempts {0};
};

} // namespace ipxp::output