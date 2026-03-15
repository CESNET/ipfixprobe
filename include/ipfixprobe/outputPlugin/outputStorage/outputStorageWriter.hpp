#pragma once

#include "outputStorage.hpp"
#include "threadAffinitySetter.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageWriter {
public:
	explicit OutputStorageWriter(
		const uint8_t writerIndex,
		std::shared_ptr<std::shared_ptr<OutputStorage<ElementType>>[]> storages,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: m_writerIndex(writerIndex)
		, m_storages(storages)
		, m_allocationBuffer(allocationBuffer)
		, m_currentContainer(*allocationBuffer->allocate(writerIndex))
	{
		m_currentContainer.getData().storage.clear();
		m_currentContainer.getData().readTimes = 0;
		m_allocationBuffer->registerWriter(writerIndex);
		for (std::size_t i = 0; i < OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT; ++i) {
			OutputStorage<ElementType>* storage = m_storages[i].get();
			if (!storage) {
				break;
			}
			storage->registerWriter(writerIndex);
		}
	}

	~OutputStorageWriter() noexcept
	{
		for (std::size_t i = 0; i < OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT; ++i) {
			OutputStorage<ElementType>* storage = m_storages[i].get();
			if (!storage) {
				break;
			}
			storage->unregisterWriter(m_writerIndex);
		}
		m_allocationBuffer->unregisterWriter(m_writerIndex);
	}

	void push(ElementType element) noexcept
	{
		/*if (m_currentContainer.getData().storage.size() != 0) {
			throw std::runtime_error("ZZZ");
		}*/
		m_currentContainer.getData().storage.emplace_back(std::move(element));
		if (m_currentContainer.getData().storage.size() == OutputContainer<ElementType>::SIZE) {
			write(m_currentContainer);
			m_writeAttempts++;
			m_currentContainer.assign(
				Reference<OutputContainer<ElementType>>(
					*m_allocationBuffer->allocate(m_writerIndex)),
				[&](ReferenceCounter<OutputContainer<ElementType>>* counter) {
					m_allocationBuffer->deallocate(counter, m_writerIndex);
				});
			m_currentContainer.getData().storage.clear();
			// m_currentContainer.getData().readTimes = 0;
		}
	}

private:
	bool write(const Reference<OutputContainer<ElementType>>& element) noexcept
	{
		bool allWritten = true;
		for (std::size_t i = 0; i < OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT; ++i) {
			OutputStorage<ElementType>* storage = m_storages[i].get();
			if (!storage) {
				break;
			}
			allWritten &= storage->write(element, m_writerIndex);
		}

		return allWritten;
	}

	const uint8_t m_writerIndex;
	std::shared_ptr<std::shared_ptr<OutputStorage<ElementType>>[]> m_storages;
	std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
		m_allocationBuffer;
	Reference<OutputContainer<ElementType>> m_currentContainer;
	std::size_t m_writeAttempts {0};
};

} // namespace ipxp::output