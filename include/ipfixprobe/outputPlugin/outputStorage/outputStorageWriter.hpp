#pragma once

#include "outputStorage.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageWriter {
	explicit OutputStorageWriter(
		const uint8_t writerIndex,
		std::shared_ptr<std::shared_ptr<OutputStorage<ElementType>>[]> storages,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: m_writerIndex(writerIndex)
		, m_storages(storages)
		, m_allocationBuffer(allocationBuffer)
		, m_currentContainer(allocationBuffer->allocate(writerIndex))
	{
		m_allocationBuffer->registerWriter();
		for (auto& storage : *m_storages) {
			if (!storage) {
				break;
			}
			storage->registerWriter(writerIndex);
		}
	}

	~OutputStorageWriter() noexcept
	{
		for(auto& storage : *m_storages) {
			if (!storage) {
				break;
			}
			storage->unregisterWriter(m_writerIndex);
		}
		m_allocationBuffer->unregisterWriter();
	}

	void push(ElementType* element) noexcept
	{
		m_currentContainer->data.emplace_back(element);
		if (m_currentContainer->full()) {
			write(m_currentContainer);
			m_currentContainer = m_allocationBuffer->allocate(m_writerIndex);
		}
	}

	bool write(ElementType* element) noexcept
	{
		bool allWritten = true;
		for (auto& storage : *m_storages) {
			if (!storage) {
				break;
			}
			allWritten &= storage->write(m_writerIndex, element);
		}

		return allWritten;
	}

private:
	const uint8_t m_writerIndex;
	std::shared_ptr<std::shared_ptr<OutputStorage<ElementType>>[]> m_storages;
	std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
		m_allocationBuffer;
	OutputContainer<ElementType>* m_currentContainer;
};

} // namespace ipxp::output