#pragma once

#include "allocationBufferS.hpp"
#include "outputStorage.hpp"
#include "outputStorageReader.hpp"
#include "outputStorageReaderGroup.hpp"
#include "outputStorageWriter.hpp"

#include <memory>

namespace ipxp::output {

template<class StorageType>
class OutputStorageRegistrar {
	using ElementType = typename StorageType::value_type;

public:
	explicit OutputStorageRegistrar(const uint8_t writersCount) noexcept
		: m_expectedWritersCount(writersCount)

	{
		m_storages = std::make_shared<std::shared_ptr<OutputStorage<ElementType>>[]>(
			OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT);
		m_allocationBuffer
			= std::make_shared<AllocationBufferS<ReferenceCounter<OutputContainer<ElementType>>>>(
				OutputStorage<ElementType>::STORAGE_CAPACITY
					* OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT,
				writersCount);
	}

	OutputStorageReaderGroup<ElementType>& registerReaderGroup(const uint8_t readersCount)
	{
		const uint8_t readerGroupIndex = m_readerGroupsCount++;
		if (readerGroupIndex >= OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT) {
			throw std::runtime_error("Maximum reader group count reached");
		}
		m_storages[readerGroupIndex] = std::make_shared<StorageType>(
			m_expectedWritersCount,
			readersCount,
			m_allocationBuffer);
		m_readerGroups.emplace_back(readerGroupIndex, m_storages[readerGroupIndex]);
		return m_readerGroups.back();
	}

	/*void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t readerIndex) noexcept
	{
		for (const auto& storage : *m_storages) {
			if (storage) {
				storage->registerReader(readerGroupIndex, readerIndex);
			}
		}
	}*/

	OutputStorageWriter<ElementType> registerWriter()
	{
		const uint8_t writerIndex = m_activeWritersCount++;
		if (writerIndex >= m_expectedWritersCount) {
			throw std::runtime_error("Maximum writer count reached");
		}
		return OutputStorageWriter<ElementType>(writerIndex, m_storages, m_allocationBuffer);
	}

private:
	std::shared_ptr<std::shared_ptr<OutputStorage<ElementType>>[]> m_storages;
	std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
		m_allocationBuffer;
	std::atomic<uint8_t> m_readerGroupsCount {0};
	std::atomic<uint8_t> m_activeWritersCount {0};
	boost::container::static_vector<
		OutputStorageReaderGroup<ElementType>,
		OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT>
		m_readerGroups;
	const uint8_t m_expectedWritersCount;
};

} // namespace ipxp::output