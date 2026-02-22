#pragma once

#include "outputStorage.hpp"

#include <memory>

namespace ipxp::output {

template<typename ElementType>
class OutputStorageRegistrar {
public:
	explicit OutputStorageRegistrar() noexcept
	{
		m_storages
			= std::make_shared<decltype(m_storages)::element_type[]>(MAX_READER_GROUPS_COUNT);
	}

	OutputStorageReaderGroup registerReaderGroup()
	{
		if (m_storages.size() == MAX_READER_GROUPS_COUNT) {
			throw std::runtime_error("Maximum reader group count reached");
		}
		const uint8_t readerGroupIndex = m_readerGroupsCount++;
		m_storages[readerGroupIndex] = std::make_shared<OutputStorage<ElementType>>();
		return OutputStorageReaderGroup(readerGroupIndex, m_storages[readerGroupIndex]);
		/*m_readerGroupSizes.push_back(groupSize);
		m_readerGroupHandlers
			.emplace_back(groupSize, *this, m_readerGroupsCount, m_readersRegisteredGlobally);
		m_readerGroupsCount++;
		return m_readerGroupHandlers.back();*/
	}

	void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t readerIndex) noexcept
	{
		for (const auto& storage : *m_storages) {
			if (storage) {
				storage->registerReader(readerGroupIndex, readerIndex);
			}
		}
	}

	OutputStorageWriter<ElementType> registerWriter() noexcept
	{
		return OutputStorageWriter<ElementType>(m_storages);
	}

private:
	std::shared_ptr<std::shared_ptr<OutputStorage<ElementType>>[]> m_storages;
	std::atomic<uint8_t> m_readerGroupsCount {0};
};

} // namespace ipxp::output