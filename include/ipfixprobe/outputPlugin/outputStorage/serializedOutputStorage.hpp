#pragma once

#include "outputStorage.hpp"

#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <vector>

namespace ipxp::output {

class SerializedOutputStorage : public OutputStorage {
public:
	explicit SerializedOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage(writersCount)
	{
	}

	ReaderGroupHandler& registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_storageMutex);
		m_readIndex.push_back(m_writeIndex);
		return OutputStorage::registerReaderGroup(groupSize);
	}

	bool storeContainer(
		ContainerWrapper container,
		[[maybe_unused]] const uint8_t writerId) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_storageMutex);
		while (!m_storage[m_writeIndex].empty()
			   && getReferenceCounter(m_storage[m_writeIndex]).hasUsers()) {
			m_writeIndex = (nextIndex(m_writeIndex));
			std::ranges::for_each(m_readIndex, [&](uint16_t& readIdx) {
				readIdx = (nextIndex(readIdx));
			});
		}

		m_storage[m_writeIndex].assign(container, *m_allocationBuffer);
		m_writeIndex = (nextIndex(m_writeIndex));

		std::ranges::for_each(m_readIndex, [&](uint16_t& readIdx) {
			if (readIdx == m_writeIndex) {
				readIdx = (nextIndex(readIdx));
			}
		});
		return true;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_storageMutex);
		if (m_readIndex[readerGroupIndex] == m_writeIndex) {
			return std::nullopt;
		}
		ContainerWrapper& container = m_storage[m_readIndex[readerGroupIndex]];
		m_readIndex[readerGroupIndex] = nextIndex(m_readIndex[readerGroupIndex]);
		return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
			getReferenceCounter(container));
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_storageMutex);
		return !writersPresent() && m_readIndex[readerGroupIndex] == m_writeIndex;
	}

protected:
	std::mutex m_storageMutex;
	std::vector<uint16_t> m_readIndex;
	uint16_t m_writeIndex {0};
};

} // namespace ipxp::output