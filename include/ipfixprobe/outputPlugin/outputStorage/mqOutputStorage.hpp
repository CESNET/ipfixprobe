#pragma once

#include "outputStorage.hpp"
#include "rwSpinlock.hpp"
#include "threadUtils.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <vector>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

class MQOutputStorage : public OutputStorage {
public:
	explicit MQOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage(writersCount)
	{
		for (const auto _ : std::views::iota(0U, writersCount)) {
			m_queues.emplace_back(OutputStorage::ALLOCATION_BUFFER_CAPACITY / writersCount);
			m_locks.emplace_back();
		}
	}

	void registerWriter() noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		OutputStorage::registerWriter();
		m_threadIdToWriterIndexMap.emplace(getThreadId(), m_threadIdToWriterIndexMap.size());
		m_writersRegistered++;
		m_allReadersRegisteredCondition.wait(lock, [&]() {
			return m_writersRegistered == m_writersCount;
		});
		m_allReadersRegisteredCondition.notify_all();
	}

	void registerReader(const std::size_t readerGroupIndex) noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_threadIdToQueueIndexMaps[readerGroupIndex].emplace(
			getThreadId(),
			QueueIndex {
				static_cast<uint16_t>(m_threadIdToQueueIndexMaps[readerGroupIndex].size()),
				0});
		m_readersRegisteredInGroup.resize(
			std::max(m_readersRegisteredInGroup.size(), readerGroupIndex + 1));
		m_readersRegisteredInGroup[readerGroupIndex]++;
		m_allReadersRegisteredCondition.wait(lock, [&]() {
			return m_readersRegisteredInGroup[readerGroupIndex]
				== m_readerGroupSizes[readerGroupIndex];
		});
		m_allReadersRegisteredCondition.notify_all();
	}

	std::size_t registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		const std::size_t index = OutputStorage::registerReaderGroup(groupSize);
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		if (groupSize > m_writersCount) {
			throw std::runtime_error(
				"MQOutputStorage: reader group size cannot be larger than writers count");
		}
		m_threadIdToQueueIndexMaps.emplace_back();
		std::ranges::for_each(m_queues, [&](Queue& queue) { queue.addReaderGroup(); });
		return index;
	}

	void storeContainer(ContainerWrapper container) noexcept override
	{
		const uint16_t writeQueueIndex = m_threadIdToWriterIndexMap.at(getThreadId());
		WriteLockGuard lockGuard(m_locks[writeQueueIndex]);
		m_queues[writeQueueIndex].tryWrite(std::move(container), *m_allocationBuffer);
	}

	std::optional<ReferenceCounterHandler<OutputContainer>>
	getContainer(const std::size_t readerGroupIndex) noexcept override
	{
		auto& [initialOffset, loops]
			= m_threadIdToQueueIndexMaps[readerGroupIndex].at(getThreadId());
		loops++;
		if (static_cast<std::size_t>(loops * m_readerGroupSizes[readerGroupIndex] + initialOffset)
			>= m_queues.size()) {
			loops = 0;
		}
		const uint16_t offset = initialOffset + loops * m_readerGroupSizes[readerGroupIndex];
		ReadLockGuard lockGuard(m_locks[offset]);
		ContainerWrapper* container = m_queues[offset].tryRead(readerGroupIndex);
		if (container != nullptr) {
			return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
				getReferenceCounter(*container));
		}
		return std::nullopt;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent()
			&& std::ranges::all_of(m_queues, [&](const Queue& queue) { return queue.finished(); });
	}

private:
	struct QueueIndex {
		const uint16_t initialOffset;
		uint8_t loops;
	};

	class Queue {
	public:
		explicit Queue(const std::size_t capacity) noexcept { m_writeBuffer.reserve(capacity); }

		bool tryWrite(
			ContainerWrapper container,
			AllocationBufferBase<ReferenceCounter<OutputContainer>>& origin) noexcept
		{
			if (m_writeBuffer.size() == m_writeBuffer.capacity()) {
				if (std::ranges::all_of(m_readerGroupPositions, [&](const uint16_t readPos) {
						return readPos == m_readBuffer.size();
					})) {
					m_swapped++;
					std::swap(m_readBuffer, m_writeBuffer);
					std::ranges::for_each(m_writeBuffer, [&origin](ContainerWrapper& wrapper) {
						wrapper.deallocate(origin);
					});
					m_writeBuffer.clear();
					std::ranges::for_each(m_readerGroupPositions, [](uint16_t& readPos) {
						readPos = 0;
					});
				}
				container.deallocate(origin);
				return false;
			}
			m_writeBuffer.emplace_back(std::move(container));
			return true;
		}

		ContainerWrapper* tryRead(const std::size_t readerGroupIndex) noexcept
		{
			if (m_readerGroupPositions[readerGroupIndex] == m_readBuffer.size()) {
				return nullptr;
			}

			ContainerWrapper* res = &m_readBuffer[m_readerGroupPositions[readerGroupIndex]];
			if ((size_t) res <= 0x2000) {
				throw std::runtime_error("Should not happen");
			}

			m_readerGroupPositions[readerGroupIndex]++;
			return res;
		}

		void addReaderGroup() noexcept { m_readerGroupPositions.emplace_back(m_readBuffer.size()); }

		bool finished() const noexcept
		{
			return std::ranges::all_of(m_readerGroupPositions, [&](const uint16_t readPos) {
				return readPos == m_readBuffer.size();
			});
		}

	private:
		std::vector<ContainerWrapper> m_readBuffer;
		std::vector<ContainerWrapper> m_writeBuffer;
		std::vector<uint16_t> m_readerGroupPositions;
		uint8_t m_swapped {0};
		uint16_t m_writePosition {0};
	};

	std::mutex m_registrationMutex;
	std::atomic_uint64_t m_queueDistributionIndex;
	boost::container::static_vector<Queue, OutputStorage::MAX_WRITERS_COUNT> m_queues;
	boost::container::static_vector<RWSpinlock, OutputStorage::MAX_WRITERS_COUNT> m_locks;
	boost::container::
		static_vector<std::unordered_map<uint16_t, QueueIndex>, OutputStorage::MAX_WRITERS_COUNT>
			m_threadIdToQueueIndexMaps;
	std::unordered_map<uint16_t, uint16_t> m_threadIdToWriterIndexMap;
	uint16_t m_writeIndex {0};
	std::vector<uint8_t> m_readersRegisteredInGroup;
	std::condition_variable m_allReadersRegisteredCondition;
	uint16_t m_writersRegistered {0};
};

} // namespace ipxp::output