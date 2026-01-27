#pragma once

#include "doubleBufferedValue.hpp"
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

	OutputStorage::WriteHandler registerWriter() noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_threadIdToWriterIndexMap.emplace(getThreadId(), m_threadIdToWriterIndexMap.size());
		std::cout << "Registered writer with thread ID " << getThreadId() << "\n";
		m_writersRegistered++;
		m_allReadersRegisteredCondition.notify_all();
		m_allReadersRegisteredCondition.wait(lock, [&]() {
			return m_writersRegistered == m_totalWritersCount;
		});
		lock.unlock();
		m_allReadersRegisteredCondition.notify_all();
		return OutputStorage::registerWriter();
	}

	void registerReader(
		const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		OutputStorage::registerReader(readerGroupIndex, localReaderIndex, globalReaderIndex);

		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_threadIdToQueueIndexMaps[readerGroupIndex].emplace(
			getThreadId(),
			QueueIndex {
				static_cast<uint16_t>(m_threadIdToQueueIndexMaps[readerGroupIndex].size()),
				0});
		m_readersRegisteredInGroup.resize(
			std::max<uint8_t>(m_readersRegisteredInGroup.size(), readerGroupIndex + 1));
		m_readersRegisteredInGroup[readerGroupIndex]++;
		m_allReadersRegisteredCondition.wait(lock, [&]() {
			return m_readersRegisteredInGroup[readerGroupIndex]
				== m_readerGroupSizes[readerGroupIndex];
		});
		m_allReadersRegisteredCondition.notify_all();
	}

	ReaderGroupHandler& registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		m_threadIdToQueueIndexMaps.emplace_back();
		std::ranges::for_each(m_queues, [&](Queue& queue) { queue.addReaderGroup(); });
		return OutputStorage::registerReaderGroup(groupSize);
	}

	void storeContainer(
		ContainerWrapper container,
		[[maybe_unused]] const uint8_t writerId) noexcept override
	{
		const uint16_t writeQueueIndex = m_threadIdToWriterIndexMap.at(getThreadId());
		// WriteLockGuard lockGuard(m_locks[writeQueueIndex]);
		m_queues[writeQueueIndex].tryWrite(std::move(container), *m_allocationBuffer);
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		auto& [initialOffset, loops]
			= m_threadIdToQueueIndexMaps[readerGroupIndex].at(getThreadId());
		loops++;
		if (static_cast<std::size_t>(loops * m_readerGroupSizes[readerGroupIndex] + initialOffset)
			>= m_queues.size()) {
			loops = 0;
		}
		const uint16_t offset = initialOffset + loops * m_readerGroupSizes[readerGroupIndex];
		// ReadLockGuard lockGuard(m_locks[offset]);
		ReadLockGuard lockGuard = m_queues[offset].lockRead();
		ContainerWrapper* container = m_queues[offset].tryRead(readerGroupIndex);
		if (container != nullptr) {
			if (container->empty()) {
				throw std::runtime_error("Should not happen");
			}
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
		explicit Queue(const std::size_t capacity) noexcept
		{
			m_writeBuffer.reserve(capacity);
			m_readBuffer.reserve(capacity);
			m_stateBuffer.setNewValue(
				State {
					.readBuffer = &m_readBuffer,
					.writeBuffer = &m_writeBuffer,
					.readerGroupPositions = {}});
		}

		bool tryWrite(
			ContainerWrapper container,
			AllocationBufferBase<ReferenceCounter<OutputContainer>>& origin) noexcept
		{
			State& currentState = m_stateBuffer.getCurrentValue();

			if (currentState.writeBuffer->size() == currentState.writeBuffer->capacity()) {
				if (std::ranges::all_of(
						currentState.readerGroupPositions,
						[&](const uint32_t readPos) {
							return readPos == currentState.readBuffer->size();
						})) {
					// while (m_spinlock.test_and_set(std::memory_order_acquire)) {}
					WriteLockGuard lockGuard(m_lock);
					// std::cout << "OOH AAH I'M SWAPPING\n";
					m_stateBuffer.setNewValue(
						State {
							.readBuffer = currentState.writeBuffer,
							.writeBuffer = currentState.readBuffer,
							.readerGroupPositions = boost::container::static_vector<uint32_t, 4>(
								currentState.readerGroupPositions.size(),
								0)});
					m_swapped++;

					std::ranges::for_each(
						*currentState.readBuffer,
						[&origin](ContainerWrapper& wrapper) { wrapper.deallocate(origin); });
					currentState.readBuffer->clear();
				}
				container.deallocate(origin);
				return false;
			}
			currentState.writeBuffer->emplace_back(std::move(container));
			return true;
		}

		ContainerWrapper* tryRead(const std::size_t readerGroupIndex) noexcept
		{
			State& currentState = m_stateBuffer.getCurrentValue();
			if (currentState.readerGroupPositions[readerGroupIndex]
				== currentState.readBuffer->size()) {
				return nullptr;
			}
			// std::cout << "Reader " + std::to_string(readerGroupIndex) + " reading position "
			//		+ std::to_string(currentState.readerGroupPositions[readerGroupIndex]) + "\n";
			ContainerWrapper* res
				= &(*currentState.readBuffer)[currentState.readerGroupPositions[readerGroupIndex]];
			if (res->getContainer().sequenceNumber == 0) {
				std::cout << std::endl;
			}
			if ((size_t) res <= 0x2000) {
				throw std::runtime_error("Should not happen");
			}

			currentState.readerGroupPositions[readerGroupIndex]++;
			return res;
		}

		void addReaderGroup() noexcept
		{
			m_stateBuffer.getCurrentValue().readerGroupPositions.emplace_back(0);
			// m_readerGroupPositions.emplace_back(m_readBuffer.size());
		}

		bool finished() const noexcept
		{
			const State& currentState = m_stateBuffer.getCurrentValue();
			return std::ranges::all_of(
				currentState.readerGroupPositions,
				[&](const uint32_t readPos) { return readPos == currentState.readBuffer->size(); });
		}

		ReadLockGuard lockRead() noexcept { return ReadLockGuard(m_lock); }

	private:
		std::vector<ContainerWrapper> m_readBuffer;
		std::vector<ContainerWrapper> m_writeBuffer;
		uint8_t m_swapped {0};
		RWSpinlock m_lock;

		struct State {
			std::vector<ContainerWrapper>* readBuffer;
			std::vector<ContainerWrapper>* writeBuffer;
			boost::container::static_vector<uint32_t, 4> readerGroupPositions;
		};
		DoubleBufferedValue<State> m_stateBuffer;
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