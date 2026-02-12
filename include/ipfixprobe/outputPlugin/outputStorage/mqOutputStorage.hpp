#pragma once

#include "backoffScheme.hpp"
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
		ContainerWrapper* begin = m_storage.data();
		for (const auto _ : std::views::iota(0U, writersCount)) {
			m_queues.emplace_back(
				std::span<ContainerWrapper>(
					begin,
					OutputStorage::ALLOCATION_BUFFER_CAPACITY / writersCount));
			begin += OutputStorage::ALLOCATION_BUFFER_CAPACITY / writersCount;
			// m_locks.emplace_back();
		}
	}

	OutputStorage::WriteHandler registerWriter() noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		// m_threadIdToWriterIndexMap.emplace(getThreadId(), m_threadIdToWriterIndexMap.size());
		/*m_writersRegistered++;
		m_allReadersRegisteredCondition.notify_all();
		m_allReadersRegisteredCondition.wait(lock, [&]() {
			return m_writersRegistered == m_totalWritersCount;
		});
		m_allReadersRegisteredCondition.notify_all();*/
		lock.unlock();
		return OutputStorage::registerWriter();
	}

	void registerReader(
		const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		OutputStorage::registerReader(readerGroupIndex, localReaderIndex, globalReaderIndex);

		uint8_t currentIndex = localReaderIndex;
		for (uint8_t& index : m_readersData[globalReaderIndex]->queueJumpSequence) {
			index = currentIndex;
			currentIndex += m_readerGroupSizes[readerGroupIndex];
			if (currentIndex >= m_queues.size()) {
				currentIndex = localReaderIndex;
			}
		}

		// std::unique_lock<std::mutex> lock(m_registrationMutex);
		/*m_threadIdToQueueIndexMaps[readerGroupIndex].emplace(
			getThreadId(),
			QueueIndex {
				static_cast<uint16_t>(m_threadIdToQueueIndexMaps[readerGroupIndex].size()),
				0});*/
		/*m_readersRegisteredInGroup.resize(
			std::max<uint8_t>(m_readersRegisteredInGroup.size(), readerGroupIndex + 1));
		m_readersRegisteredInGroup[readerGroupIndex]++;*/
		/*m_allReadersRegisteredCondition.wait(lock, [&]() {
			return m_readersRegisteredInGroup[readerGroupIndex]
				== m_readerGroupSizes[readerGroupIndex];
		});
		m_allReadersRegisteredCondition.notify_all();*/
	}

	void unregisterWriter([[maybe_unused]] const uint8_t writerId) noexcept override
	{
		OutputStorage::unregisterWriter(writerId);
		m_queues[writerId].setWriterFinished();
	}

	ReaderGroupHandler& registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		// m_threadIdToQueueIndexMaps.emplace_back();
		std::ranges::for_each(m_queues, [&](Queue& queue) { queue.addReaderGroup(); });
		return OutputStorage::registerReaderGroup(groupSize);
	}

	bool storeContainer(ContainerWrapper container, const uint8_t writerId) noexcept override
	{
		// const uint16_t writeQueueIndex = m_threadIdToWriterIndexMap.at(getThreadId());
		//  WriteLockGuard lockGuard(m_locks[writeQueueIndex]);
		if (!m_queues[writerId]
				 .tryWrite(std::move(container), *m_allocationBuffer, m_readerGroupsCount)) {
			std::this_thread::yield();
			return false;
		}
		return true;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		const size_t tries = MAX_WRITERS_COUNT / m_readerGroupSizes[readerGroupIndex];
		for (const auto _ : std::views::iota(0U, tries)) {
			const uint8_t sequenceIndex = m_readersData[globalReaderIndex]->sequenceIndex++;
			const uint8_t queueIndex = m_readersData[globalReaderIndex]
										   ->queueJumpSequence[sequenceIndex % MAX_WRITERS_COUNT];
			// ReadLockGuard lockGuard(m_locks[offset]);
			// ReadLockGuard lockGuard = m_queues[offset].lockRead();
			ContainerWrapper* container = m_queues[queueIndex].tryRead(readerGroupIndex);
			if (container != nullptr) {
				return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
					getReferenceCounter(*container));
			}
		}
		std::this_thread::yield();
		return std::nullopt;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return m_readerGroupSizes[readerGroupIndex] > m_totalWritersCount
			|| (!writersPresent() && std::ranges::all_of(m_queues, [&](const Queue& queue) {
				   return queue.finished();
			   }));
	}

private:
	struct QueueIndex {
		const uint16_t initialOffset;
		uint8_t loops;
	};

	class Queue {
	public:
		explicit Queue(std::span<ContainerWrapper> allocatedSpace) noexcept
		{
			/*m_buffers[0] = {allocatedSpace.data(), allocatedSpace.size() / 2};
			m_buffers[1]
				= {allocatedSpace.data() + allocatedSpace.size() / 2, allocatedSpace.size() / 2};*/
			// m_writeBuffer.reserve(capacity);
			//  m_readBuffer.reserve(capacity);
			m_stateBuffer.setNewValue(
				State {
					.readBuffer = {allocatedSpace.data(), allocatedSpace.size() / 2},
					.writeBuffer
					= {allocatedSpace.data() + allocatedSpace.size() / 2,
					   allocatedSpace.size() / 2},
					.readerGroupPositions = {},
					.written = 0,
				});
		}

		bool tryWrite(
			ContainerWrapper container,
			AllocationBufferBase<ReferenceCounter<OutputContainer>>& origin,
			const uint8_t readerGroupCount) noexcept
		{
			State* currentState = &m_stateBuffer.getCurrentValue();

			if (currentState->written == currentState->writeBuffer.size()) {
				BackoffScheme backoff(3, 5);
				while (!allReadersFinished()) {
					if (!backoff.backoff()) {
						container.deallocate(origin);
						return false;
					}
				}
				// WriteLockGuard lockGuard(m_lock);
				m_stateBuffer.setNewValue(
					State {
						.readBuffer = currentState->writeBuffer,
						.writeBuffer = currentState->readBuffer,
						.readerGroupPositions
						= decltype(currentState->readerGroupPositions)(readerGroupCount),
						.written = 0,
					});
				currentState = &m_stateBuffer.getCurrentValue();

				/*std::ranges::for_each(
					*currentState.readBuffer,
					[&origin](ContainerWrapper& wrapper) { wrapper.deallocate(origin); });
				currentState.readBuffer->clear();*/
			}
			currentState->writeBuffer[currentState->written].assign(container, origin);
			currentState->written++;
			// currentState.writeBuffer->emplace_back(std::move(container));
			return true;
		}

		ContainerWrapper* tryRead(const std::size_t readerGroupIndex) noexcept
		{
			State& currentState = m_stateBuffer.getCurrentValue();
			const uint64_t readPos = currentState.readerGroupPositions[readerGroupIndex]->fetch_add(
				1,
				std::memory_order_acq_rel);
			if (readPos >= currentState.readBuffer.size()) {
				const uint64_t readPosOfWriteBuffer = readPos - currentState.readBuffer.size();
				/*std::println(
					std::cout,
					"WRP {}, RP {}, written {}",
					readPosOfWriteBuffer,
					readPos,
					currentState.written);*/
				if (m_writerFinished.load(std::memory_order_acquire)
					&& readPosOfWriteBuffer < currentState.written) [[unlikely]] {
					return &currentState.writeBuffer[readPosOfWriteBuffer];
				}
				return nullptr;
			}
			ContainerWrapper* res = &currentState.readBuffer[readPos];
			return res;
		}

		void addReaderGroup() noexcept
		{
			State& currentState = m_stateBuffer.getCurrentValue();
			currentState.readerGroupPositions.emplace_back(currentState.readBuffer.size());
			// m_readerGroupPositions.emplace_back(m_readBuffer.size());
		}

		void setWriterFinished() noexcept
		{
			m_writerFinished.store(true, std::memory_order_release);
		}

		bool finished() const noexcept
		{
			const State& currentState = m_stateBuffer.getCurrentValue();
			return m_writerFinished.load(std::memory_order_acquire)
				&& std::ranges::all_of(
					   m_stateBuffer.getCurrentValue().readerGroupPositions,
					   [&](const CacheAlligned<std::atomic<uint64_t>>& readPos) {
						   return readPos->load(std::memory_order_acquire)
							   >= currentState.readBuffer.size() + currentState.writeBuffer.size();
					   });
		}

		ReadLockGuard lockRead() noexcept { return ReadLockGuard(m_lock); }

	private:
		bool allReadersFinished() const noexcept
		{
			const State& currentState = m_stateBuffer.getCurrentValue();
			return std::ranges::all_of(
				currentState.readerGroupPositions,
				[&](const CacheAlligned<std::atomic<uint64_t>>& readPos) {
					return readPos->load(std::memory_order_acquire)
						> currentState.readBuffer.size();
				});
		}
		// std::vector<ContainerWrapper> m_readBuffer;
		// std::vector<ContainerWrapper> m_writeBuffer;
		// std::span<ContainerWrapper> m_readBuffer;
		// std::span<ContainerWrapper> m_writeBuffer;
		// std::array<std::span<ContainerWrapper>, 2> m_buffers;
		uint8_t m_swapped {0};
		RWSpinlock m_lock;
		std::atomic<bool> m_writerFinished {false};

		struct State {
			std::span<ContainerWrapper> readBuffer;
			std::span<ContainerWrapper> writeBuffer;
			boost::container::static_vector<
				CacheAlligned<std::atomic<uint64_t>>,
				OutputStorage::MAX_READERS_COUNT>
				readerGroupPositions;
			uint64_t written;

			State& operator=(const State& other) noexcept
			{
				readBuffer = other.readBuffer;
				writeBuffer = other.writeBuffer;
				readerGroupPositions.resize(other.readerGroupPositions.size());
				for (std::size_t i = 0; i < other.readerGroupPositions.size(); i++) {
					readerGroupPositions[i]->store(
						other.readerGroupPositions[i]->load(std::memory_order_acquire),
						std::memory_order_release);
				}
				written = other.written;
				return *this;
			}
		};
		DoubleBufferedValue<State> m_stateBuffer;
	};

	std::mutex m_registrationMutex;
	// std::atomic_uint64_t m_queueDistributionIndex;
	boost::container::static_vector<Queue, OutputStorage::MAX_WRITERS_COUNT> m_queues;

	struct ReaderData {
		std::array<uint8_t, OutputStorage::MAX_WRITERS_COUNT> queueJumpSequence;
		uint8_t sequenceIndex {0};
	};

	std::array<CacheAlligned<ReaderData>, MAX_READERS_COUNT> m_readersData;

	/*boost::container::static_vector<RWSpinlock, OutputStorage::MAX_WRITERS_COUNT> m_locks;
	boost::container::
		static_vector<std::unordered_map<uint16_t, QueueIndex>,
	OutputStorage::MAX_WRITERS_COUNT> m_threadIdToQueueIndexMaps; std::unordered_map<uint16_t,
	uint16_t> m_threadIdToWriterIndexMap; uint16_t m_writeIndex {0};* std::vector<uint8_t>
	m_readersRegisteredInGroup; std::condition_variable m_allReadersRegisteredCondition;
	uint16_t m_writersRegistered {0};*/
};

} // namespace ipxp::output