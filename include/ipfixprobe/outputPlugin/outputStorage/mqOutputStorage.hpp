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

template<typename ElementType>
class MQOutputStorage : public OutputStorage<ElementType> {
public:
	explicit MQOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage<ElementType>(writersCount)
	{
		ElementType** begin = this->m_storage.data();
		for (const auto _ : std::views::iota(0U, writersCount)) {
			m_queues.emplace_back(
				std::span<ElementType*>(
					begin,
					OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY / writersCount));
			begin += OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY / writersCount;
		}
	}

	typename OutputStorage<ElementType>::WriteHandler registerWriter() noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		lock.unlock();
		return OutputStorage<ElementType>::registerWriter();
	}

	void registerReader(
		const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		OutputStorage<ElementType>::registerReader(
			readerGroupIndex,
			localReaderIndex,
			globalReaderIndex);

		uint8_t currentIndex = localReaderIndex;
		for (uint8_t& index : m_readersData[globalReaderIndex]->queueJumpSequence) {
			index = currentIndex;
			currentIndex += this->m_readerGroupSizes[readerGroupIndex];
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
		OutputStorage<ElementType>::unregisterWriter(writerId);
		m_queues[writerId].setWriterFinished();
	}

	typename OutputStorage<ElementType>::ReaderGroupHandler&
	registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		// m_threadIdToQueueIndexMaps.emplace_back();
		std::ranges::for_each(m_queues, [&](Queue& queue) { queue.addReaderGroup(); });
		return OutputStorage<ElementType>::registerReaderGroup(groupSize);
	}

	bool write(ElementType* element, const uint8_t writerId) noexcept override
	{
		if (!m_queues[writerId].tryWrite(
				element,
				*this->m_allocationBuffer,
				this->m_readerGroupsCount,
				3,
				writerId)) {
			return false;
		}
		return true;
	}

	ElementType* read(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		const size_t tries
			= this->m_totalWritersCount / this->m_readerGroupSizes[readerGroupIndex] + 1;
		BackoffScheme backoff(3, 5);
		for (const auto _ : std::views::iota(0U, tries)) {
			const uint8_t sequenceIndex = m_readersData[globalReaderIndex]->sequenceIndex++;
			const uint8_t queueIndex
				= m_readersData[globalReaderIndex]->queueJumpSequence
					  [sequenceIndex % OutputStorage<ElementType>::MAX_WRITERS_COUNT];
			ElementType* element = m_queues[queueIndex].tryRead(readerGroupIndex);
			if (element != nullptr) {
				return element;
			}
			std::this_thread::yield();
			// backoff.backoff();
		}
		return nullptr;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return this->m_readerGroupSizes[readerGroupIndex] > this->m_totalWritersCount
			|| (!this->writersPresent() && std::ranges::all_of(m_queues, [&](const Queue& queue) {
				   return queue.finished();
			   }));
	}

protected:
	struct QueueIndex {
		const uint16_t initialOffset;
		uint8_t loops;
	};

	class Queue {
	public:
		explicit Queue(std::span<ElementType*> allocatedSpace) noexcept
			: m_buffersSize(allocatedSpace.size() / 2)
		{
			/*m_buffers[0] = {allocatedSpace.data(), allocatedSpace.size() / 2};
			m_buffers[1]
				= {allocatedSpace.data() + allocatedSpace.size() / 2, allocatedSpace.size() / 2};*/
			// m_writeBuffer.reserve(capacity);
			//  m_readBuffer.reserve(capacity);
			m_stateBuffer.setNewValue(
				State {
					.written = 0,
					.readBuffer = {allocatedSpace.data(), m_buffersSize},
					.writeBuffer = {allocatedSpace.data() + m_buffersSize, m_buffersSize},
					.readerGroupPositions = {},
				});
		}

		bool tryWrite(
			ElementType* element,
			AllocationBufferBase<ElementType>& origin,
			const uint8_t readerGroupCount,
			const std::size_t longBackoffTries,
			const uint8_t writerId) noexcept
		{
			State* currentState = &m_stateBuffer.getCurrentValue();

			if (currentState->written == m_buffersSize) {
				BackoffScheme backoff(7, longBackoffTries);
				while (!allReadersFinished()) {
					if (!backoff.backoff()) {
						origin.deallocate(element, writerId);
						return false;
					}
				}
				// WriteLockGuard lockGuard(m_lock);
				m_stateBuffer.setNewValue(
					State {
						.written = 0,
						.readBuffer = currentState->writeBuffer,
						.writeBuffer = currentState->readBuffer,
						.readerGroupPositions
						= decltype(currentState->readerGroupPositions)(readerGroupCount),
					});
				currentState = &m_stateBuffer.getCurrentValue();
			}
			origin.replace(currentState->writeBuffer[currentState->written], element, writerId);
			currentState->written++;
			return true;
		}

		ElementType* tryRead(const std::size_t readerGroupIndex) noexcept
		{
			State& currentState = m_stateBuffer.getCurrentValue();
			const uint64_t readPos = currentState.readerGroupPositions[readerGroupIndex]->fetch_add(
				1,
				std::memory_order_acq_rel);
			if (readPos >= m_buffersSize) {
				const uint64_t readPosOfWriteBuffer = readPos - m_buffersSize;
				/*std::println(
					std::cout,
					"WRP {}, RP {}, written {}",
					readPosOfWriteBuffer,
					readPos,
					currentState.written);*/
				if (m_writerFinished.load(std::memory_order_acquire)
					&& readPosOfWriteBuffer < currentState.written) [[unlikely]] {
					return currentState.writeBuffer[readPosOfWriteBuffer];
				}
				return nullptr;
			}
			ElementType* res = currentState.readBuffer[readPos];
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
						   return readPos->load(std::memory_order_acquire) >= 2 * m_buffersSize;
					   });
		}

	private:
		struct State {
			uint64_t written;
			std::span<ElementType*> readBuffer;
			std::span<ElementType*> writeBuffer;
			boost::container::static_vector<
				CacheAlligned<std::atomic<uint64_t>>,
				OutputStorage<ElementType>::MAX_READERS_COUNT>
				readerGroupPositions;

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

		bool allReadersFinished() const noexcept
		{
			const State& currentState = m_stateBuffer.getCurrentValue();
			return std::ranges::all_of(
				currentState.readerGroupPositions,
				[&](const CacheAlligned<std::atomic<uint64_t>>& readPos) {
					return readPos->load(std::memory_order_acquire) > m_buffersSize;
				});
		}

		std::atomic<bool> m_writerFinished {false};
		DoubleBufferedValue<State> m_stateBuffer;
		const std::size_t m_buffersSize;
	};

	std::mutex m_registrationMutex;
	boost::container::static_vector<Queue, OutputStorage<ElementType>::MAX_WRITERS_COUNT> m_queues;
	struct ReaderData {
		std::array<uint8_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT> queueJumpSequence;
		uint8_t sequenceIndex {0};
	};

	std::array<CacheAlligned<ReaderData>, OutputStorage<ElementType>::MAX_READERS_COUNT>
		m_readersData;
};

} // namespace ipxp::output