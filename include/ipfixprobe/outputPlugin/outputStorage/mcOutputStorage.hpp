#pragma once

#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class MCOutputStorage : public OutputStorage<ElementType> {
public:
	explicit MCOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage<ElementType>(writersCount)
	{
		const std::size_t queueStorageSize
			= OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY / writersCount;
		for (std::size_t queueIndex = 0; queueIndex < writersCount; queueIndex++) {
			m_queues.emplace_back(
				std::span<ElementType*>(
					this->m_storage.data() + queueIndex * queueStorageSize,
					queueStorageSize));
		}
		for (std::size_t readerIndex = 0;
			 readerIndex < OutputStorage<ElementType>::MAX_READERS_COUNT;
			 readerIndex++) {
			m_readersData.emplace_back();
		}
	}

	typename OutputStorage<ElementType>::ReaderGroupHandler&
	registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::ranges::for_each(m_queues, [&](Queue& queue) { queue.groupData.emplace_back(); });
		return OutputStorage<ElementType>::registerReaderGroup(groupSize);
	}

	void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		m_readersData[globalReaderIndex]->lastQueueIndex = localReaderIndex;
		OutputStorage<ElementType>::registerReader(
			readerGroupIndex,
			localReaderIndex,
			globalReaderIndex);
	}

	typename OutputStorage<ElementType>::WriteHandler registerWriter() noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);

		lock.unlock();
		return OutputStorage<ElementType>::registerWriter();
	}

	bool write(ElementType* element, const uint8_t writerId) noexcept override
	{
		Queue& queue = m_queues[writerId];
		const std::size_t writeIndex = queue.enqueCount % queue.storage.size();
		if (queue.enqueCount >= queue.storage.size()
			&& queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			queue.cachedLowestHeadIndex = queue.lowestHeadIndex();
		}
		if (queue.enqueCount >= queue.storage.size()
			&& queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			this->m_allocationBuffer->deallocate(element, writerId);
			std::this_thread::yield();
			return false;
		}

		// std::atomic_thread_fence(std::memory_order_seq_cst);
		//  queue.storage[writeIndex].assign(container, *m_allocationBuffer);
		this->m_allocationBuffer->replace(queue.storage[writeIndex], element, writerId);
		std::atomic_thread_fence(std::memory_order_seq_cst);
		queue.enqueCount++;
		return true;
	}

	ElementType* read(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		ReaderData& readerData = m_readersData[globalReaderIndex].get();
		if (readerData.lastReadSuccessful) {
			m_queues[readerData.lastQueueIndex % m_queues.size()]
				.groupData[readerGroupIndex]
				->confirmedIndex++;
		}

		if (readerData.shiftQueue) {
			readerData.shiftQueue = false;
			readerData.lastQueueIndex++;
			// readerData.cachedEnqueCount = 0;
		}
		for (uint8_t queueShifts = 0; queueShifts < this->m_totalWritersCount; queueShifts++) {
			const uint8_t currentQueueIndex = readerData.lastQueueIndex % m_queues.size();
			Queue& queue = m_queues[currentQueueIndex];
			queue.sync(readerGroupIndex);
			const std::size_t dequeCount = queue.groupData[readerGroupIndex]->dequeueCount++;
			const std::size_t d_x = readerData.cachedEnqueCounts[currentQueueIndex];
			const std::size_t d_enqueCount = queue.enqueCount.load();
			if (dequeCount >= readerData.cachedEnqueCounts[currentQueueIndex]) {
				readerData.cachedEnqueCounts[currentQueueIndex] = queue.enqueCount;
			}
			const std::size_t d_y = readerData.cachedEnqueCounts[currentQueueIndex];
			if (dequeCount >= readerData.cachedEnqueCounts[currentQueueIndex]) {
				queue.groupData[readerGroupIndex]->dequeueCount--;
				readerData.lastQueueIndex++;
				readerData.readWithoutShift = 0;
				// readerData.cachedEnqueCount = 0;
				continue;
			}
			readerData.readWithoutShift++;
			// TODO originally was 256
			bool d_s = false;
			if (readerData.readWithoutShift == queue.storage.size()) {
				this->shiftAllQueues();
				d_s = true;
			}
			// std::atomic_thread_fence(std::memory_order_seq_cst);
			const std::size_t readIndex
				= queue.groupData[readerGroupIndex]->headIndex++ % queue.storage.size();
			// std::atomic_thread_fence(std::memory_order_seq_cst);

			auto& y = queue.groupData[readerGroupIndex];
			/*if (readerData.cachedEnqueCounts[currentQueueIndex] > queue.enqueCount) {
				throw std::runtime_error("XXXXX");
			}*/

			readerData.lastReadSuccessful = true;
			return queue.storage[readIndex];
		}
		readerData.lastReadSuccessful = false;
		std::this_thread::yield();
		return nullptr;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !this->writersPresent()
			&& std::ranges::all_of(m_queues, [&](const Queue& queue) { return queue.finished(); });
	}

protected:
	struct ReaderData {
		// uint64_t cachedEnqueCount {0};
		std::atomic<uint16_t> readWithoutShift {0};
		std::array<uint64_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT> cachedEnqueCounts;
		uint8_t lastQueueIndex {0};
		bool shiftQueue {false};
		bool lastReadSuccessful {false};
	};

	struct GroupData {
		std::atomic<uint64_t> dequeueCount {0};
		std::atomic<uint64_t> overcommitCount {0};
		std::atomic<uint64_t> headIndex {0};
		std::atomic<uint64_t> confirmedIndex {0};
		std::atomic<uint64_t> commitedIndex {1};
	};

	struct Queue {
		Queue(std::span<ElementType*> storage) noexcept
			: storage(storage)
		{
		}

		std::size_t lowestHeadIndex() const noexcept
		{
			const auto snapshot
				= groupData | std::views::transform([](const CacheAlligned<GroupData>& groupData) {
					  return groupData->commitedIndex.load(std::memory_order_acquire);
				  })
				| std::ranges::to<boost::container::static_vector<
					std::size_t,
					OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT>>();
			return *std::ranges::min_element(snapshot);
		}

		void sync(const std::size_t readerGroupIndex) noexcept
		{
			const std::size_t confirmedIndex = groupData[readerGroupIndex]->confirmedIndex.load();
			const std::size_t headIndex = groupData[readerGroupIndex]->headIndex.load();
			if (headIndex == confirmedIndex) {
				groupData[readerGroupIndex]->commitedIndex = headIndex;
			}
		}

		bool finished() const noexcept { return lowestHeadIndex() >= enqueCount; }

		std::atomic<uint64_t> enqueCount {0};
		uint64_t cachedLowestHeadIndex {0};
		std::span<ElementType*> storage;
		boost::container::static_vector<
			CacheAlligned<GroupData>,
			OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT>
			groupData;
		std::span<CacheAlligned<GroupData>> d_groupData {groupData.data(), groupData.capacity()};
	};

	void shiftAllQueues() noexcept
	{
		for (CacheAlligned<ReaderData>& readerData : m_readersData) {
			readerData->readWithoutShift = 0;
			readerData->shiftQueue = true;
		}
	}

	std::mutex m_registrationMutex;
	boost::container::static_vector<Queue, OutputStorage<ElementType>::MAX_WRITERS_COUNT> m_queues;
	boost::container::
		static_vector<CacheAlligned<ReaderData>, OutputStorage<ElementType>::MAX_READERS_COUNT>
			m_readersData;
	// uint8_t m_queueShift {0};
};

} // namespace ipxp::output