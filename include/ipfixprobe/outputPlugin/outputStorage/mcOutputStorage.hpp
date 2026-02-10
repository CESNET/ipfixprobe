#pragma once

#include "outputStorage.hpp"

namespace ipxp::output {

class MCOutputStorage : public OutputStorage {
public:
	explicit MCOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage(writersCount)
	{
		const std::size_t queueStorageSize = ALLOCATION_BUFFER_CAPACITY / writersCount;
		for (std::size_t queueIndex = 0; queueIndex < writersCount; queueIndex++) {
			m_queues.emplace_back(
				std::span<ContainerWrapper> {
					m_storage.data() + queueIndex * queueStorageSize,
					queueStorageSize});
		}
		for (std::size_t readerIndex = 0; readerIndex < MAX_READERS_COUNT; readerIndex++) {
			m_readersData.emplace_back();
		}
	}

	ReaderGroupHandler& registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::ranges::for_each(m_queues, [&](Queue& queue) { queue.groupData.emplace_back(); });
		return OutputStorage::registerReaderGroup(groupSize);
	}

	void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		m_readersData[globalReaderIndex]->lastQueueIndex = localReaderIndex;
		OutputStorage::registerReader(readerGroupIndex, localReaderIndex, globalReaderIndex);
	}

	WriteHandler registerWriter() noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);

		lock.unlock();
		return OutputStorage::registerWriter();
	}

	void storeContainer(ContainerWrapper container, const uint8_t writerId) noexcept override
	{
		Queue& queue = m_queues[writerId];
		const std::size_t writeIndex = queue.enqueCount % queue.storage.size();
		if (queue.enqueCount >= queue.storage.size()
			&& queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			d_writerUpdated++;
			queue.cachedLowestHeadIndex = queue.lowestHeadIndex();
		}
		if (queue.enqueCount >= queue.storage.size()
			&& queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			d_deallocatedContainers++;
			container.deallocate(*m_allocationBuffer);
			return;
		}

		std::atomic_thread_fence(std::memory_order_seq_cst);
		queue.storage[writeIndex].assign(container, *m_allocationBuffer);
		std::atomic_thread_fence(std::memory_order_seq_cst);
		queue.enqueCount++;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
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

		/*auto& confirmedIndexAtomic = m_queues[readerData.lastQueueIndex % m_queues.size()]
										 .groupData[readerGroupIndex]
										 ->confirmedIndex;
		const std::size_t confirmedIndex
			= readerData.lastReadSuccessful ? confirmedIndexAtomic++ : confirmedIndexAtomic.load();
		const std::size_t headIndex = m_queues[readerData.lastQueueIndex % m_queues.size()]
										  .groupData[readerGroupIndex]
										  ->headIndex.load(std::memory_order_acquire);
		if (confirmedIndex + 1 == headIndex) {
			m_queues[readerData.lastQueueIndex % m_queues.size()]
				.groupData[readerGroupIndex]
				->commitedIndex
				= headIndex;
		}*/

		if (readerData.shiftQueue) {
			readerData.shiftQueue = false;
			readerData.lastQueueIndex++;
			readerData.cachedEnqueCount = 0;
		}
		for (uint8_t queueShifts = 0; queueShifts < m_totalWritersCount; queueShifts++) {
			Queue& queue = m_queues[readerData.lastQueueIndex % m_queues.size()];
			const std::size_t dequeCount = queue.groupData[readerGroupIndex]->dequeueCount++;
			const std::size_t d_x = readerData.cachedEnqueCount;
			const std::size_t d_enqueCount = queue.enqueCount.load();
			if (dequeCount >= readerData.cachedEnqueCount) {
				readerData.cachedEnqueCount = queue.enqueCount;
			}
			const std::size_t d_y = readerData.cachedEnqueCount;
			if (dequeCount >= readerData.cachedEnqueCount) {
				queue.groupData[readerGroupIndex]->dequeueCount--;
				readerData.lastQueueIndex++;
				readerData.readWithoutShift = 0;
				readerData.cachedEnqueCount = 0;
				const std::size_t confirmedIndex
					= queue.groupData[readerGroupIndex]->confirmedIndex.load();
				const std::size_t headIndex = queue.groupData[readerGroupIndex]->headIndex.load();
				if (headIndex == confirmedIndex) {
					queue.groupData[readerGroupIndex]->commitedIndex = headIndex;
				}
				continue;
			}
			readerData.readWithoutShift++;
			constexpr std::size_t overreadThreshold = 256;
			bool d_s = false;
			if (readerData.readWithoutShift == overreadThreshold) {
				shiftAllQueues();
				d_s = true;
			}
			std::atomic_thread_fence(std::memory_order_seq_cst);
			const std::size_t readIndex
				= queue.groupData[readerGroupIndex]->headIndex++ % queue.storage.size();
			std::atomic_thread_fence(std::memory_order_seq_cst);

			auto& y = queue.groupData[readerGroupIndex];
			if (readerData.cachedEnqueCount > queue.enqueCount) {
				throw std::runtime_error("XXXXX");
			}
			if (queue.storage[readIndex].empty()) {
				throw std::runtime_error("Should not happen");
			}
			if (queue.storage[readIndex].getContainer().readTimes == 4) {
				throw std::runtime_error("Bad read times");
			}

			readerData.lastReadSuccessful = true;
			return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
				getReferenceCounter(queue.storage[readIndex]));
		}
		d_nulloptsReturned++;
		readerData.lastReadSuccessful = false;
		return std::nullopt;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent()
			&& std::ranges::all_of(m_queues, [&](const Queue& queue) { return queue.finished(); });
	}

private:
	struct ReaderData {
		uint64_t cachedEnqueCount {0};
		std::atomic<uint16_t> readWithoutShift {0};
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
		Queue(std::span<ContainerWrapper> storage) noexcept
			: storage(storage)
		{
		}

		std::size_t lowestHeadIndex() const noexcept
		{
			const auto snapshot
				= groupData | std::views::transform([](const CacheAlligned<GroupData>& groupData) {
					  return groupData->commitedIndex.load(std::memory_order_acquire);
				  })
				| std::ranges::to<
					  boost::container::static_vector<std::size_t, MAX_READER_GROUPS_COUNT>>();
			return *std::ranges::min_element(snapshot);
			auto it = std::ranges::min_element(
				groupData,
				std::ranges::less {},
				[](const CacheAlligned<GroupData>& groupData) {
					return groupData->commitedIndex.load();
				});
			return it->get().commitedIndex.load();
		}

		bool finished() const noexcept
		{
			// xXXXXXXX
			return lowestHeadIndex() >= enqueCount;
		}

		std::atomic<uint64_t> enqueCount {0};
		uint64_t cachedLowestHeadIndex {0};
		std::span<ContainerWrapper> storage;
		boost::container::static_vector<CacheAlligned<GroupData>, MAX_READER_GROUPS_COUNT>
			groupData;
		std::span<CacheAlligned<GroupData>, MAX_READER_GROUPS_COUNT> d_groupData {
			groupData.data(),
			MAX_READER_GROUPS_COUNT};
	};

	void shiftAllQueues() noexcept
	{
		for (CacheAlligned<ReaderData>& readerData : m_readersData) {
			readerData->readWithoutShift = 0;
			readerData->shiftQueue = true;
		}
	}

	std::mutex m_registrationMutex;
	boost::container::static_vector<Queue, MAX_WRITERS_COUNT> m_queues;
	boost::container::static_vector<CacheAlligned<ReaderData>, MAX_READERS_COUNT> m_readersData;
	std::span<CacheAlligned<ReaderData>, MAX_READERS_COUNT> d_readersData {
		m_readersData.data(),
		MAX_READERS_COUNT};
	std::span<Queue> d_queues {m_queues.data(), MAX_WRITERS_COUNT};
	std::atomic<uint64_t> d_nulloptsReturned {0};
	std::atomic<uint64_t> d_writerUpdated {0};
	std::atomic<uint64_t> d_deallocatedContainers {0};
	// uint8_t m_queueShift {0};
};

} // namespace ipxp::output