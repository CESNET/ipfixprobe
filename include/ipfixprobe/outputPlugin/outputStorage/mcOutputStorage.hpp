#pragma once

#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class MCOutputStorage : public OutputStorage<ElementType> {
public:
	explicit MCOutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: OutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
	{
		const std::size_t queueStorageSize
			= OutputStorage<ElementType>::STORAGE_CAPACITY / expectedWritersCount;
		for (std::size_t queueIndex = 0; queueIndex < expectedWritersCount; queueIndex++) {
			m_queues.emplace_back(
				std::span<Reference<OutputContainer<ElementType>>>(
					this->m_storage.data() + queueIndex * queueStorageSize,
					queueStorageSize));
		}
		/*for (std::size_t readerIndex = 0;
			 readerIndex < OutputStorage<ElementType>::MAX_READERS_COUNT;
			 readerIndex++) {
			m_readersData.emplace_back();
		}*/
	}

	void registerReader(const uint8_t readerIndex) noexcept override
	{
		m_readersData[readerIndex]->lastQueueIndex = readerIndex;
		OutputStorage<ElementType>::registerReader(readerIndex);
	}

	// void registerWriter() noexcept override { OutputStorage<ElementType>::registerWriter(); }

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerId) noexcept override
	{
		Queue& queue = m_queues[writerId].get();
		const std::size_t enqueCount = queue.enqueCount.load(std::memory_order_acquire);
		const std::size_t writeIndex = enqueCount % queue.storage->size();
		if (enqueCount >= queue.storage->size()
			&& enqueCount - queue.storage->size() >= queue.cachedFinishedIndex) {
			queue.cachedFinishedIndex
				= queue.groupData->finishedIndex.load(std::memory_order_acquire);
		}
		if (enqueCount >= queue.storage->size()
			&& enqueCount - queue.storage->size() >= queue.cachedFinishedIndex) {
			// this->m_allocationBuffer->deallocate(container.getCounter(), writerId);
			BackoffScheme(0, 1).backoff();
			return false;
		}

		// std::atomic_thread_fence(std::memory_order_seq_cst);
		queue.storage.get()[writeIndex].assign(container, this->makeDeallocationCallback(writerId));
		// this->assignAndDeallocate(queue.storage[writeIndex], container, writerId);
		/*queue.storage[writeIndex].assign(
			std::move(Reference<OutputContainer<ElementType>>(*container)),
			*this->m_allocationBuffer);*/
		// this->m_allocationBuffer->replace(queue.storage[writeIndex], element, writerId);
		// std::atomic_thread_fence(std::memory_order_seq_cst);
		queue.enqueCount.fetch_add(1, std::memory_order_release);
		return true;
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		ReaderData& readerData = m_readersData[readerIndex].get();
		if (readerData.lastReadSuccessful) {
			m_queues[readerData.lastQueueIndex % m_queues.size()]
				->groupData->readsFinished.fetch_add(1, std::memory_order_acq_rel);
		}

		if (readerData.shiftQueue) {
			readerData.shiftQueue = false;
			readerData.lastQueueIndex++;
			// readerData.cachedEnqueCount = 0;
		}
		for (uint8_t queueShifts = 0; queueShifts < this->m_expectedWritersCount; queueShifts++) {
			const uint8_t currentQueueIndex = readerData.lastQueueIndex % m_queues.size();
			Queue& queue = m_queues[currentQueueIndex].get();
			queue.sync();
			const std::size_t dequeTry
				= queue.groupData->dequeueTries.fetch_add(1, std::memory_order_acq_rel);
			// const std::size_t d_x = readerData.cachedEnqueCounts[currentQueueIndex];
			// const std::size_t d_enqueCount = queue.enqueCount.load();
			if (dequeTry >= readerData.cachedEnqueCounts[currentQueueIndex]) {
				readerData.cachedEnqueCounts[currentQueueIndex]
					= queue.enqueCount.load(std::memory_order_acquire);
			}
			// const std::size_t d_y = readerData.cachedEnqueCounts[currentQueueIndex];
			if (dequeTry >= readerData.cachedEnqueCounts[currentQueueIndex]) {
				queue.groupData->dequeueTries.fetch_sub(1, std::memory_order_acq_rel);
				readerData.lastQueueIndex++;
				readerData.readWithoutShift = 0;
				// readerData.cachedEnqueCount = 0;
				continue;
			}
			readerData.readWithoutShift++;
			// TODO originally was 256
			// bool d_s = false;
			if (readerData.readWithoutShift == queue.storage->size()) {
				this->shiftAllQueues();
				// d_s = true;
			}
			// std::atomic_thread_fence(std::memory_order_seq_cst);
			const std::size_t readIndex
				= queue.groupData->readRank.fetch_add(1, std::memory_order_acq_rel)
				% queue.storage->size();
			// std::atomic_thread_fence(std::memory_order_seq_cst);

			/*if (readerData.cachedEnqueCounts[currentQueueIndex] > queue.enqueCount) {
				throw std::runtime_error("XXXXX");
			}*/

			readerData.lastReadSuccessful = true;
			return &queue.storage.get()[readIndex].getData();
		}
		readerData.lastReadSuccessful = false;
		BackoffScheme(0, 1).backoff();
		return nullptr;
	}

	bool finished() noexcept override
	{
		return !this->writersPresent()
			&& std::ranges::all_of(m_queues, [&](const CacheAlligned<Queue>& queue) {
				   return queue->finished();
			   });
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
		std::atomic<uint64_t> dequeueTries {0};
		// std::atomic<uint64_t> overcommitCount {0};
		std::atomic<uint64_t> readRank {0};
		std::atomic<uint64_t> readsFinished {0};
		std::atomic<uint64_t> finishedIndex {1};
	};

	struct Queue {
		Queue(std::span<Reference<OutputContainer<ElementType>>> storage) noexcept
			: storage(storage)
		{
		}

		void sync() noexcept
		{
			const std::size_t readsFinished
				= groupData->readsFinished.load(std::memory_order_acquire);
			const std::size_t readIndex = groupData->readRank.load(std::memory_order_acquire);
			if (readIndex == readsFinished) {
				groupData->finishedIndex.store(readIndex, std::memory_order_release);
			}
		}

		bool finished() const noexcept
		{
			return groupData->finishedIndex.load(std::memory_order_acquire)
				>= enqueCount.load(std::memory_order_acquire);
		}

		std::atomic<uint64_t> enqueCount {0};
		uint64_t cachedFinishedIndex {0};
		CacheAlligned<GroupData> groupData;
		CacheAlligned<std::span<Reference<OutputContainer<ElementType>>>> storage;
		// std::span<CacheAlligned<GroupData>> d_groupData {groupData.data(), groupData.capacity()};
	};

	void shiftAllQueues() noexcept
	{
		for (CacheAlligned<ReaderData>& readerData : m_readersData) {
			readerData->readWithoutShift = 0;
			readerData->shiftQueue = true;
		}
	}

	std::mutex m_registrationMutex;
	boost::container::
		static_vector<CacheAlligned<Queue>, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			m_queues;
	std::array<CacheAlligned<ReaderData>, OutputStorage<ElementType>::MAX_READERS_COUNT>
		m_readersData;
	// uint8_t m_queueShift {0};
};

} // namespace ipxp::output