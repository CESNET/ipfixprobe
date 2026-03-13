#pragma once

#include "backoffScheme.hpp"
#include "mcOutputStorage.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class MC2OutputStorage : public MCOutputStorage<ElementType> {
public:
	explicit MC2OutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: MCOutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
	{
	}

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerId) noexcept override
	{
		typename MCOutputStorage<ElementType>::Queue& queue = this->m_queues[writerId].get();
		const std::size_t enqueCount = queue.enqueCount.load(std::memory_order_acquire);
		const std::size_t writeIndex = remap(enqueCount) % queue.storage->size();
		if (enqueCount >= queue.storage->size()
			&& enqueCount - queue.storage->size() >= queue.cachedFinishedIndex) {
			queue.cachedFinishedIndex
				= queue.groupData->finishedIndex.load(std::memory_order_acquire);
		}
		BackoffScheme backoffScheme(10, std::numeric_limits<std::size_t>::max());
		while (queue.enqueCount.load(std::memory_order_acquire) >= queue.storage->size()
			   && queue.enqueCount.load(std::memory_order_acquire) - queue.storage->size()
				   >= queue.cachedFinishedIndex) {
			backoffScheme.backoff();
			queue.cachedFinishedIndex
				= queue.groupData->finishedIndex.load(std::memory_order_acquire);
		}

		queue.storage.get()[writeIndex].assign(container, this->makeDeallocationCallback(writerId));
		queue.enqueCount.fetch_add(1, std::memory_order_release);
		return true;
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		typename MCOutputStorage<ElementType>::ReaderData& readerData
			= this->m_readersData[readerIndex].get();
		if (readerData.lastReadSuccessful) {
			this->m_queues[readerData.lastQueueIndex % this->m_queues.size()]
				->groupData->readsFinished.fetch_add(1, std::memory_order_acq_rel);
		}

		if (readerData.shiftQueue) {
			readerData.shiftQueue = false;
			readerData.lastQueueIndex++;
		}
		for (uint8_t queueShifts = 0; queueShifts < this->m_expectedWritersCount; queueShifts++) {
			const uint8_t currentQueueIndex = readerData.lastQueueIndex % this->m_queues.size();
			typename MCOutputStorage<ElementType>::Queue& queue
				= this->m_queues[currentQueueIndex].get();
			queue.sync();
			const std::size_t dequeTry
				= queue.groupData->dequeueTries.fetch_add(1, std::memory_order_acq_rel);
			if (dequeTry >= readerData.cachedEnqueCounts[currentQueueIndex]) {
				readerData.cachedEnqueCounts[currentQueueIndex]
					= queue.enqueCount.load(std::memory_order_acquire);
			}
			if (dequeTry >= readerData.cachedEnqueCounts[currentQueueIndex]) {
				queue.groupData->dequeueTries.fetch_sub(1, std::memory_order_acq_rel);
				readerData.lastQueueIndex++;
				readerData.readWithoutShift = 0;
				continue;
			}
			readerData.readWithoutShift++;
			if (readerData.readWithoutShift == queue.storage->size()) {
				this->shiftAllQueues();
			}

			const std::size_t readIndex
				= remap(queue.groupData->readRank.fetch_add(1, std::memory_order_acq_rel))
				% queue.storage->size();
			readerData.lastReadSuccessful = true;
			return &queue.storage.get()[readIndex].getData();
		}
		readerData.lastReadSuccessful = false;
		BackoffScheme(0, 1).backoff();
		return nullptr;
	}
};

} // namespace ipxp::output