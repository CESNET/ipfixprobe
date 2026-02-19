#pragma once

#include "backoffScheme.hpp"
#include "mcOutputStorage.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class MC2OutputStorage : public MCOutputStorage<ElementType> {
public:
	explicit MC2OutputStorage(const uint8_t writersCount) noexcept
		: MCOutputStorage<ElementType>(writersCount)
	{
	}

	bool write(ElementType* element, const uint8_t writerId) noexcept override
	{
		typename MCOutputStorage<ElementType>::Queue& queue = this->m_queues[writerId];
		const std::size_t writeIndex = queue.enqueCount % queue.storage.size();
		if (queue.enqueCount >= queue.storage.size()
			&& queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			queue.cachedLowestHeadIndex = queue.lowestHeadIndex();
		}
		BackoffScheme backoffScheme(10, std::numeric_limits<std::size_t>::max());
		while (queue.enqueCount >= queue.storage.size()
			   && queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			backoffScheme.backoff();
			queue.cachedLowestHeadIndex = queue.lowestHeadIndex();
		}

		// std::atomic_thread_fence(std::memory_order_seq_cst);
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
		typename MCOutputStorage<ElementType>::ReaderData& readerData
			= this->m_readersData[globalReaderIndex].get();
		if (readerData.lastReadSuccessful) {
			this->m_queues[readerData.lastQueueIndex % this->m_queues.size()]
				.groupData[readerGroupIndex]
				->confirmedIndex++;
		}

		if (readerData.shiftQueue) {
			readerData.shiftQueue = false;
			readerData.lastQueueIndex++;
			// readerData.cachedEnqueCount = 0;
		}
		for (uint8_t queueShifts = 0; queueShifts < this->m_totalWritersCount; queueShifts++) {
			const uint8_t currentQueueIndex = readerData.lastQueueIndex % this->m_queues.size();
			typename MCOutputStorage<ElementType>::Queue& queue = this->m_queues[currentQueueIndex];
			queue.sync(readerGroupIndex);
			const std::size_t dequeCount = queue.groupData[readerGroupIndex]->dequeueCount++;
			const std::size_t d_x = readerData.cachedEnqueCounts[currentQueueIndex];
			// const std::size_t d_enqueCount = queue.enqueCount.load();
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
			std::atomic_thread_fence(std::memory_order_seq_cst);
			const std::size_t readIndex
				= queue.groupData[readerGroupIndex]->headIndex++ % queue.storage.size();
			std::atomic_thread_fence(std::memory_order_seq_cst);

			// auto& y = queue.groupData[readerGroupIndex];
			/*if (readerData.cachedEnqueCounts[currentQueueIndex] > queue.enqueCount) {
				throw std::runtime_error("XXXXX");
			}
			if (queue.storage[readIndex].empty()) {
				throw std::runtime_error("Should not happen");
			}
			if (queue.storage[readIndex].getContainer().readTimes == 4) {
				throw std::runtime_error("Bad read times");
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
			&& std::ranges::all_of(
				this->m_queues,
				[&](const typename MCOutputStorage<ElementType>::Queue& queue) {
					return queue.finished();
				});
	}

private:
};

} // namespace ipxp::output