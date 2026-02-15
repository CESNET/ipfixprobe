#pragma once

#include "backoffScheme.hpp"
#include "mcOutputStorage.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

class MC2OutputStorage : public MCOutputStorage {
public:
	explicit MC2OutputStorage(const uint8_t writersCount) noexcept
		: MCOutputStorage(writersCount)
	{
	}

	bool storeContainer(ContainerWrapper container, const uint8_t writerId) noexcept override
	{
		Queue& queue = m_queues[writerId];
		const std::size_t writeIndex = queue.enqueCount % queue.storage.size();
		if (queue.enqueCount >= queue.storage.size()
			&& queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			d_writerUpdated++;
			queue.cachedLowestHeadIndex = queue.lowestHeadIndex();
		}
		BackoffScheme backoffScheme(10, std::numeric_limits<std::size_t>::max());
		while (queue.enqueCount >= queue.storage.size()
			   && queue.enqueCount - queue.storage.size() >= queue.cachedLowestHeadIndex) {
			/*d_deallocatedContainers++;
			container.deallocate(*m_allocationBuffer);
			std::this_thread::yield();
			return false;*/
			backoffScheme.backoff();
			queue.cachedLowestHeadIndex = queue.lowestHeadIndex();
		}

		std::atomic_thread_fence(std::memory_order_seq_cst);
		queue.storage[writeIndex].assign(container, *m_allocationBuffer);
		std::atomic_thread_fence(std::memory_order_seq_cst);
		queue.enqueCount++;
		return true;
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

		if (readerData.shiftQueue) {
			readerData.shiftQueue = false;
			readerData.lastQueueIndex++;
			// readerData.cachedEnqueCount = 0;
		}
		for (uint8_t queueShifts = 0; queueShifts < m_totalWritersCount; queueShifts++) {
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
				shiftAllQueues();
				d_s = true;
			}
			std::atomic_thread_fence(std::memory_order_seq_cst);
			const std::size_t readIndex
				= queue.groupData[readerGroupIndex]->headIndex++ % queue.storage.size();
			std::atomic_thread_fence(std::memory_order_seq_cst);

			auto& y = queue.groupData[readerGroupIndex];
			if (readerData.cachedEnqueCounts[currentQueueIndex] > queue.enqueCount) {
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
		std::this_thread::yield();
		return std::nullopt;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent()
			&& std::ranges::all_of(m_queues, [&](const Queue& queue) { return queue.finished(); });
	}

private:
};

} // namespace ipxp::output