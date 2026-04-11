#pragma once

#include "backoffScheme.hpp"
#include "doubleBufferedValue.hpp"
#include "mqOutputStorage.hpp"
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
class MQ2OutputStorage : public MQOutputStorage<ElementType> {
public:
	explicit MQ2OutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer)
		: MQOutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
	{
	}

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerIndex) noexcept override
	{
		BackoffScheme backoff(30, std::numeric_limits<std::size_t>::max());
		while (!this->m_queues[writerIndex].tryWrite(
			container,
			*this->m_allocationBuffer,
			std::numeric_limits<std::size_t>::max(),
			writerIndex)) {
			backoff.backoff();
		}
		return true;
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		BackoffScheme backoff(30, std::numeric_limits<std::size_t>::max());
		while (true) {
			const uint8_t sequenceIndex = this->m_readersData[readerIndex]->sequenceIndex++;
			const uint8_t nextSequenceIndex = sequenceIndex + 1;
			const uint8_t queueIndex
				= this->m_readersData[readerIndex]->queueJumpSequence
					  [sequenceIndex % OutputStorage<ElementType>::MAX_WRITERS_COUNT];
			const uint8_t nextQueueIndex 
				= this->m_readersData[readerIndex]->queueJumpSequence
					  [nextSequenceIndex % OutputStorage<ElementType>::MAX_WRITERS_COUNT];
			this->m_queues[nextQueueIndex].prefetch();
			auto* element = this->m_queues[queueIndex].tryRead();
			if (element != nullptr) {
				return element;
			}
			backoff.backoff();
			if (finished()) {
				return nullptr;
			}
		}
	}

	bool finished() noexcept override
	{
		return this->m_expectedReadersCount > this->m_expectedWritersCount
			|| (!this->writersPresent()
				&& std::ranges::all_of(
					this->m_queues,
					[&](const typename MQOutputStorage<ElementType>::Queue& queue) {
						return queue.finished();
					}));
	}
};

} // namespace ipxp::output