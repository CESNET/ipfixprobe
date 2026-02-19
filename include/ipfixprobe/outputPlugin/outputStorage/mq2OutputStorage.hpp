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
	explicit MQ2OutputStorage(const uint8_t writersCount) noexcept
		: MQOutputStorage<ElementType>(writersCount)
	{
		std::cout << std::endl;
	}

	bool write(ElementType* element, const uint8_t writerId) noexcept override
	{
		BackoffScheme backoff(3, std::numeric_limits<std::size_t>::max());
		while (!this->m_queues[writerId].tryWrite(
			element,
			*this->m_allocationBuffer,
			this->m_readerGroupsCount,
			std::numeric_limits<std::size_t>::max(),
			writerId)) {
			backoff.backoff();
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
			const uint8_t sequenceIndex = this->m_readersData[globalReaderIndex]->sequenceIndex++;
			const uint8_t queueIndex
				= this->m_readersData[globalReaderIndex]->queueJumpSequence
					  [sequenceIndex % OutputStorage<ElementType>::MAX_WRITERS_COUNT];
			ElementType* element = this->m_queues[queueIndex].tryRead(readerGroupIndex);
			if (element != nullptr) {
				return element;
			}
			// std::this_thread::yield();
			backoff.backoff();
		}
		return nullptr;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return this->m_readerGroupSizes[readerGroupIndex] > this->m_totalWritersCount
			|| (!this->writersPresent()
				&& std::ranges::all_of(
					this->m_queues,
					[&](const typename MQOutputStorage<ElementType>::Queue& queue) {
						return queue.finished();
					}));
	}

private:
};

} // namespace ipxp::output