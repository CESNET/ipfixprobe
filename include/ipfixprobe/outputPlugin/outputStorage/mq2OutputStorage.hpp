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

class MQ2OutputStorage : public MQOutputStorage {
public:
	explicit MQ2OutputStorage(const uint8_t writersCount) noexcept
		: MQOutputStorage(writersCount)
	{
		std::cout << std::endl;
	}

	bool storeContainer(ContainerWrapper container, const uint8_t writerId) noexcept override
	{
		BackoffScheme backoff(3, std::numeric_limits<std::size_t>::max());
		while (!m_queues[writerId].tryWrite(
			std::move(container),
			*m_allocationBuffer,
			m_readerGroupsCount,
			std::numeric_limits<std::size_t>::max())) {
			backoff.backoff();
		}
		return true;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		const size_t tries = m_totalWritersCount / m_readerGroupSizes[readerGroupIndex] + 1;
		BackoffScheme backoff(3, 5);
		for (const auto _ : std::views::iota(0U, tries)) {
			const uint8_t sequenceIndex = m_readersData[globalReaderIndex]->sequenceIndex++;
			const uint8_t queueIndex = m_readersData[globalReaderIndex]
										   ->queueJumpSequence[sequenceIndex % MAX_WRITERS_COUNT];
			ContainerWrapper* container = m_queues[queueIndex].tryRead(readerGroupIndex);
			if (container != nullptr) {
				return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
					getReferenceCounter(*container));
			}
			// std::this_thread::yield();
			backoff.backoff();
		}
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
};

} // namespace ipxp::output