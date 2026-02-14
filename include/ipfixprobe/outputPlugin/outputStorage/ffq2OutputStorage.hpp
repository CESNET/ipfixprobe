#pragma once
#include "backoffScheme.hpp"
#include "ffqOutputStorage.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

class FFQ2OutputStorage : public FFQOutputStorage {
	constexpr static uint32_t SHORT_TRIES = 5;
	constexpr static uint32_t LONG_TRIES = 3;

public:
	explicit FFQ2OutputStorage(const uint8_t writersCount) noexcept
		: FFQOutputStorage(writersCount)
	{
	}

	bool storeContainer(ContainerWrapper container, const uint8_t writerId) noexcept override
	{
		BackoffScheme backoffScheme(70, std::numeric_limits<std::size_t>::max());
		const uint64_t writeRank = m_writeRank++;
		const uint64_t writeIndex = writeRank % ALLOCATION_BUFFER_CAPACITY;
		while (
			!(m_cells[writeIndex].state.allGroupsRead()
			  && m_cells[writeIndex].state.tryToSetWriter())) {
			backoffScheme.backoff();
		}
		m_storage[writeIndex].assign(container, *m_allocationBuffer);
		std::atomic_thread_fence(std::memory_order_release);
		m_cells[writeIndex].state.reset(m_readerGroupsCount.load());
		return true;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		BackoffScheme backoffScheme(30, std::numeric_limits<std::size_t>::max());
		if (m_readersData[globalReaderIndex]->lastReadIndex.has_value()) {
			m_cells[*m_readersData[globalReaderIndex]->lastReadIndex].state.setReadingFinished(
				readerGroupIndex);
		}
		const uint64_t readRank = m_readRanks[readerGroupIndex].get()++;
		const uint64_t readerIndex = readRank % ALLOCATION_BUFFER_CAPACITY;
		while (readRank >= m_writeRank.load() && writersPresent()) {
			backoffScheme.backoff();
		}
		if (readRank >= m_writeRank.load()) {
			return std::nullopt;
		}

		while (!m_cells[readerIndex].state.tryToSetReadingStarted(readerGroupIndex)) {
			backoffScheme.backoff();
		}
		std::atomic_thread_fence(std::memory_order_acquire);
		m_readersData[globalReaderIndex]->lastReadIndex = readerIndex;
		if (m_storage[readerIndex].empty()) {
			throw std::runtime_error("Should not happen");
		}
		return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
			getReferenceCounter(m_storage[readerIndex]));
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent() &&
			// m_readRanks[readerGroupIndex].get() % ALLOCATION_BUFFER_CAPACITY
			//== m_writeRank.load() % ALLOCATION_BUFFER_CAPACITY;
			m_readRanks[readerGroupIndex].get() > m_writeRank.load();
	}

private:
};

} // namespace ipxp::output