#pragma once
#include "backoffScheme.hpp"
#include "ffqOutputStorage.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class FFQ2OutputStorage : public FFQOutputStorage<ElementType> {
	constexpr static uint32_t SHORT_TRIES = 5;
	constexpr static uint32_t LONG_TRIES = 3;

public:
	explicit FFQ2OutputStorage(const uint8_t writersCount) noexcept
		: FFQOutputStorage<ElementType>(writersCount)
	{
	}

	bool write(ElementType* element, const uint8_t writerId) noexcept override
	{
		/*if (element->getContainer().readTimes > 0) {
			throw std::runtime_error("Container read more times than there are reader groups.");
		}*/
		BackoffScheme backoffScheme(70, std::numeric_limits<std::size_t>::max());
		const uint64_t writeRank = this->m_writeRank++;
		const uint64_t writeIndex
			= writeRank % OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY;
		while (!this->m_cells[writeIndex].state.tryToSetWriter()) {
			backoffScheme.backoff();
		}
		while (!this->m_cells[writeIndex].state.allGroupsRead()) {
			backoffScheme.backoff();
		}

		// this->m_storage[writeIndex].assign(container, *this->m_allocationBuffer);
		this->m_allocationBuffer->replace(this->m_storage[writeIndex], element, writerId);
		std::atomic_thread_fence(std::memory_order_release);
		this->m_cells[writeIndex].state.reset(this->m_readerGroupsCount.load());
		return true;
	}

	ElementType* read(
		const std::size_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		BackoffScheme backoffScheme(30, std::numeric_limits<std::size_t>::max());
		if (this->m_readersData[globalReaderIndex]->lastReadIndex.has_value()) {
			this->m_cells[*this->m_readersData[globalReaderIndex]->lastReadIndex]
				.state.setReadingFinished(readerGroupIndex);
			this->m_readersData[globalReaderIndex]->lastReadIndex = std::nullopt;
		}
		const uint64_t readRank = this->m_readRanks[readerGroupIndex].get()++;
		const uint64_t readerIndex
			= readRank % OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY;
		while (readRank >= this->m_writeRank.load() && this->writersPresent()) {
			backoffScheme.backoff();
		}
		if (readRank >= this->m_writeRank.load()) {
			return nullptr;
		}

		while (!this->m_cells[readerIndex].state.tryToSetReadingStarted(readerGroupIndex)) {
			backoffScheme.backoff();
		}
		std::atomic_thread_fence(std::memory_order_acquire);
		this->m_readersData[globalReaderIndex]->lastReadIndex = readerIndex;
		/*if (this->m_storage[readerIndex].empty()) {
			throw std::runtime_error("Should not happen");
		}*/
		return this->m_storage[readerIndex];
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !this->writersPresent() &&
			// m_readRanks[readerGroupIndex].get() % ALLOCATION_BUFFER_CAPACITY
			//== m_writeRank.load() % ALLOCATION_BUFFER_CAPACITY;
			this->m_readRanks[readerGroupIndex].get() > this->m_writeRank.load();
	}

private:
	// std::array<std::atomic<uint64_t>, ALLOCATION_BUFFER_CAPACITY> m_readTimes {};
};

} // namespace ipxp::output