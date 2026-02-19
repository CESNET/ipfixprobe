#pragma once

#include "backoffScheme.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class FFQOutputStorage : public OutputStorage<ElementType> {
	constexpr static uint32_t SHORT_TRIES = 5;
	constexpr static uint32_t LONG_TRIES = 3;

public:
	explicit FFQOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage<ElementType>(writersCount)
		, m_cells(OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY)
	{
		// m_cells.resize(ALLOCATION_BUFFER_CAPACITY);
	}

	bool write(ElementType* element, const uint8_t writerId) noexcept override
	{
		BackoffScheme backoffScheme(70, 1);
		while (true) {
			const uint64_t writeRank = this->m_writeRank++;
			const uint64_t writeIndex
				= writeRank % OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY;
			if (
				/*(m_storage[writeIndex].empty()
				 || !getReferenceCounter(m_storage[writeIndex]).hasUsers())&&*/
				m_cells[writeIndex].state.allGroupsRead()
				&& m_cells[writeIndex].state.tryToSetWriter()) {
				// m_storage[writeIndex].assign(container, *m_allocationBuffer);

				this->m_allocationBuffer->replace(this->m_storage[writeIndex], element, writerId);
				std::atomic_thread_fence(std::memory_order_release);
				m_cells[writeIndex].state.reset(this->m_readerGroupsCount.load());
				return true;
			}
			if (!backoffScheme.backoff()) {
				// container.deallocate(*m_allocationBuffer);
				this->m_allocationBuffer->deallocate(element, writerId);
				return false;
			}
		}
	}

	const ElementType* read(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		BackoffScheme backoffScheme(30, 1);
		if (m_readersData[globalReaderIndex]->lastReadIndex.has_value()) {
			m_cells[*m_readersData[globalReaderIndex]->lastReadIndex].state.setReadingFinished(
				readerGroupIndex);
		}
		while (!finished(readerGroupIndex)) {
			const uint64_t readRank = m_readRanks[readerGroupIndex].get()++;
			const uint64_t readIndex
				= readRank % OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY;
			if (m_cells[readIndex].state.tryToSetReadingStarted(readerGroupIndex)) {
				std::atomic_thread_fence(std::memory_order_acquire);
				m_readersData[globalReaderIndex]->lastReadIndex = readIndex;
				return this->m_storage[readIndex];
			}
			if (!backoffScheme.backoff()) {
				m_readersData[globalReaderIndex]->lastReadIndex = std::nullopt;
				return nullptr;
			}
		}
		return nullptr;
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !this->writersPresent()
			&& m_readRanks[readerGroupIndex].get()
				% OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY
			== m_writeRank.load() % OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY;
	}

protected:
	class ReaderGroupState {
		constexpr static uint8_t WRITER_INDEX
			= OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT - 1;

	public:
		explicit ReaderGroupState() noexcept
			: m_startedState(std::numeric_limits<uint64_t>::max() >> 8)
			, m_finishedState(std::numeric_limits<uint64_t>::max())
		{
		}

		bool tryToSetWriter() noexcept { return setByte(WRITER_INDEX, m_startedState); }

		bool tryToSetReadingStarted(const uint8_t readerGroup) noexcept
		{
			return setByte(readerGroup, m_startedState);
		}

		void setReadingFinished(const uint8_t readerGroup) noexcept
		{
			setByte(readerGroup, m_finishedState);
		}

		void reset(const uint8_t groupsTotal)
		{
			m_finishedState = (std::numeric_limits<uint64_t>::max() << ((groupsTotal) * 8));
			m_startedState = (std::numeric_limits<uint64_t>::max() << (groupsTotal * 8 + 1)) >> 8;
			// m_state = (std::numeric_limits<uint64_t>::max() << ((groupsTotal * 2 + 1) * 8)) >> 8;
		}

		bool allGroupsRead() noexcept
		{
			return m_finishedState == std::numeric_limits<uint64_t>::max();
		}

	private:
		static bool setByte(const uint8_t index, std::atomic<uint64_t>& state) noexcept
		{
			uint64_t expected;
			uint64_t newState;
			do {
				expected = state.load(std::memory_order_relaxed);
				newState = expected;
				std::span<uint8_t> newGroups(
					reinterpret_cast<uint8_t*>(&newState),
					sizeof(newState) / sizeof(uint8_t));
				if (newGroups[index] == 0xFF) {
					return false;
				}
				newGroups[index] = 0xFF;
			} while (!state.compare_exchange_weak(expected, newState));
			return true;
		}

		std::atomic<uint64_t> m_startedState;
		std::atomic<uint64_t> m_finishedState;
	};

	struct Cell {
		constexpr static uint64_t INVALID_RANK = std::numeric_limits<uint64_t>::max();

		uint64_t rank;
		ReaderGroupState state;
		bool gap;
	};

	struct ReaderData {
		std::optional<uint16_t> lastReadIndex {0};
	};

	boost::container::static_vector<Cell, OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY>
		m_cells;
	std::span<Cell> d_cells {
		m_cells.data(),
		OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY};
	std::atomic<uint64_t> m_writeRank {0};
	std::array<
		CacheAlligned<std::atomic<uint64_t>>,
		OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT>
		m_readRanks;
	std::array<CacheAlligned<ReaderData>, OutputStorage<ElementType>::MAX_READERS_COUNT>
		m_readersData;
};

} // namespace ipxp::output