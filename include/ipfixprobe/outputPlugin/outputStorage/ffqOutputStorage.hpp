#pragma once

#include "backoffScheme.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

class FFQOutputStorage : public OutputStorage {
	constexpr static uint32_t SHORT_TRIES = 5;
	constexpr static uint32_t LONG_TRIES = 3;

public:
	explicit FFQOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage(writersCount)
		, m_cells(ALLOCATION_BUFFER_CAPACITY)
	{
		// m_cells.resize(ALLOCATION_BUFFER_CAPACITY);
	}

	void storeContainer(ContainerWrapper container, const uint8_t writerId) noexcept override
	{
		BackoffScheme backoffScheme(SHORT_TRIES, LONG_TRIES);
		while (true) {
			const uint64_t writeRank = m_writeRank++;
			const uint64_t writeIndex = writeRank % ALLOCATION_BUFFER_CAPACITY;
			if ((m_storage[writeIndex].empty()
				 || !getReferenceCounter(m_storage[writeIndex]).hasUsers())
				&& m_cells[writeIndex].state.allGroupsRead()
				&& m_cells[writeIndex].state.tryToSetWriter()) {
				m_storage[writeIndex].assign(container, *m_allocationBuffer);
				std::atomic_thread_fence(std::memory_order_release);
				m_cells[writeIndex].state.reset(m_readerGroupsCount.load());
				return;
			}
			if (!backoffScheme.backoff()) {
				container.deallocate(*m_allocationBuffer);
				return;
			}
		}
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		BackoffScheme backoffScheme(SHORT_TRIES, LONG_TRIES);
		if (m_readersData[globalReaderIndex]->lastReadIndex.has_value()) {
			m_cells[*m_readersData[globalReaderIndex]->lastReadIndex].state.setReadingFinished(
				readerGroupIndex);
		}
		while (true) {
			const uint64_t readRank = m_readRanks[readerGroupIndex].get()++;
			const uint64_t readIndex = readRank % ALLOCATION_BUFFER_CAPACITY;
			if (m_cells[readIndex].state.tryToSetReadingStarted(readerGroupIndex)) {
				std::atomic_thread_fence(std::memory_order_acquire);
				m_readersData[globalReaderIndex]->lastReadIndex = readIndex;
				return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
					getReferenceCounter(m_storage[readIndex]));
			}
			if (!backoffScheme.backoff()) {
				m_readersData[globalReaderIndex]->lastReadIndex = std::nullopt;
				return std::nullopt;
			}
		}
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent()
			&& m_readRanks[readerGroupIndex].get() % ALLOCATION_BUFFER_CAPACITY
			== m_writeRank.load() % ALLOCATION_BUFFER_CAPACITY;
	}

private:
	class ReaderGroupState {
		constexpr static uint8_t WRITER_INDEX = MAX_READER_GROUPS_COUNT - 1;

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

	boost::container::static_vector<Cell, ALLOCATION_BUFFER_CAPACITY> m_cells;
	std::span<Cell> d_cells {m_cells.data(), ALLOCATION_BUFFER_CAPACITY};
	std::atomic<uint64_t> m_writeRank {0};
	std::array<CacheAlligned<std::atomic<uint64_t>>, MAX_READER_GROUPS_COUNT> m_readRanks;
	std::array<CacheAlligned<ReaderData>, MAX_READERS_COUNT> m_readersData;
};

} // namespace ipxp::output