#pragma once

#include "backoffScheme.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class FFQOutputStorage : public OutputStorage<ElementType> {
	constexpr static uint32_t SHORT_TRIES = 5;
	constexpr static uint32_t LONG_TRIES = 3;

public:
	explicit FFQOutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: OutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
		, m_cells(OutputStorage<ElementType>::STORAGE_CAPACITY)
	{
	}

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerId) noexcept override
	{
		BackoffScheme backoffScheme(70, 1);
		while (true) {
			const uint64_t writeRank = this->m_writeRank->fetch_add(1, std::memory_order_acq_rel);
			const uint64_t writeIndex = writeRank % OutputStorage<ElementType>::STORAGE_CAPACITY;
			if (
				/*(m_storage[writeIndex].empty()
				 || !getReferenceCounter(m_storage[writeIndex]).hasUsers())&&*/
				m_cells[writeIndex].state.isRead() && m_cells[writeIndex].state.tryToSetWriter()) {
				// m_storage[writeIndex].assign(container, *m_allocationBuffer);

				// this->m_allocationBuffer->replace(this->m_storage[writeIndex], element,
				// writerId);
				this->m_storage[writeIndex].assign(
					container,
					this->makeDeallocationCallback(writerId));
				// std::atomic_thread_fence(std::memory_order_release);
				m_cells[writeIndex].state.reset();
				return true;
			}
			if (!backoffScheme.backoff()) {
				// container.deallocate(*m_allocationBuffer);
				// this->m_allocationBuffer->deallocate(element, writerId);
				return false;
			}
		}
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		BackoffScheme backoffScheme(30, 1);
		if (m_readersData[readerIndex]->lastReadIndex.has_value()) {
			m_cells[*m_readersData[readerIndex]->lastReadIndex].state.setReadingFinished();
		}
		while (!finished()) {
			const uint64_t readRank = m_readRank->fetch_add(1, std::memory_order_acq_rel);
			const uint64_t readIndex = readRank % OutputStorage<ElementType>::STORAGE_CAPACITY;
			if (m_cells[readIndex].state.tryToSetReadingStarted()) {
				// std::atomic_thread_fence(std::memory_order_acquire);
				m_readersData[readerIndex]->lastReadIndex = readIndex;
				return &this->m_storage[readIndex].getData();
			}
			if (!backoffScheme.backoff()) {
				m_readersData[readerIndex]->lastReadIndex = std::nullopt;
				return nullptr;
			}
		}
		return nullptr;
	}

	bool finished() noexcept override
	{
		return !this->writersPresent()
			&& m_readRank->load(std::memory_order_acquire)
				% OutputStorage<ElementType>::STORAGE_CAPACITY
			== m_writeRank->load(std::memory_order_acquire)
				% OutputStorage<ElementType>::STORAGE_CAPACITY;
	}

protected:
	class ReaderGroupState {
		constexpr static uint8_t WRITER_INDEX
			= OutputStorage<ElementType>::MAX_READER_GROUPS_COUNT - 1;

	public:
		explicit ReaderGroupState() noexcept
		//: m_startedState(std::numeric_limits<uint64_t>::max() >> 8)
		//, m_finishedState(std::numeric_limits<uint64_t>::max())
		{
		}

		// bool tryToSetWriter() noexcept { return setByte(WRITER_INDEX, m_startedState); }
		bool tryToSetWriter() noexcept
		{
			return m_writingStarted.exchange(true, std::memory_order_acq_rel) == false;
		}

		/*bool tryToSetReadingStarted(const uint8_t readerGroup) noexcept
		{
			return setByte(readerGroup, m_startedState);
		}*/
		bool tryToSetReadingStarted() noexcept
		{
			return m_readingStarted.exchange(true, std::memory_order_acq_rel) == false;
		}

		/*void setReadingFinished(const uint8_t readerGroup) noexcept
		{
			setByte(readerGroup, m_finishedState);
		}*/
		void setReadingFinished() noexcept
		{
			m_readingFinished.store(true, std::memory_order_release);
			// setByte(readerGroup, m_finishedState);
		}

		void reset()
		{
			m_readingFinished.store(false, std::memory_order_release);
			m_writingStarted.store(false, std::memory_order_release);
			m_readingStarted.store(false, std::memory_order_release);
			// m_readingFinished = false;
			// m_writingStarted = false;
			// m_readingStarted = false;
			//  m_finishedState = (std::numeric_limits<uint64_t>::max() << ((groupsTotal) * 8));
			//  m_startedState = (std::numeric_limits<uint64_t>::max() << (groupsTotal * 8 + 1)) >>
			//  8;
		}

		/*bool allGroupsRead() noexcept
		{
			return m_finishedState == std::numeric_limits<uint64_t>::max();
		}*/
		bool isRead() noexcept { return m_readingFinished.load(std::memory_order_acquire); }

	private:
		/*static bool setByte(const uint8_t index, std::atomic<uint64_t>& state) noexcept
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
		}*/

		// std::atomic<uint64_t> m_startedState;
		// std::atomic<uint64_t> m_finishedState;
		std::atomic<bool> m_readingStarted {true};
		std::atomic<bool> m_readingFinished {true};
		std::atomic<bool> m_writingStarted {false};
	};

	struct Cell {
		constexpr static uint64_t INVALID_RANK = std::numeric_limits<uint64_t>::max();

		// uint64_t rank;
		ReaderGroupState state;
		// bool gap;
	};

	struct ReaderData {
		std::optional<uint16_t> lastReadIndex {};
	};

	std::array<CacheAlligned<ReaderData>, OutputStorage<ElementType>::MAX_READERS_COUNT>
		m_readersData;
	boost::container::static_vector<Cell, OutputStorage<ElementType>::STORAGE_CAPACITY> m_cells;
	CacheAlligned<std::atomic<uint64_t>> m_writeRank {0};
	CacheAlligned<std::atomic<uint64_t>> m_readRank {0};
};

} // namespace ipxp::output