#pragma once
#include "backoffScheme.hpp"
#include "ffqOutputStorage.hpp"
#include "outputStorage.hpp"

namespace ipxp::output {

template<typename ElementType>
class FFQ2OutputStorage : public FFQOutputStorage<ElementType> {
	// constexpr static uint32_t SHORT_TRIES = 5;
	// constexpr static uint32_t LONG_TRIES = 3;

public:
	explicit FFQ2OutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer)
		: FFQOutputStorage<ElementType>(
			  expectedWritersCount,
			  expectedReadersCount,
			  allocationBuffer)
	{
	}

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerId) noexcept override
	{
		BackoffScheme backoffScheme(70, std::numeric_limits<std::size_t>::max());
		const uint64_t writeRank = this->m_writeRank->fetch_add(1, std::memory_order_acq_rel);
		const uint64_t writeIndex = remap(writeRank) % OutputStorage<ElementType>::STORAGE_CAPACITY;
		while (!this->m_cells[writeIndex].state.tryToSetWriter()) {
			backoffScheme.backoff();
		}
		while (!this->m_cells[writeIndex].state.isRead()) {
			backoffScheme.backoff();
		}

		this->m_storage[writeIndex].assign(container, this->makeDeallocationCallback(writerId));
		this->m_cells[writeIndex].state.reset();
		return true;
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		BackoffScheme backoffScheme(100, std::numeric_limits<std::size_t>::max());
		if (this->m_readersData[readerIndex]->lastReadIndex.has_value()) {
			this->m_cells[*this->m_readersData[readerIndex]->lastReadIndex]
				.state.setReadingFinished();
			this->m_readersData[readerIndex]->lastReadIndex = std::nullopt;
		}
		const uint64_t readRank = this->m_readRank->fetch_add(1, std::memory_order_acq_rel);
		const uint64_t readIndex = remap(readRank) % OutputStorage<ElementType>::STORAGE_CAPACITY;
		while (readRank >= this->m_writeRank->load(std::memory_order_acquire)
			   && this->writersPresent()) {
			backoffScheme.backoff();
		}
		if (readRank >= this->m_writeRank->load(std::memory_order_acquire)) {
			return nullptr;
		}

		while (!this->m_cells[readIndex].state.tryToSetReadingStarted()) {
			backoffScheme.backoff();
		}

		this->m_readersData[readerIndex]->lastReadIndex = readIndex;
		return &this->m_storage[readIndex].getData();
	}

	bool finished() noexcept override
	{
		return !this->writersPresent()
			&& this->m_readRank->load(std::memory_order_acquire)
			> this->m_writeRank->load(std::memory_order_acquire);
	}
};

} // namespace ipxp::output