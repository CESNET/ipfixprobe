#pragma once

#include "outputStorage.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

template<typename ElementType>
class LFNBOutputStorage : public OutputStorage<ElementType> {
public:
	constexpr static std::size_t BUCKET_SIZE = 512;

	explicit LFNBOutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: OutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
	{
		m_readerData.resize(expectedReadersCount);
	}

	/*typename OutputStorage<ElementType>::ReaderGroupHandler&
	registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		m_readerGroupPositions.emplace_back(m_nextWritePos.load());
		//m_alreadyReadGroupPositions.emplace_back(0);
		m_readerData.resize(m_readerData.size() + groupSize);
		return OutputStorage<ElementType>::registerReaderGroup(groupSize);
	}*/

	/*void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		m_readerData
	}*/

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerIndex) noexcept override
	{
		const uint64_t sequentialWritePosition
			= m_nextWritePos.fetch_add(1, std::memory_order_acq_rel);
		const uint64_t writePosition
			= sequentialWritePosition % OutputStorage<ElementType>::STORAGE_CAPACITY;

		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		while (m_writersFinished[writePosition / BUCKET_SIZE].load(std::memory_order_acquire)
					   / BUCKET_SIZE
				   != sequentialWritePosition / OutputStorage<ElementType>::STORAGE_CAPACITY
			   || !bucketIsRead(writePosition / BUCKET_SIZE)) {
			backoffScheme.backoff();
		}

		// this->assignAndDeallocate(this->m_storage[writePosition], container, writerId);
		this->m_storage[writePosition].assign(
			container,
			this->makeDeallocationCallback(writerIndex));
		// this->m_allocationBuffer->replace(this->m_storage[writePosition], element, writerId);
		// std::atomic_thread_fence(std::memory_order_release);
		m_writersFinished[writePosition / BUCKET_SIZE].fetch_add(1, std::memory_order_release);
		return true;
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		ReaderData& readerData = m_readerData[readerIndex].get();
		if (readerData.lastReadPosition.has_value()) {
			m_readersFinished[*readerData.lastReadPosition / BUCKET_SIZE].fetch_add(
				1,
				std::memory_order_release);
		}

		// const uint64_t sequentialReadPosition = m_readerGroupPositions[readerGroupIndex]++;
		const uint64_t sequentialReadPosition
			= m_readPosition.fetch_add(1, std::memory_order_acq_rel);
		const uint64_t readPosition
			= sequentialReadPosition % OutputStorage<ElementType>::STORAGE_CAPACITY;
		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		while ((m_readersFinished[readPosition / BUCKET_SIZE].load(std::memory_order_acquire)
						/ (BUCKET_SIZE * 1)
					!= sequentialReadPosition / OutputStorage<ElementType>::STORAGE_CAPACITY
				|| !bucketIsWritten(readPosition / BUCKET_SIZE))
			   && this->writersPresent()) {
			backoffScheme.backoff();
		}

		// TODO Maybe Remove
		// std::atomic_thread_fence(std::memory_order_acquire);
		if (sequentialReadPosition >= m_nextWritePos.load()) {
			readerData.lastReadPosition = std::nullopt;
			return nullptr;
		}
		/*if (this->m_storage[readPosition] == nullptr) {
			throw std::runtime_error("Should not happen");
		}*/
		readerData.lastReadPosition = readPosition;
		/*const auto sync = this->m_storage[readPosition].getData().written.load();
		if (this->m_storage[readPosition].getData().storage.size() == 0) {
			throw std::runtime_error("Attempting to read empty container.");
		}*/
		// readerData.lastReadPosition = readPosition;
		return &this->m_storage[readPosition].getData();
	}

	bool finished() noexcept override
	{
		return !this->writersPresent() && m_readPosition >= m_nextWritePos.load();
	}

private:
	bool bucketIsWritten(const uint64_t bucketIndex) noexcept
	{
		const uint64_t writersFinished
			= m_writersFinished[bucketIndex].load(std::memory_order_acquire);
		return writersFinished % BUCKET_SIZE == 0
			&& writersFinished * 1 > m_readersFinished[bucketIndex].load(std::memory_order_acquire);
	}

	bool bucketIsRead(const uint64_t bucketIndex) noexcept
	{
		const uint64_t readersFinished
			= m_readersFinished[bucketIndex].load(std::memory_order_acquire);
		auto x = readersFinished % (BUCKET_SIZE) == 0
			&& m_writersFinished[bucketIndex].load(std::memory_order_acquire) - readersFinished
				< BUCKET_SIZE;
		return x;
	}

	struct ReaderData {
		std::optional<uint64_t> lastReadPosition;
	};

	std::atomic<uint64_t> m_readPosition;
	/*boost::container::
		static_vector<std::atomic_uint64_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			m_readerGroupPositions;
	boost::container::
		static_vector<std::atomic_uint64_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			m_alreadyReadGroupPositions;*/
	std::array<std::atomic<uint64_t>, OutputStorage<ElementType>::STORAGE_CAPACITY / BUCKET_SIZE>
		m_writersFinished;
	std::array<std::atomic<uint64_t>, OutputStorage<ElementType>::STORAGE_CAPACITY / BUCKET_SIZE>
		m_readersFinished;
	boost::container::
		static_vector<CacheAlligned<ReaderData>, OutputStorage<ElementType>::MAX_READERS_COUNT>
			m_readerData;
	std::span<CacheAlligned<ReaderData>> d_readerData {
		m_readerData.data(),
		OutputStorage<ElementType>::MAX_READERS_COUNT};
	std::atomic_uint64_t m_nextWritePos {0};
	std::atomic_uint64_t m_confirmedPos {0};
	std::atomic_uint64_t m_writtenPos {0};
	std::atomic_uint64_t d_writerYields {0};
	std::atomic_uint64_t d_writerShifts {0};
	uint64_t d_readerYields {0};
	std::mutex m_registrationMutex;
	bool m_initialized {false};
	std::condition_variable m_initializationCV;
};

} // namespace ipxp::output