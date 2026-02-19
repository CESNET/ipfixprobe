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

	explicit LFNBOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage<ElementType>(writersCount)
	{
	}

	typename OutputStorage<ElementType>::ReaderGroupHandler&
	registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		m_readerGroupPositions.emplace_back(m_nextWritePos.load());
		m_alreadyReadGroupPositions.emplace_back(0);
		m_readerData.resize(m_readerData.size() + groupSize);
		return OutputStorage<ElementType>::registerReaderGroup(groupSize);
	}

	/*void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		m_readerData
	}*/

	bool write(ElementType* element, [[maybe_unused]] const uint8_t writerId) noexcept override
	{
		const uint64_t sequentialWritePosition = m_nextWritePos++;
		const uint64_t writePosition = sequentialWritePosition % this->m_storage.size();
		/*const bool rightCircle
			= m_writersFinished[writePosition / BUCKET_SIZE].load(std::memory_order_acquire)
				/ BUCKET_SIZE
			!= sequentialWritePosition / ALLOCATION_BUFFER_CAPACITY;*/
		while (m_writersFinished[writePosition / BUCKET_SIZE].load(std::memory_order_acquire)
					   / BUCKET_SIZE
				   != sequentialWritePosition
					   / OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY
			   || !bucketIsRead(writePosition / BUCKET_SIZE)) {
			std::this_thread::yield();
		}

		this->m_allocationBuffer->replace(this->m_storage[writePosition], element, writerId);
		std::atomic_thread_fence(std::memory_order_release);
		m_writersFinished[writePosition / BUCKET_SIZE]++;
		return true;
	}

	const ElementType* read(
		const std::size_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		ReaderData& readerData = m_readerData[globalReaderIndex].get();
		if (readerData.lastReadPosition.has_value()) {
			m_readersFinished[*readerData.lastReadPosition / BUCKET_SIZE]++;
		}

		const uint64_t sequentialReadPosition = m_readerGroupPositions[readerGroupIndex]++;
		const uint64_t readPosition = sequentialReadPosition % this->m_storage.size();
		while (
			(m_readersFinished[readPosition / BUCKET_SIZE].load(std::memory_order_acquire)
					 / (BUCKET_SIZE * this->m_readerGroupsCount)
				 != sequentialReadPosition / OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY
			 || !bucketIsWritten(readPosition / BUCKET_SIZE))
			&& this->writersPresent()) {
			std::this_thread::yield();
		}

		std::atomic_thread_fence(std::memory_order_acquire);
		if (sequentialReadPosition >= m_nextWritePos.load()) {
			readerData.lastReadPosition = std::nullopt;
			return nullptr;
		}
		/*if (this->m_storage[readPosition] == nullptr) {
			throw std::runtime_error("Should not happen");
		}*/
		readerData.lastReadPosition = readPosition;
		return this->m_storage[readPosition];
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !this->writersPresent()
			&& std::ranges::all_of(m_readerGroupPositions, [&](const auto& position) {
				   return position.load(std::memory_order_acquire) >= m_nextWritePos.load();
			   });
	}

private:
	bool bucketIsWritten(const uint64_t bucketIndex) noexcept
	{
		const uint64_t writersFinished
			= m_writersFinished[bucketIndex].load(std::memory_order_acquire);
		return writersFinished % BUCKET_SIZE == 0
			&& writersFinished * this->m_readerGroupsCount
			> m_readersFinished[bucketIndex].load(std::memory_order_acquire);
	}

	bool bucketIsRead(const uint64_t bucketIndex) noexcept
	{
		const uint64_t readersFinished
			= m_readersFinished[bucketIndex].load(std::memory_order_acquire);
		auto x = readersFinished % (BUCKET_SIZE * this->m_readerGroupsCount) == 0
			&& m_writersFinished[bucketIndex].load(std::memory_order_acquire)
						* this->m_readerGroupsCount
					- readersFinished
				< BUCKET_SIZE * this->m_readerGroupsCount;
		return x;
	}

	struct ReaderData {
		std::optional<uint64_t> lastReadPosition;
	};

	boost::container::
		static_vector<std::atomic_uint64_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			m_readerGroupPositions;
	boost::container::
		static_vector<std::atomic_uint64_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			m_alreadyReadGroupPositions;
	std::array<
		std::atomic<uint64_t>,
		OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY / BUCKET_SIZE>
		m_writersFinished;
	std::array<
		std::atomic<uint64_t>,
		OutputStorage<ElementType>::ALLOCATION_BUFFER_CAPACITY / BUCKET_SIZE>
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