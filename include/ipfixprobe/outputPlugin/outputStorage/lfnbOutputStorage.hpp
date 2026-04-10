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
			allocationBuffer)
		: OutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
	{
		m_readerData.resize(expectedReadersCount);
	}

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerIndex) noexcept override
	{
		const uint64_t sequentialWritePosition
			= m_nextWritePos.fetch_add(1, std::memory_order_acq_rel);
		const uint64_t writePosition
			= sequentialWritePosition % OutputStorage<ElementType>::STORAGE_CAPACITY;
		const uint64_t remappedWritePosition
			= remap(writePosition) % OutputStorage<ElementType>::STORAGE_CAPACITY;
		const uint64_t nextRemappedWritePosition
			= remap(writePosition + 1) % OutputStorage<ElementType>::STORAGE_CAPACITY;
		__builtin_prefetch(
			&this->m_storage[nextRemappedWritePosition],
			PrefetchMode::Write,
			Locality::High);
		__builtin_prefetch(
			&this->m_writersFinished[nextRemappedWritePosition / BUCKET_SIZE],
			PrefetchMode::Write,
			Locality::High);
		__builtin_prefetch(
			&this->m_readersFinished[nextRemappedWritePosition / BUCKET_SIZE],
			PrefetchMode::Write,
			Locality::High);
		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		while (m_writersFinished[writePosition / BUCKET_SIZE].load(std::memory_order_acquire)
					   / BUCKET_SIZE
				   != sequentialWritePosition / OutputStorage<ElementType>::STORAGE_CAPACITY
			   || !bucketIsRead(writePosition / BUCKET_SIZE)) {
			backoffScheme.backoff();
		}

		this->m_storage[remappedWritePosition].assign(
			container,
			this->makeDeallocationCallback(writerIndex));
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

		const uint64_t sequentialReadPosition
			= m_readPosition.fetch_add(1, std::memory_order_acq_rel);
		const uint64_t readPosition
			= sequentialReadPosition % OutputStorage<ElementType>::STORAGE_CAPACITY;
		const uint64_t remappedReadPosition
			= remap(readPosition) % OutputStorage<ElementType>::STORAGE_CAPACITY;
		const uint64_t nextRemappedReadPosition
			= remap(readPosition + 1) % OutputStorage<ElementType>::STORAGE_CAPACITY;
		__builtin_prefetch(
			&this->m_storage[nextRemappedReadPosition],
			PrefetchMode::Write,
			Locality::High);
		__builtin_prefetch(
			&this->m_writersFinished[nextRemappedReadPosition / BUCKET_SIZE],
			PrefetchMode::Write,
			Locality::High);
		__builtin_prefetch(
			&this->m_readersFinished[nextRemappedReadPosition / BUCKET_SIZE],
			PrefetchMode::Write,
			Locality::High);
		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		while ((m_readersFinished[readPosition / BUCKET_SIZE].load(std::memory_order_acquire)
						/ (BUCKET_SIZE * 1)
					!= sequentialReadPosition / OutputStorage<ElementType>::STORAGE_CAPACITY
				|| !bucketIsWritten(readPosition / BUCKET_SIZE))
			   && this->writersPresent()) {
			backoffScheme.backoff();
		}

		if (sequentialReadPosition >= m_nextWritePos.load()) {
			readerData.lastReadPosition = std::nullopt;
			return nullptr;
		}
		readerData.lastReadPosition = readPosition;
		return &this->m_storage[remappedReadPosition].getData();
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
	std::atomic<uint64_t> m_nextWritePos {0};
};

} // namespace ipxp::output