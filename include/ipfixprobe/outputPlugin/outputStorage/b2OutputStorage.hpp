#pragma once

// #include "bucketAllocator.hpp"
#include "bOutputStorage.hpp"
#include "backoffScheme.hpp"
#include "fastRandomGenerator.hpp"
#include "outputStorage.hpp"
#include "spinlock.hpp"
#include "threadUtils.hpp"

#include <bit>
#include <cstddef>
#include <optional>
#include <random>

#include <boost/container/static_vector.hpp>
#include <immintrin.h>

namespace ipxp::output {

template<typename ElementType>
class B2OutputStorage : public BOutputStorage<ElementType> {
public:
	explicit B2OutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: BOutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
	{
	}

	~B2OutputStorage() override { std::cout << "In loop: " << d_reads << std::endl; }

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerIndex) noexcept override
	{
		typename BOutputStorage<ElementType>::WriterData& writerData
			= this->m_writersData[writerIndex].get();
		const uint16_t containersLeft = writerData.bucketAllocation.containersLeft();
		switch (containersLeft) {
		case 1: {
			this->getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
		}
			[[fallthrough]];
		case 0:
			break;
		default: {
			this->getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
			return true;
		}
		}

		BackoffScheme backoffScheme(2, std::numeric_limits<std::size_t>::max());
		do {
			const bool overflowed = writerData.randomShift();
			if (overflowed) {
				writerData.cachedLowestReaderGeneration
					= this->m_lowestReaderGeneration.load(std::memory_order_acquire);
				backoffScheme.backoff();
			}

			if (this->m_buckets[writerData.writePosition].generation.load(std::memory_order_acquire)
					>= writerData.cachedLowestReaderGeneration
				|| !BOutputStorage<ElementType>::BucketAllocation::isValidBucketIndex(
					this->m_buckets[writerData.writePosition].bucketIndex)
				|| !this->m_buckets[writerData.writePosition].lock.tryLock()) {
				continue;
			}
			if (this->m_buckets[writerData.writePosition].generation.load(std::memory_order_acquire)
					>= writerData.cachedLowestReaderGeneration
				|| !BOutputStorage<ElementType>::BucketAllocation::isValidBucketIndex(
					this->m_buckets[writerData.writePosition].bucketIndex)) {
				this->m_buckets[writerData.writePosition].lock.unlock();
				continue;
			}
			break;
		} while (true);

		this->m_buckets[writerData.writePosition].bucketIndex = writerData.bucketAllocation.reset(
			this->m_buckets[writerData.writePosition].bucketIndex);

		const uint8_t correspondingReaderIndex
			= writerData.writePosition % this->m_expectedReadersCount;
		uint64_t generationToStore = 0;
		do {
			generationToStore = this->m_readersData[correspondingReaderIndex]->generation.load(
									std::memory_order_acquire)
				+ BOutputStorage<ElementType>::WINDOW_SIZE;
			this->m_buckets[writerData.writePosition].generation.store(
				generationToStore,
				std::memory_order_release);
			// TODO REMOVE DEBUG COUNTER
			// d_reads.fetch_add(1, std::memory_order_acq_rel);
		} while (this->m_readersData[correspondingReaderIndex]->generation.load(
					 std::memory_order_acquire)
				 >= generationToStore);
		this->m_buckets[writerData.writePosition].lock.unlock();

		if (containersLeft == 0) {
			this->getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
		}
		return true;
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		typename BOutputStorage<ElementType>::ReaderData& readerData
			= this->m_readersData[readerIndex].get();
		if (readerData.bucketAllocation.containersLeft()) {
			__builtin_prefetch(
				&this->getNextElement(readerData.bucketAllocation).getData() + 1,
				PrefetchMode::Read,
				Locality::High);
			return &this->getNextElement(readerData.bucketAllocation).getData();
		}

		uint64_t cachedGeneration;
		uint16_t cachedBucketIndex;
		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		do {
			const bool overflowed = readerData.shift(this->m_expectedReadersCount, readerIndex);
			__builtin_prefetch(
				&this->m_buckets[readerData.readPosition + this->m_expectedReadersCount],
				PrefetchMode::Write,
				Locality::Medium);
			if (overflowed) {
				if (!this->writersPresent()) {
					readerData.generation.fetch_add(1, std::memory_order_release);
					updateLowestReaderGeneration();
					return nullptr;
				}
				if (!readerData.seenValidBucket) {
					updateLowestReaderGeneration();
					backoffScheme.backoff();
					readerData.skipLoop = true;
					return nullptr;
				}
				readerData.generation.fetch_add(1, std::memory_order_release);
				readerData.seenValidBucket = false;
				readerData.skipLoop = false;
				updateLowestReaderGeneration();
			}
			this->m_buckets[readerData.readPosition].lock.lock();
			cachedGeneration = this->m_buckets[readerData.readPosition].generation.load(
				std::memory_order_acquire);
			cachedBucketIndex = this->m_buckets[readerData.readPosition].bucketIndex;
			if (cachedGeneration > readerData.generation.load(std::memory_order_acquire)) {
				readerData.seenValidBucket = true;
			}
			this->m_buckets[readerData.readPosition].lock.unlock();
		} while (cachedGeneration != readerData.generation.load(std::memory_order_acquire)
				 || !BOutputStorage<ElementType>::BucketAllocation::isValidBucketIndex(
					 cachedBucketIndex));

		readerData.seenValidBucket = true;
		readerData.bucketAllocation.reset(this->m_buckets[readerData.readPosition].bucketIndex);

		return &this->getNextElement(readerData.bucketAllocation).getData();
	}

protected:
	void updateLowestReaderGeneration() noexcept
	{
		const auto readerGenerations
			= this->m_readersData
			| std::views::transform(
				  [](const CacheAlligned<typename BOutputStorage<ElementType>::ReaderData>&
						 readerDataAlligned) {
					  return readerDataAlligned->generation.load(std::memory_order_acquire);
				  })
			| std::ranges::to<boost::container::static_vector<
				uint64_t,
				OutputStorage<ElementType>::MAX_READERS_COUNT>>();
		const uint64_t lowestReaderGeneration = *std::ranges::min_element(readerGenerations);
		this->m_lowestReaderGeneration.store(lowestReaderGeneration, std::memory_order_release);
	}

	std::atomic<uint64_t> m_highestWriterGeneration {0};
	std::atomic<uint64_t> d_reads {0};
};

} // namespace ipxp::output