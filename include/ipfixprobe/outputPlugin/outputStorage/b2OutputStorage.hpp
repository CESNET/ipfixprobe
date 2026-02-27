#pragma once

// #include "bucketAllocator.hpp"
#include "bOutputStorage.hpp"
#include "backoffScheme.hpp"
#include "fastRandomGenerator.hpp"
#include "outputStorage.hpp"
#include "spinlock.hpp"

#include <bit>
#include <cstddef>
#include <optional>
#include <random>

#include <boost/container/static_vector.hpp>

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

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerIndex) noexcept override
	{
		typename BOutputStorage<ElementType>::WriterData& writerData
			= this->m_writersData[writerIndex].get();
		const uint16_t containersLeft = writerData.bucketAllocation.containersLeft();
		switch (containersLeft) {
		case 1: {
			/*this->m_allocationBuffer->replace(
				this->getNextElement(writerData.bucketAllocation),
				container,
				writerIndex);*/
			this->getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
		}
			[[fallthrough]];
		case 0:
			break;
		default: {
			/*this->m_allocationBuffer->replace(
				this->getNextElement(writerData.bucketAllocation),
				container,
				writerIndex);*/
			this->getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
			return true;
		}
		}

		// uint8_t loopCounter = 0;
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
		// std::atomic_thread_fence(std::memory_order_release);

		const uint64_t highestReaderGeneration
			= this->m_highestReaderGeneration.load(std::memory_order_acquire);
		if (writerData.generation.load(std::memory_order_acquire)
			< highestReaderGeneration + BOutputStorage<ElementType>::WINDOW_SIZE) {
			writerData.generation.store(
				highestReaderGeneration + BOutputStorage<ElementType>::WINDOW_SIZE,
				std::memory_order_release);
			// casMax(m_highestWriterGeneration, writerData.generation);
		}
		this->m_buckets[writerData.writePosition].generation.store(
			writerData.generation.load(std::memory_order_acquire),
			std::memory_order_release);

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
		// const uint64_t readPosition = readerData.readPosition;
		if (readerData.bucketAllocation.containersLeft()) {
			return &this->getNextElement(readerData.bucketAllocation).getData();
		}

		// uint8_t loopCounter = 0;
		uint64_t cachedGeneration;
		uint16_t cachedBucketIndex;
		// 	const uint16_t initialPosition = readerData.readPosition;
		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		do {
			const bool overflowed = readerData.shift(this->m_expectedReadersCount, readerIndex);

			// auto& y = this->m_buckets[readerData.readPosition];
			// if (readerData.isOnBufferBegin(this->m_expectedReadersCount)) {
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
			cachedGeneration = this->m_buckets[readerData.readPosition].generation.load(
				std::memory_order_acquire);
			// std::atomic_thread_fence(std::memory_order_acquire);
			cachedBucketIndex = this->m_buckets[readerData.readPosition].bucketIndex;
			if (cachedGeneration >= readerData.generation.load(std::memory_order_acquire)
					+ BOutputStorage<ElementType>::WINDOW_SIZE) {
				readerData.seenValidBucket = true;
			}
		} while (cachedGeneration != readerData.generation.load(std::memory_order_acquire)
				 || !BOutputStorage<ElementType>::BucketAllocation::isValidBucketIndex(
					 cachedBucketIndex));

		readerData.seenValidBucket = true;
		readerData.bucketAllocation.reset(this->m_buckets[readerData.readPosition].bucketIndex);

		return &this->getNextElement(readerData.bucketAllocation).getData();
	}

	/*bool finished([[maybe_unused]] const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent() && m_highestWriterGeneration + 200000 < m_lowestReaderGeneration;
	}*/

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
		const uint64_t highestReaderGeneration = *std::ranges::max_element(readerGenerations);
		casMax(this->m_highestReaderGeneration, highestReaderGeneration);
		// m_highestReaderGeneration = highestReaderGeneration;
		const uint64_t lowestReaderGeneration = *std::ranges::min_element(readerGenerations);
		// casMin(m_lowestReaderGeneration, lowestReaderGeneration);
		this->m_lowestReaderGeneration.store(lowestReaderGeneration, std::memory_order_release);
	}

	std::atomic<uint64_t> m_highestWriterGeneration {0};
};

} // namespace ipxp::output