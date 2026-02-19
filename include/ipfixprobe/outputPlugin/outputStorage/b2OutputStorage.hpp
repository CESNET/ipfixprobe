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
	explicit B2OutputStorage(const uint8_t writersCount) noexcept
		: BOutputStorage<ElementType>(writersCount)
	{
	}

	bool write(ElementType* element, const uint8_t writerIndex) noexcept override
	{
		typename BOutputStorage<ElementType>::WriterData& writerData
			= this->m_writersData[writerIndex].get();
		const uint16_t containersLeft = writerData.bucketAllocation.containersLeft();
		switch (containersLeft) {
		case 1: {
			this->m_allocationBuffer->replace(
				this->getNextElement(writerData.bucketAllocation),
				element,
				writerIndex);
		}
			[[fallthrough]];
		case 0:
			break;
		default: {
			this->m_allocationBuffer->replace(
				this->getNextElement(writerData.bucketAllocation),
				element,
				writerIndex);
			return true;
		}
		}

		uint8_t loopCounter = 0;
		BackoffScheme backoffScheme(2, std::numeric_limits<std::size_t>::max());
		do {
			const bool overflowed = writerData.randomShift();
			if (overflowed) {
				writerData.cachedLowestReaderGeneration = this->m_lowestReaderGeneration.load();
				if (containersLeft == 0) {}
				backoffScheme.backoff();
			}

			if (this->m_buckets[writerData.writePosition].generation
					>= writerData.cachedLowestReaderGeneration
				|| !BOutputStorage<ElementType>::BucketAllocation::isValidBucketIndex(
					this->m_buckets[writerData.writePosition].bucketIndex)
				|| !this->m_buckets[writerData.writePosition].lock.try_lock()) {
				continue;
			}
			if (this->m_buckets[writerData.writePosition].generation
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
		std::atomic_thread_fence(std::memory_order_release);

		const uint64_t highestReaderGeneration
			= this->m_highestReaderGeneration.load(std::memory_order_acquire);
		if (writerData.generation
			< highestReaderGeneration + BOutputStorage<ElementType>::WINDOW_SIZE) {
			writerData.generation
				= highestReaderGeneration + BOutputStorage<ElementType>::WINDOW_SIZE;
			// casMax(m_highestWriterGeneration, writerData.generation);
		}
		this->m_buckets[writerData.writePosition].generation = writerData.generation;

		this->m_buckets[writerData.writePosition].lock.unlock();

		if (containersLeft == 0) {
			this->m_allocationBuffer->replace(
				this->getNextElement(writerData.bucketAllocation),
				element,
				writerIndex);
		}
		return true;
	}

	ElementType* read(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		typename BOutputStorage<ElementType>::ReaderData& readerData
			= this->m_readersData[globalReaderIndex].get();
		// const uint64_t readPosition = readerData.readPosition;
		if (readerData.bucketAllocation.containersLeft()) {
			return this->getNextElement(readerData.bucketAllocation);
		}

		uint8_t loopCounter = 0;
		uint64_t cachedGeneration;
		uint16_t cachedBucketIndex;
		const uint16_t initialPosition = readerData.readPosition;
		do {
			readerData.shift(this->m_readerGroupSizes[readerGroupIndex], localReaderIndex);

			auto& y = this->m_buckets[readerData.readPosition];
			if (readerData.isOnBufferBegin(this->m_readerGroupSizes[readerGroupIndex])) {
				if (!this->writersPresent()) {
					readerData.generation++;
					updateLowestReaderGeneration(globalReaderIndex);
					return nullptr;
				}
				if (!readerData.seenValidBucket) {
					updateLowestReaderGeneration(globalReaderIndex);
					std::this_thread::yield();
					readerData.skipLoop = true;
					return nullptr;
				}
				readerData.generation++;
				readerData.seenValidBucket = false;
				readerData.skipLoop = false;
				updateLowestReaderGeneration(globalReaderIndex);
			}
			cachedGeneration = this->m_buckets[readerData.readPosition].generation;
			std::atomic_thread_fence(std::memory_order_acquire);
			cachedBucketIndex = this->m_buckets[readerData.readPosition].bucketIndex;
			if (cachedGeneration >= readerData.generation + 2) {
				readerData.seenValidBucket = true;
			}
		} while (cachedGeneration != readerData.generation
				 || !BOutputStorage<ElementType>::BucketAllocation::isValidBucketIndex(
					 cachedBucketIndex));

		readerData.seenValidBucket = true;
		readerData.bucketAllocation.reset(this->m_buckets[readerData.readPosition].bucketIndex);

		return this->getNextElement(readerData.bucketAllocation);
	}

	/*bool finished([[maybe_unused]] const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent() && m_highestWriterGeneration + 200000 < m_lowestReaderGeneration;
	}*/

protected:
	void updateLowestReaderGeneration(const uint8_t globalReaderIndex) noexcept
	{
		const auto readerGenerations
			= this->m_readersData
			| std::views::transform(
				  [](const CacheAlligned<typename BOutputStorage<ElementType>::ReaderData>&
						 readerDataAlligned) { return readerDataAlligned->generation; })
			| std::ranges::to<boost::container::static_vector<
				uint64_t,
				OutputStorage<ElementType>::MAX_READERS_COUNT>>();
		const uint64_t highestReaderGeneration = *std::ranges::max_element(readerGenerations);
		/*uint64_t expected;
		do {
			expected = m_highestReaderGeneration.load();
			if (highestReaderGeneration <= expected) {
				break;
			}
		} while (m_highestReaderGeneration.compare_exchange_weak(
			expected,
			highestReaderGeneration,
			std::memory_order_release));*/
		casMax(this->m_highestReaderGeneration, highestReaderGeneration);
		// m_highestReaderGeneration = highestReaderGeneration;
		const uint64_t lowestReaderGeneration = *std::ranges::min_element(readerGenerations);
		// casMin(m_lowestReaderGeneration, lowestReaderGeneration);
		this->m_lowestReaderGeneration = lowestReaderGeneration;
	}

	std::atomic<uint64_t> m_highestWriterGeneration {0};
};

} // namespace ipxp::output