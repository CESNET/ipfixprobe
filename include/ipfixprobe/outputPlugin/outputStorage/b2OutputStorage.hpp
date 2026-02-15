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

class B2OutputStorage : public BOutputStorage {
public:
	explicit B2OutputStorage(const uint8_t writersCount) noexcept
		: BOutputStorage(writersCount)
	{
	}

	bool storeContainer(ContainerWrapper container, const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		const uint16_t containersLeft = writerData.bucketAllocation.containersLeft();
		switch (containersLeft) {
		case 1:
			getNextContainer(writerData.bucketAllocation).assign(container, *m_allocationBuffer);
			[[fallthrough]];
		case 0:
			break;
		default:
			getNextContainer(writerData.bucketAllocation).assign(container, *m_allocationBuffer);
			return true;
		}

		uint8_t loopCounter = 0;
		BackoffScheme backoffScheme(2, std::numeric_limits<std::size_t>::max());
		// const uint16_t initialPosition = writerData.writePosition;
		do {
			const bool overflowed = writerData.randomShift();
			d_writerShifts++;
			if (overflowed) {
				writerData.cachedLowestReaderGeneration = m_lowestReaderGeneration.load();
				if (containersLeft == 0) {
					container.deallocate(*m_allocationBuffer);
				}
				d_writerYields++;
				backoffScheme.backoff();
			}

			if (m_buckets[writerData.writePosition].generation
					>= writerData.cachedLowestReaderGeneration
				|| !BucketAllocation::isValidBucketIndex(
					m_buckets[writerData.writePosition].bucketIndex)
				|| !m_buckets[writerData.writePosition].lock.try_lock()) {
				continue;
			}
			if (m_buckets[writerData.writePosition].generation
					>= writerData.cachedLowestReaderGeneration
				|| !BucketAllocation::isValidBucketIndex(
					m_buckets[writerData.writePosition].bucketIndex)) {
				m_buckets[writerData.writePosition].lock.unlock();
				continue;
			}
			break;
		} while (true);

		m_buckets[writerData.writePosition].bucketIndex
			= writerData.bucketAllocation.reset(m_buckets[writerData.writePosition].bucketIndex);
		std::atomic_thread_fence(std::memory_order_release);

		writerData.generation = m_highestReaderGeneration + WINDOW_SIZE;
		m_buckets[writerData.writePosition].generation = writerData.generation;

		m_buckets[writerData.writePosition].lock.unlock();

		if (containersLeft == 0) {
			getNextContainer(writerData.bucketAllocation).assign(container, *m_allocationBuffer);
		}
		return true;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		ReaderData& readerData = m_readersData[globalReaderIndex].get();
		// const uint64_t readPosition = readerData.readPosition;
		if (readerData.bucketAllocation.containersLeft()) {
			return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
				getReferenceCounter(getNextContainer(readerData.bucketAllocation)));
		}

		uint8_t loopCounter = 0;
		uint64_t cachedGeneration;
		uint16_t cachedBucketIndex;
		const uint16_t initialPosition = readerData.readPosition;
		do {
			readerData.shift(m_readerGroupSizes[readerGroupIndex], localReaderIndex);
			d_readerShifts++;

			auto& y = m_buckets[readerData.readPosition];
			if (readerData.isOnBufferBegin(m_readerGroupSizes[readerGroupIndex])) {
				if (!writersPresent()) {
					readerData.generation++;
					updateLowestReaderGeneration(globalReaderIndex);
					return std::nullopt;
				}
				if (!readerData.seenValidBucket) {
					updateLowestReaderGeneration(globalReaderIndex);
					std::this_thread::yield();
					d_readerYields++;
					readerData.skipLoop = true;
					return std::nullopt;
				}
				readerData.generation++;
				readerData.seenValidBucket = false;
				readerData.skipLoop = false;
				updateLowestReaderGeneration(globalReaderIndex);
			}
			cachedGeneration = m_buckets[readerData.readPosition].generation;
			std::atomic_thread_fence(std::memory_order_acquire);
			cachedBucketIndex = m_buckets[readerData.readPosition].bucketIndex;
			if (cachedGeneration >= readerData.generation + 2) {
				readerData.seenValidBucket = true;
			}
		} while (cachedGeneration != readerData.generation
				 || !BucketAllocation::isValidBucketIndex(cachedBucketIndex));

		readerData.seenValidBucket = true;
		readerData.bucketAllocation.reset(m_buckets[readerData.readPosition].bucketIndex);

		return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
			getReferenceCounter(getNextContainer(readerData.bucketAllocation)));
	}

	bool finished([[maybe_unused]] const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent() && getHighestWriterGeneration() < m_lowestReaderGeneration;
	}

protected:
	void updateLowestReaderGeneration(const uint8_t globalReaderIndex) noexcept
	{
		boost::container::static_vector<uint64_t, MAX_READERS_COUNT> readerGenerations
			= m_readersData
			| std::views::transform([](const CacheAlligned<ReaderData>& readerDataAlligned) {
				  return readerDataAlligned->generation;
			  })
			| std::ranges::to<boost::container::static_vector<uint64_t, MAX_READERS_COUNT>>();
		const uint64_t highestReaderGeneration = *std::ranges::max_element(readerGenerations);
		uint64_t expected;
		do {
			expected = m_highestReaderGeneration.load();
			if (highestReaderGeneration <= expected) {
				break;
			}
		} while (m_highestReaderGeneration.compare_exchange_weak(
			expected,
			highestReaderGeneration,
			std::memory_order_release));
		// m_highestReaderGeneration = highestReaderGeneration;
		const uint64_t lowestReaderGeneration = *std::ranges::min_element(readerGenerations);
		m_lowestReaderGeneration = lowestReaderGeneration;
	}
};

} // namespace ipxp::output