#pragma once

#include "allocationBufferBase.hpp"
#include "backoffScheme.hpp"
#include "cacheAlligned.hpp"
#include "fastRandomGenerator.hpp"

#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <random>
#include <ranges>
#include <vector>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

template<typename ElementType>
class AllocationBufferB : public AllocationBufferBase<ElementType> {
	constexpr static std::size_t BUCKET_SIZE = 16;
	constexpr static std::size_t INDEXES_IN_CACHE_LINE = 64 / sizeof(uint16_t);
	constexpr static std::size_t WINDOW_SIZE = 16;

public:
	/*__attribute__((noinline)) std::size_t d_test(auto& container)
	{
		return std::ranges::count_if(container, [](const auto& bucket) {
			return bucket.load(std::memory_order_acquire) != std::numeric_limits<uint16_t>::max();
		});
	}*/

	explicit AllocationBufferB(const std::size_t capacity, const uint8_t writersCount) noexcept
		: m_objectPool(capacity + writersCount * BUCKET_SIZE)
		, m_buckets(m_objectPool.size() / BUCKET_SIZE)
	{
		if (capacity % BUCKET_SIZE != 0) {
			throw std::invalid_argument("Capacity must be a multiple of bucket size");
		}
		if (m_buckets.size() % writersCount != 0) {
			throw std::invalid_argument("Number of buckets must be a multiple of writers count");
		}

		// m_fullBuckets.reserve(m_buckets.size());
		// m_emptyBuckets.reserve(m_buckets.size());
		for (ElementType& element : m_objectPool) {
			const std::size_t elementIndex = &element - m_objectPool.data();
			const std::size_t bucketIndex = elementIndex / BUCKET_SIZE;
			m_buckets[bucketIndex].storage[elementIndex % BUCKET_SIZE] = &element;
		}
		m_fullBuckets.resize(m_buckets.size());
		m_emptyBuckets.resize(m_buckets.size());
		for (std::size_t i = 0; i < m_buckets.size(); i++) {
			m_fullBuckets[i].store(i);
			m_emptyBuckets[i].store(Bucket::PLACEHOLDER);
		}
		for (std::size_t i = m_buckets.size(); i < m_fullBuckets.size(); i++) {
			m_fullBuckets[i].store(Bucket::PLACEHOLDER);
			m_emptyBuckets[i].store(Bucket::PLACEHOLDER);
		}
		m_writersData.resize(writersCount);
		for (uint8_t writerIndex = 0; writerIndex < writersCount; writerIndex++) {
			m_writersData[writerIndex]->fullPushRank = writerIndex * INDEXES_IN_CACHE_LINE;
			m_writersData[writerIndex]->emptyPushRank = writerIndex * INDEXES_IN_CACHE_LINE;
			m_writersData[writerIndex]->currentBucketIndex = writerIndex;
			m_writersData[writerIndex]->currentBucketSize = BUCKET_SIZE;
			m_fullBuckets[writerIndex].store(Bucket::PLACEHOLDER);
		}
	}

	// void unregisterWriter(const uint8_t writerIndex) noexcept override {}

	ElementType* allocate(const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		if (writerData.currentBucketSize == 0) {
			if (writerData.reservedEmptyBucketIndexes.size() == WINDOW_SIZE) {
				pushBucket(m_emptyBuckets, writerData.currentBucketIndex, writerData.emptyPushRank);
			} else {
				writerData.reservedEmptyBucketIndexes.push_back(writerData.currentBucketIndex);
			}
			if (writerData.reservedFullBucketIndexes.size() == 0) {
				while (writerData.reservedFullBucketIndexes.size() < WINDOW_SIZE) {
					uint16_t fullBucketIndex = popBucket(m_fullBuckets, writerData.fullPushRank);
					writerData.reservedFullBucketIndexes.push_back(fullBucketIndex);
				}
			}
			writerData.currentBucketIndex = writerData.reservedFullBucketIndexes.back();
			writerData.reservedFullBucketIndexes.pop_back();
			writerData.currentBucketSize = BUCKET_SIZE;
		}
		Bucket& bucket = m_buckets[writerData.currentBucketIndex];
		ElementType* res = bucket.storage[writerData.currentBucketSize - 1];
		writerData.currentBucketSize--;
		return res;
	}

	void deallocate(ElementType* element, const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		if (writerData.currentBucketSize == BUCKET_SIZE) {
			if (writerData.reservedFullBucketIndexes.size() == WINDOW_SIZE) {
				pushBucket(m_fullBuckets, writerData.currentBucketIndex, writerData.fullPushRank);
			} else {
				writerData.reservedFullBucketIndexes.push_back(writerData.currentBucketIndex);
			}
			if (writerData.reservedEmptyBucketIndexes.size() == 0) {
				while (writerData.reservedEmptyBucketIndexes.size() < WINDOW_SIZE) {
					uint16_t emptyBucketIndex = popBucket(m_emptyBuckets, writerData.emptyPushRank);
					writerData.reservedEmptyBucketIndexes.push_back(emptyBucketIndex);
				}
			}
			writerData.currentBucketIndex = writerData.reservedEmptyBucketIndexes.back();
			writerData.reservedEmptyBucketIndexes.pop_back();
			writerData.currentBucketSize = 0;
		}
		Bucket& bucket = m_buckets[writerData.currentBucketIndex];
		bucket.storage[writerData.currentBucketSize] = element;
		writerData.currentBucketSize++;
	}

private:
	struct WriterData {
		std::size_t fullPushRank;
		std::size_t emptyPushRank;
		uint16_t currentBucketIndex;
		std::size_t currentBucketSize {BUCKET_SIZE};
		std::vector<uint16_t> reservedFullBucketIndexes;
		std::vector<uint16_t> reservedEmptyBucketIndexes;
	};

	struct Bucket {
		constexpr static uint16_t PLACEHOLDER = std::numeric_limits<uint16_t>::max();
		std::array<ElementType*, BUCKET_SIZE> storage;
	};

	void pushBucket(auto& buckets, const std::size_t bucketIndex, std::size_t& pushRank) noexcept
	{
		// std::size_t offset = 0;
		while (true) {
			uint16_t expected = buckets[pushRank].load(std::memory_order_acquire);
			/*if (++offset % 100'000'000 == 0) {
				std::cout << "d_test(push)=" << d_test(buckets) << "\n";
			}*/
			if (expected != Bucket::PLACEHOLDER) {
				const std::size_t newPushRank
					= ((pushRank / INDEXES_IN_CACHE_LINE + 1) * INDEXES_IN_CACHE_LINE)
					% buckets.size();
				if (newPushRank < pushRank) {
					// offset++;
				}
				pushRank = newPushRank;
				continue;
			}
			if (buckets[pushRank].compare_exchange_weak(
					expected,
					bucketIndex,
					std::memory_order_release,
					std::memory_order_acquire)) {
				pushRank = (pushRank + 1) % buckets.size();
				return;
			}
		}
	}

	uint16_t popBucket(auto& buckets, std::size_t& popRank) noexcept
	{
		// std::size_t offset = 0;
		popRank = (popRank - 1 + buckets.size()) % buckets.size();
		while (true) {
			/*if (++offset % 100'000'000 == 0) {
				std::cout << "d_test(pop)=" << d_test(buckets) << "\n";
			}*/
			uint16_t expected = buckets[popRank].load(std::memory_order_acquire);
			if (expected == Bucket::PLACEHOLDER) {
				popRank
					= (popRank / INDEXES_IN_CACHE_LINE * INDEXES_IN_CACHE_LINE - 1 + buckets.size())
					% buckets.size();
				continue;
			}
			if (buckets[popRank].compare_exchange_weak(
					expected,
					Bucket::PLACEHOLDER,
					std::memory_order_release,
					std::memory_order_acquire)) {
				// popRank = (popRank - 1 + buckets.size()) % buckets.size();
				return expected;
			}
		}
	}

	std::vector<ElementType> m_objectPool;
	std::vector<Bucket> m_buckets;
	// std::array<std::atomic<uint16_t>, 65536> m_fullBuckets;
	// std::array<std::atomic<uint16_t>, 65536> m_emptyBuckets;
	std::deque<std::atomic<uint16_t>> m_fullBuckets;
	std::deque<std::atomic<uint16_t>> m_emptyBuckets;
	std::vector<CacheAlligned<WriterData>> m_writersData;
};

} // namespace ipxp::output