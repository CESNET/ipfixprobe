#pragma once

// #include "bucketAllocator.hpp"
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
class BOutputStorage : public OutputStorage<ElementType> {
protected:
	constexpr static std::size_t BUCKET_SIZE = 128;
	constexpr static std::size_t BUCKET_COUNT
		= OutputStorage<ElementType>::STORAGE_CAPACITY / BUCKET_SIZE;

	struct BucketAllocation {
		constexpr static uint16_t INVALID_BUCKET_INDEX = std::numeric_limits<uint16_t>::max();
		constexpr static bool isValidBucketIndex(uint16_t index) noexcept
		{
			return index != INVALID_BUCKET_INDEX;
		}

		uint16_t bucketIndex {INVALID_BUCKET_INDEX};
		uint16_t containerIndex {BUCKET_SIZE};

		uint16_t containersLeft() const noexcept { return BUCKET_SIZE - containerIndex; }

		uint16_t reset(const uint16_t newBucketIndex) noexcept
		{
			const uint16_t oldBucketIndex = bucketIndex;
			bucketIndex = newBucketIndex;
			containerIndex = 0;
			return oldBucketIndex;
		}
	};

public:
	// constexpr static std::size_t BUCKET_INDEX_BIT_SIZE = std::countr_zero(BUCKET_COUNT);

	explicit BOutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: OutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
		, m_randomGenerator(1, OutputStorage<ElementType>::MAX_WRITERS_COUNT)
	{
		std::ranges::for_each(
			std::views::repeat(std::ignore, BUCKET_COUNT),
			[&, bucketIndex = 0](const auto) mutable { m_buckets.emplace_back(bucketIndex++); });
		for (std::size_t writerIndex = 0; writerIndex < expectedWritersCount; writerIndex++) {
			m_writersData.emplace_back(m_randomGenerator);
			m_buckets[writerIndex].bucketIndex = m_writersData[writerIndex]->bucketAllocation.reset(
				m_buckets[writerIndex].bucketIndex);
		}
		m_readersData.resize(expectedReadersCount);
	}

	void registerWriter(const uint8_t writerIndex) noexcept override
	{
		/*std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_writersData.emplace_back(m_randomGenerator);
		m_buckets[m_writersData.size() - 1].bucketIndex
			= m_writersData.back()->bucketAllocation.reset(
				m_buckets[m_writersData.size() - 1].bucketIndex);
		lock.unlock();*/
		OutputStorage<ElementType>::registerWriter(writerIndex);
	}

	void registerReader(const uint8_t readerIndex) noexcept override
	{
		// std::unique_lock<std::mutex> lock(m_registrationMutex);
		// m_readersData.resize(std::max<std::size_t>(m_readersData.size(), readerIndex + 1));
		m_readersData[readerIndex]->readPosition = readerIndex;
		// m_readersData[globalReaderIndex]->generationIncreasePosition = readerIndex;
		// lock.unlock();

		OutputStorage<ElementType>::registerReader(readerIndex);
	}

	Reference<OutputContainer<ElementType>>& getNextElement(BucketAllocation& position) noexcept
	{
		const uint64_t containerIndex = position.containerIndex++;
		return this->m_storage[position.bucketIndex * BUCKET_SIZE + containerIndex];
	}

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		const uint16_t containersLeft = writerData.bucketAllocation.containersLeft();
		switch (containersLeft) {
		case 1:
			// getNextContainer(writerData.bucketAllocation).assign(container,
			// *m_allocationBuffer);
			/*this->m_allocationBuffer->replace(
				getNextElement(writerData.bucketAllocation),
				container,
				writerIndex);*/
			getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
			[[fallthrough]];
		case 0:
			break;
		default:
			// getNextContainer(writerData.bucketAllocation).assign(container,
			// *m_allocationBuffer);
			/*this->m_allocationBuffer->replace(
				getNextElement(writerData.bucketAllocation),
				container,
				writerIndex);*/
			getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
			return true;
		}

		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		do {
			const bool overflowed = writerData.randomShift();
			if (overflowed) {
				writerData.cachedLowestReaderGeneration
					= m_lowestReaderGeneration.load(std::memory_order_acquire);
				if (containersLeft == 0) {
					// this->m_allocationBuffer->deallocate(element, writerIndex);
				}
				backoffScheme.backoff();
				return false;
			}

			if (m_buckets[writerData.writePosition].generation.load(std::memory_order_acquire)
					>= writerData.cachedLowestReaderGeneration
				|| !BucketAllocation::isValidBucketIndex(
					m_buckets[writerData.writePosition].bucketIndex)
				|| !m_buckets[writerData.writePosition].lock.tryLock()) {
				continue;
			}
			if (m_buckets[writerData.writePosition].generation.load(std::memory_order_acquire)
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
		// std::atomic_thread_fence(std::memory_order_release);

		writerData.generation.store(
			m_highestReaderGeneration.load(std::memory_order_acquire) + WINDOW_SIZE,
			std::memory_order_release);
		m_buckets[writerData.writePosition].generation.store(
			writerData.generation.load(std::memory_order_acquire),
			std::memory_order_release);

		m_buckets[writerData.writePosition].lock.unlock();

		if (containersLeft == 0) {
			getNextElement(writerData.bucketAllocation)
				.assign(container, this->makeDeallocationCallback(writerIndex));
		}
		return true;
	}

	OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept override
	{
		ReaderData& readerData = m_readersData[readerIndex].get();
		// const uint64_t readPosition = readerData.readPosition;
		if (readerData.bucketAllocation.containersLeft()) {
			/*if
			(!BucketAllocation::isValidBucketIndex(readerData.bucketAllocation.bucketIndex)) {
				throw std::runtime_error("Should not happen");
			}*/
			return &getNextElement(readerData.bucketAllocation).getData();
		}

		uint64_t cachedGeneration;
		uint16_t cachedBucketIndex;
		BackoffScheme backoffScheme(0, std::numeric_limits<std::size_t>::max());
		do {
			const bool overflowed = readerData.shift(this->m_expectedReadersCount, readerIndex);

			// auto& y = m_buckets[readerData.readPosition];
			if (overflowed) {
				if (!this->writersPresent()) {
					std::cout << "Leving\n";
					readerData.generation.fetch_add(1, std::memory_order_release);
					updateLowestReaderGeneration();
					return nullptr;
				}
				if (!readerData.seenValidBucket) {
					std::cout << "Hits\n";
					updateLowestReaderGeneration();
					backoffScheme.backoff();
					// readerData.skipLoop = true;
					return nullptr;
				}
				std::cout << "Normano\n";
				readerData.generation.fetch_add(1, std::memory_order_release);
				readerData.seenValidBucket = false;
				// readerData.skipLoop = false;
				updateLowestReaderGeneration();
			}
			cachedGeneration
				= m_buckets[readerData.readPosition].generation.load(std::memory_order_acquire);
			// std::atomic_thread_fence(std::memory_order_acquire);
			cachedBucketIndex = m_buckets[readerData.readPosition].bucketIndex;
			// if (cachedGeneration >= readerData.generation + WINDOW_SIZE) {
			if (cachedGeneration
				>= readerData.generation.load(std::memory_order_acquire) + WINDOW_SIZE) {
				std::cout << "Shto\n";
				readerData.seenValidBucket = true;
			}
		} while (cachedGeneration != readerData.generation.load(std::memory_order_acquire)
				 || !BucketAllocation::isValidBucketIndex(cachedBucketIndex));

		readerData.seenValidBucket = true;
		readerData.bucketAllocation.reset(m_buckets[readerData.readPosition].bucketIndex);

		return &getNextElement(readerData.bucketAllocation).getData();
	}

	bool finished() noexcept override
	{
		return !this->writersPresent() && getHighestWriterGeneration() < m_lowestReaderGeneration;
	}

protected:
	uint16_t remap(const uint16_t index) noexcept
	{
		return index;
		// TODO test another remap strategy
		// return __builtin_bitreverse32(static_cast<uint32_t>(index)) & (BUCKET_SIZE - 1);
	}

	struct WriterData {
		explicit WriterData(FastRandomGenerator<uint8_t>& randomGenerator) noexcept
			: randomHandler(randomGenerator.getHandler())
		{
		}

		FastRandomGenerator<uint8_t>::FastRandomGeneratorHandler randomHandler;
		BucketAllocation bucketAllocation;
		uint16_t writePosition {0};
		std::atomic<uint64_t> generation {1};
		uint64_t cachedLowestReaderGeneration {1};

		bool randomShift() noexcept
		{
			const uint16_t saved = writePosition;
			writePosition = (writePosition + randomHandler.getValue()) % BUCKET_COUNT;
			// writePosition = ~writePosition & (BUCKET_COUNT - 1);
			return writePosition < saved;
		}

		bool isOnBufferBegin(const uint8_t writersCount) const noexcept
		{
			return writePosition < writersCount;
		}
	};

	void updateLowestReaderGeneration() noexcept
	{
		boost::container::static_vector<uint64_t, OutputStorage<ElementType>::MAX_READERS_COUNT>
			readerGenerations
			= m_readersData
			| std::views::transform([](const CacheAlligned<ReaderData>& readerDataAlligned) {
				  return readerDataAlligned->generation.load(std::memory_order_acquire);
			  })
			| std::ranges::to<boost::container::static_vector<
				uint64_t,
				OutputStorage<ElementType>::MAX_READERS_COUNT>>();
		const uint64_t highestReaderGeneration = *std::ranges::max_element(readerGenerations);
		m_highestReaderGeneration.store(highestReaderGeneration, std::memory_order_release);
		const uint64_t lowestReaderGeneration = *std::ranges::min_element(readerGenerations);
		m_lowestReaderGeneration.store(lowestReaderGeneration, std::memory_order_release);
	}

	uint64_t getHighestWriterGeneration() const noexcept
	{
		boost::container::static_vector<uint64_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			writerGenerations
			= m_writersData
			| std::views::transform([](const CacheAlligned<WriterData>& writerDataAlligned) {
				  return writerDataAlligned->generation.load(std::memory_order_acquire);
			  })
			| std::ranges::to<boost::container::static_vector<
				uint64_t,
				OutputStorage<ElementType>::MAX_WRITERS_COUNT>>();
		return *std::ranges::max_element(writerGenerations);
	}

	struct ReaderData {
		BucketAllocation bucketAllocation {};
		uint16_t readPosition;
		// uint16_t generationIncreasePosition;
		std::atomic<uint64_t> generation {1};
		bool seenValidBucket {false};
		bool skipLoop {false};

		bool shift(const uint8_t adjustment, const uint16_t initialPosition) noexcept
		{
			// TODO Better calculation
			const uint16_t newReadPosition = readPosition + adjustment;
			if (newReadPosition >= BUCKET_COUNT) {
				readPosition = initialPosition;
				return true;
			}
			readPosition = newReadPosition;
			return false;
		}

		bool isOnBufferBegin(const uint8_t readersInGroupCount) const noexcept
		{
			return readPosition < readersInGroupCount;
		}
	};

	struct Bucket {
		//		constexpr static std::size_t INVALID_INDEX =
		// std::numeric_limits<uint16_t>::max();
		explicit Bucket(const uint16_t bucketIndex) noexcept
			: bucketIndex(bucketIndex)
		{
		}

		std::atomic<uint64_t> generation {0};
		Spinlock lock;
		uint16_t bucketIndex;
	};

	boost::container::static_vector<Bucket, BUCKET_COUNT> m_buckets;
	std::span<Bucket> d_buckets {m_buckets.data(), BUCKET_COUNT};
	std::vector<uint16_t> m_bucketIndices;
	/*struct D {
		uint64_t bucketIndex;
		uint64_t generation;
		uint64_t readPos;
		uint64_t generationIncreasePos;
	};
	std::vector<std::vector<D>> debugIndices;*/

	FastRandomGenerator<uint8_t> m_randomGenerator;
	/*BucketAllocator m_bucketAllocator {
		std::span<ContainerWrapper> {m_storage.data(), m_storage.size()},
		m_randomGenerator};*/
	boost::container::
		static_vector<CacheAlligned<WriterData>, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			m_writersData;
	// std::atomic<uint64_t> m_highestWriterGeneration {1};

	// std::vector<uint16_t> m_readIndex;
	constexpr static std::size_t WINDOW_SIZE = 4;
	boost::container::
		static_vector<CacheAlligned<ReaderData>, OutputStorage<ElementType>::MAX_READERS_COUNT>
			m_readersData;
	std::span<CacheAlligned<ReaderData>> debugReaders {
		m_readersData.data(),
		m_readersData.capacity()};
	std::span<CacheAlligned<WriterData>> debugWriters {
		m_writersData.data(),
		m_writersData.capacity()};

	std::atomic<uint64_t> m_lowestReaderGeneration {1};
	std::atomic<uint64_t> m_highestReaderGeneration {1};
	boost::container::
		static_vector<std::atomic_uint64_t, OutputStorage<ElementType>::MAX_WRITERS_COUNT>
			m_alreadyReadGroupPositions;
	std::mutex m_registrationMutex;
	/*std::array<std::atomic<uint64_t>, ALLOCATION_BUFFER_CAPACITY / BUCKET_SIZE>
	m_writersFinished; std::atomic_uint64_t m_nextWritePos {0}; std::atomic_uint64_t
	m_confirmedPos {0}; std::atomic_uint64_t m_writtenPos {0}; bool m_initialized {false};*/
	std::condition_variable m_registrationCondition;
};

} // namespace ipxp::output