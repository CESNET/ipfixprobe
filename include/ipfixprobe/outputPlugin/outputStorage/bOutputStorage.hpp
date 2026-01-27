#pragma once

// #include "bucketAllocator.hpp"
#include "fastRandomGenerator.hpp"
#include "outputStorage.hpp"
#include "spinlock.hpp"

#include <bit>
#include <cstddef>
#include <optional>
#include <random>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

class BOutputStorage : public OutputStorage {
	constexpr static std::size_t BUCKET_SIZE = 128;
	constexpr static std::size_t BUCKET_COUNT
		= OutputStorage::ALLOCATION_BUFFER_CAPACITY / BUCKET_SIZE;

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

	explicit BOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage(writersCount)
		, m_randomGenerator(1, writersCount)
	{
		std::ranges::for_each(
			std::views::repeat(std::ignore, BUCKET_COUNT),
			[&, bucketIndex = 0](const auto) mutable { m_buckets.emplace_back(bucketIndex++); });
	}

	WriteHandler registerWriter() noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_writersData.emplace_back(m_randomGenerator);
		m_buckets[m_writersData.size() - 1].bucketIndex
			= m_writersData.back()->bucketAllocation.reset(
				m_buckets[m_writersData.size() - 1].bucketIndex);
		// m_registrationCondition.notify_all();
		lock.unlock();
		return OutputStorage::registerWriter();
	}

	ReaderGroupHandler& registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		/*std::lock_guard<std::mutex> lock(m_registrationMutex);
		m_readerGroupPositions.emplace_back(m_nextWritePos.load());
		m_alreadyReadGroupPositions.emplace_back(0);*/
		return OutputStorage::registerReaderGroup(groupSize);
	}

	void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_readersData.resize(std::max<std::size_t>(m_readersData.size(), globalReaderIndex + 1));
		m_readersData[globalReaderIndex]->readPosition = localReaderIndex;
		m_readersData[globalReaderIndex]->generationIncreasePosition = localReaderIndex;
		lock.unlock();

		// debugIndices.emplace_back();
		// m_registrationCondition.notify_all();
		// m_registrationCondition.wait(lock, [&]() { return m_writersCount > 0; });
		return OutputStorage::registerReader(readerGroupIndex, localReaderIndex, globalReaderIndex);
	}

	ContainerWrapper& getNextContainer(BucketAllocation& position) noexcept
	{
		const uint64_t containerIndex = position.containerIndex++;
		if (position.bucketIndex * BUCKET_SIZE + containerIndex >= m_storage.size()
			|| containerIndex >= BUCKET_SIZE) {
			throw std::runtime_error("Should not happen");
		}
		return m_storage[position.bucketIndex * BUCKET_SIZE + containerIndex];
	}

	void storeContainer(ContainerWrapper container, const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		/*if (writerData.bucketAllocation.containersLeft()) {
			getNextContainer(writerData.bucketAllocation).assign(container, *m_allocationBuffer);
			return;
		}*/
		const uint16_t containersLeft = writerData.bucketAllocation.containersLeft();
		switch (containersLeft) {
		case 1:
			getNextContainer(writerData.bucketAllocation).assign(container, *m_allocationBuffer);
			[[fallthrough]];
		case 0:
			break;
		default:
			getNextContainer(writerData.bucketAllocation).assign(container, *m_allocationBuffer);
			return;
		}
		/*if (writerData.generation < m_highestReaderGeneration.load()) {
			writerData.generation = m_highestReaderGeneration.load() + 3;
			d_writerInitialJumps++;
		}*/

		uint8_t loopCounter = 0;
		const uint16_t initialPosition = writerData.writePosition;
		do {
			writerData.randomShift();
			d_writerShifts++;
			// const uint64_t writePosition = writerData.writePosition;
			if (writerData.writePosition == initialPosition) {
				writerData.cachedLowestReaderGeneration = m_lowestReaderGeneration.load();
				if (containersLeft == 0) {
					container.deallocate(*m_allocationBuffer);
				}
				d_writerYields++;
				std::this_thread::yield();
				return;
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
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept override
	{
		ReaderData& readerData = m_readersData[globalReaderIndex].get();
		// const uint64_t readPosition = readerData.readPosition;
		if (readerData.bucketAllocation.containersLeft()) {
			if (!BucketAllocation::isValidBucketIndex(readerData.bucketAllocation.bucketIndex)) {
				throw std::runtime_error("Should not happen");
			}
			return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
				getReferenceCounter(getNextContainer(readerData.bucketAllocation)));
		}

		if (readerData.readPosition % m_readerGroupSizes[readerGroupIndex] != localReaderIndex) {
			throw std::runtime_error("Should not happen");
		}

		uint8_t loopCounter = 0;
		uint64_t cachedGeneration;
		uint16_t cachedBucketIndex;
		const uint16_t initialPosition = readerData.readPosition;
		do {
			readerData.shift(m_readerGroupSizes[readerGroupIndex], localReaderIndex);
			d_readerShifts++;
			// std::cout << "Trying to read position: " + std::to_string(readerData.readPosition)
			//		  << std::endl;

			auto& y = m_buckets[readerData.readPosition];
			/*if (readerData.readPosition == readerData.generationIncreasePosition) {
				if (readerData.seenValidBucket) {
					readerData.generation++;
					readerData.seenValidBucket = false;
				}
				if (readerData.generation > m_writersData[0]->generation) {
					d_readerGenerationBigger++;
				} else {
					d_writerGenerationBigger++;
				}
				// std::cout << "increasing generation" << std::endl;
				updateLowestReaderGeneration(globalReaderIndex);
			}*/
			if (readerData.isOnBufferBegin(m_readerGroupSizes[readerGroupIndex])) {
				if (!writersPresent()) {
					readerData.generation++;
					updateLowestReaderGeneration(globalReaderIndex);
					return std::nullopt;
				}
				if (!readerData.seenValidBucket) {
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
			if (cachedGeneration == readerData.generation + WINDOW_SIZE) {
				readerData.seenValidBucket = true;
			}
			/*if (cachedGeneration > readerData.generation) {
				readerData.generation = cachedGeneration;
				readerData.generationIncreasePosition = readerData.readPosition;
				d_readerJumps++;
			}*/
		} while (cachedGeneration != readerData.generation
				 || !BucketAllocation::isValidBucketIndex(cachedBucketIndex));
		// std::cout << "Found " << std::to_string(readerData.readPosition) << " with bucket "
		//		  << std::to_string(m_buckets[readerData.readPosition].bucketIndex) << std::endl;
		readerData.seenValidBucket = true;
		readerData.bucketAllocation.reset(m_buckets[readerData.readPosition].bucketIndex);

		return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
			getReferenceCounter(getNextContainer(readerData.bucketAllocation)));
	}

	bool finished([[maybe_unused]] const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent() && getHighestWriterGeneration() < m_lowestReaderGeneration;
	}

private:
	uint16_t remap(const uint16_t index) noexcept
	{
		return index;
		// TODO test another remap strategy
		// return __builtin_bitreverse32(static_cast<uint32_t>(index)) & (BUCKET_SIZE - 1);
	}

	struct WriterData {
		// BucketAllocator::BucketAllocationHandler bucketAllocationHandler;
		// std::span<ContainerWrapper, BucketAllocator::BUCKET_SIZE> currentBucket;
		// uint16_t withinCurrentBucketIndex {0};
		explicit WriterData(FastRandomGenerator<uint8_t>& randomGenerator) noexcept
			: randomHandler(randomGenerator.getHandler())
		{
		}

		FastRandomGenerator<uint8_t>::FastRandomGeneratorHandler randomHandler;
		BucketAllocation bucketAllocation;
		uint16_t writePosition {0};
		uint64_t generation {1};
		uint64_t cachedLowestReaderGeneration {1};

		void randomShift() noexcept
		{
			writePosition = (writePosition + randomHandler.getValue()) % BUCKET_COUNT;
			// writePosition = ~writePosition & (BUCKET_COUNT - 1);
		}

		bool isOnBufferBegin(const uint8_t writersCount) const noexcept
		{
			return writePosition < writersCount;
		}
	};

	void updateLowestReaderGeneration(const uint8_t globalReaderIndex) noexcept
	{
		boost::container::static_vector<uint64_t, MAX_READERS_COUNT> readerGenerations
			= m_readersData
			| std::views::transform([](const CacheAlligned<ReaderData>& readerDataAlligned) {
				  return readerDataAlligned->generation;
			  })
			| std::ranges::to<boost::container::static_vector<uint64_t, MAX_READERS_COUNT>>();
		const uint64_t highestReaderGeneration = *std::ranges::max_element(readerGenerations);
		// m_readersData[globalReaderIndex]->generation = highestReaderGeneration;
		m_highestReaderGeneration = highestReaderGeneration;
		const uint64_t lowestReaderGeneration = *std::ranges::min_element(readerGenerations);
		m_lowestReaderGeneration = lowestReaderGeneration;
		return;
		/*uint64_t expected;
		do {
			expected = m_lowestReaderGeneration.load(std::memory_order_relaxed);
			if (expected <= lowestReaderGeneration) {
				return;
			}
		} while (!m_lowestReaderGeneration.compare_exchange_weak(
			expected,
			lowestReaderGeneration,
			std::memory_order_release,
			std::memory_order_acquire));*/
	}

	uint64_t getHighestWriterGeneration() const noexcept
	{
		boost::container::static_vector<uint64_t, MAX_WRITERS_COUNT> writerGenerations
			= m_writersData
			| std::views::transform([](const CacheAlligned<WriterData>& writerDataAlligned) {
				  return writerDataAlligned->generation;
			  })
			| std::ranges::to<boost::container::static_vector<uint64_t, MAX_WRITERS_COUNT>>();
		return *std::ranges::max_element(writerGenerations);
	}

	struct ReaderData {
		BucketAllocation bucketAllocation {};
		uint16_t readPosition;
		uint16_t generationIncreasePosition;
		uint64_t generation {1};
		bool seenValidBucket {false};
		bool skipLoop {false};

		void shift(const uint8_t adjustment, const uint16_t initialPosition) noexcept
		{
			const uint16_t newReadPosition = readPosition + adjustment;
			const bool overflow = newReadPosition >= BUCKET_COUNT;
			readPosition = newReadPosition * !overflow + initialPosition * overflow;
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

		uint64_t generation {0};
		Spinlock lock;
		uint16_t bucketIndex;
	};

	boost::container::static_vector<Bucket, BUCKET_COUNT> m_buckets;
	std::span<Bucket> debugBuckets {m_buckets.data(), BUCKET_COUNT};
	std::vector<uint16_t> m_bucketIndices;
	struct D {
		uint64_t bucketIndex;
		uint64_t generation;
		uint64_t readPos;
		uint64_t generationIncreasePos;
	};
	std::vector<std::vector<D>> debugIndices;

	FastRandomGenerator<uint8_t> m_randomGenerator;
	/*BucketAllocator m_bucketAllocator {
		std::span<ContainerWrapper> {m_storage.data(), m_storage.size()},
		m_randomGenerator};*/
	boost::container::static_vector<CacheAlligned<WriterData>, MAX_WRITERS_COUNT> m_writersData;
	// std::atomic<uint64_t> m_highestWriterGeneration {1};

	// std::vector<uint16_t> m_readIndex;
	constexpr static uint8_t WINDOW_SIZE = 2;
	boost::container::static_vector<CacheAlligned<ReaderData>, MAX_READERS_COUNT> m_readersData;
	std::span<CacheAlligned<ReaderData>> debugReaders {m_readersData.data(), MAX_READERS_COUNT};
	std::span<CacheAlligned<WriterData>> debugWriters {m_writersData.data(), MAX_WRITERS_COUNT};

	std::atomic<uint64_t> m_lowestReaderGeneration {1};
	std::atomic<uint64_t> m_highestReaderGeneration {1};
	boost::container::static_vector<std::atomic_uint64_t, MAX_WRITERS_COUNT>
		m_alreadyReadGroupPositions;
	std::mutex m_registrationMutex;
	std::size_t d_writerShifts {0};
	std::size_t d_writerYields {0};
	std::size_t d_readerShifts {0};
	std::size_t d_readerYields {0};
	std::size_t d_readerJumps {0};
	std::size_t d_writerJumps {0};
	std::size_t d_writerGenerationBigger {0};
	std::size_t d_readerGenerationBigger {0};
	std::size_t d_writerInitialJumps {0};
	/*std::array<std::atomic<uint64_t>, ALLOCATION_BUFFER_CAPACITY / BUCKET_SIZE>
	m_writersFinished; std::atomic_uint64_t m_nextWritePos {0}; std::atomic_uint64_t
	m_confirmedPos {0}; std::atomic_uint64_t m_writtenPos {0}; bool m_initialized {false};*/
	std::condition_variable m_registrationCondition;
};

} // namespace ipxp::output