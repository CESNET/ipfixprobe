#pragma once

#include "fastRandomGenerator.hpp"
#include "outputStorage.hpp"
#include "spinlock.hpp"

namespace ipxp::output {

class BucketAllocator {
public:
	constexpr static std::size_t BUCKET_SIZE = 128;
	constexpr static std::size_t BUCKET_COUNT
		= OutputStorage::ALLOCATION_BUFFER_CAPACITY / BUCKET_SIZE;

	struct AllocationData {
		uint64_t lastUnboundedBucketIndex {0};
	};

	class BucketAllocationHandler {
	public:
		explicit BucketAllocationHandler(BucketAllocator& allocator) noexcept
			: m_allocator(allocator)
		{
		}

		std::span<ContainerWrapper, BUCKET_SIZE> allocateBucket() noexcept
		{
			return m_allocator.swapBucket(m_allocationData);
		}

		uint64_t getBucketIndex() const noexcept
		{
			return m_allocationData.lastUnboundedBucketIndex % BUCKET_COUNT;
		}

	private:
		BucketAllocator::AllocationData m_allocationData;
		BucketAllocator& m_allocator;
	};

	explicit BucketAllocator(
		std::span<ContainerWrapper> storage,
		FastRandomGenerator<uint8_t> randomGenerator) noexcept
		: m_storage(storage)
		, m_randomGenerator(randomGenerator.getHandler())
	{
	}

	std::span<ContainerWrapper, BUCKET_SIZE> swapBucket(AllocationData& allocationData) noexcept
	{
		m_locks[allocationData.lastUnboundedBucketIndex % BUCKET_COUNT].unlock();
		allocationData.lastUnboundedBucketIndex += m_randomGenerator.getValue();
		while (true) {
			const uint64_t boundedWriterPos
				= allocationData.lastUnboundedBucketIndex % BUCKET_COUNT;
			// const uint64_t bucketGeneration =
			// m_bucketStorage[remapedboundedWriterPos].generation;
			/*if (bucketGeneration > writerData.generation) {
				writerData.generation = bucketGeneration;
			}
			if (bucketGeneration == writerData.generation) {
				writerData.randomShift();
				continue;
			}*/
			const bool locked = m_locks[boundedWriterPos].try_lock();
			if (!locked) {
				allocationData.lastUnboundedBucketIndex += m_randomGenerator.getValue();
				continue;
			}
			return std::span<ContainerWrapper, BUCKET_SIZE> {
				m_storage.data() + boundedWriterPos * BUCKET_SIZE,
				BUCKET_SIZE};
			// return m_storage.subspan(boundedWriterPos * BUCKET_SIZE, BUCKET_SIZE);
		}
	}

	BucketAllocationHandler getHandler() noexcept { return BucketAllocationHandler(*this); }

private:
	std::span<ContainerWrapper> m_storage;
	std::array<Spinlock, BUCKET_COUNT> m_locks;
	FastRandomGenerator<uint8_t>::FastRandomGeneratorHandler m_randomGenerator;
};

} // namespace ipxp::output