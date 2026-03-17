#pragma once

// #include "../../processPlugin/flowRecord.hpp"
/*#include "allocationBuffer.hpp"
#include "allocationBuffer2.hpp"
#include "allocationBuffer3.hpp"
#include "allocationBufferR.hpp"
#include "dummyAllocationBuffer.hpp"*/
#include "allocationBufferBase.hpp"
#include "outputContainer.hpp"
#include "referenceCounter.hpp"
#include "spinlock.hpp"

#include <atomic>
#include <condition_variable>
#include <ranges>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

enum class PrefetchMode : int { Read = 0, Write = 1 };

enum class Locality : int { None = 0, Low = 1, Medium = 2, High = 3 };

constexpr std::size_t remap(const std::size_t index) noexcept
{
	/*if (index > std::numeric_limits<uint16_t>::max()) {
		throw std::runtime_error("ZZZz");
	}*/
	return index;
	//  return index * 27644437;
	//    return ~index;
	// return std::byteswap(index);
}

template<typename ElementType>
class OutputStorage {
public:
	constexpr static std::size_t STORAGE_CAPACITY = 65536;
	constexpr static std::size_t MAX_WRITERS_COUNT = 32;
	constexpr static std::size_t MAX_READERS_COUNT = 32;
	constexpr static std::size_t MAX_READER_GROUPS_COUNT = 8;

	using value_type = ElementType;

	explicit OutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer)
		: m_expectedWritersCount(expectedWritersCount)
		, m_expectedReadersCount(expectedReadersCount)
		, m_allocationBuffer(allocationBuffer)
	{
		if (STORAGE_CAPACITY % expectedWritersCount != 0) {
			throw std::runtime_error(
				"Storage capacity must be divisible by expected writers count");
		}

		m_storage.reserve(STORAGE_CAPACITY);
		for (const std::size_t writerIndex : std::views::iota(0U, expectedWritersCount)) {
			std::generate_n(
				std::back_inserter(m_storage),
				STORAGE_CAPACITY / expectedWritersCount,
				[&]() {
					return Reference<OutputContainer<ElementType>>(
						*m_allocationBuffer->allocate(writerIndex));
				});
		}
	}

	virtual void registerReader([[maybe_unused]] const uint8_t readerIndex) noexcept
	{
		m_readersCount++;
		while (m_writersCount.load(std::memory_order_acquire) != m_expectedWritersCount)
			;
	}

	virtual void registerWriter([[maybe_unused]] const uint8_t writerIndex) noexcept
	{
		m_writersCount++;
		while (m_readersCount.load(std::memory_order_acquire) != m_expectedReadersCount)
			;
	}

	virtual void unregisterWriter([[maybe_unused]] const uint8_t writerIndex) noexcept
	{
		m_writersCount--;
	}

	bool writersPresent() const noexcept
	{
		return m_writersCount.load(std::memory_order_acquire) > 0;
	}

	virtual bool finished() noexcept = 0;

	virtual bool
	write(const Reference<OutputContainer<ElementType>>& container, const uint8_t writerId) noexcept
		= 0;

	virtual OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept = 0;

	virtual ~OutputStorage() = default;

protected:
	const uint8_t m_expectedWritersCount;
	const uint8_t m_expectedReadersCount;
	std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
		m_allocationBuffer;
	std::vector<Reference<OutputContainer<ElementType>>> m_storage;
	std::atomic<uint8_t> m_writersCount {0};
	std::atomic<uint8_t> m_readersCount {0};

	auto makeDeallocationCallback(const uint8_t writerId)
	{
		return [this, writerId](ReferenceCounter<OutputContainer<ElementType>>* counter) {
			this->m_allocationBuffer->deallocate(counter, writerId);
		};
	}

private:
	// std::condition_variable m_registrationCondition;
	// std::mutex m_registrationMutex;
	// Spinlock m_registrationLock;
};

} // namespace ipxp::output