#pragma once

// #include "../../processPlugin/flowRecord.hpp"
#include "allocationBuffer.hpp"
#include "allocationBuffer2.hpp"
#include "allocationBuffer3.hpp"
#include "allocationBufferBase.hpp"
#include "allocationBufferR.hpp"
#include "dummyAllocationBuffer.hpp"
#include "outputContainer.hpp"
#include "referenceCounter.hpp"

#include <atomic>
#include <condition_variable>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

template<typename ElementType>
class OutputStorage {
public:
	constexpr static std::size_t STORAGE_CAPACITY = 65536;
	// constexpr static std::size_t ALLOCATION_BUFFER_CAPACITY = 2048;
	constexpr static std::size_t MAX_WRITERS_COUNT = 32;
	constexpr static std::size_t MAX_READERS_COUNT = 32;
	constexpr static std::size_t MAX_READER_GROUPS_COUNT = 8;

	using value_type = ElementType;

	explicit OutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: m_expectedWritersCount(expectedWritersCount)
		, m_expectedReadersCount(expectedReadersCount)
		, m_allocationBuffer(allocationBuffer)
	{
		m_storage.reserve(STORAGE_CAPACITY);
		std::generate_n(std::back_inserter(m_storage), STORAGE_CAPACITY, [&]() {
			return Reference<OutputContainer<ElementType>>(*m_allocationBuffer->allocate(0));
		});
	}

	virtual void registerReader([[maybe_unused]] const uint8_t readerIndex) noexcept
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_readersCount++;
		m_registrationCondition.notify_all();
		m_registrationCondition.wait(lock, [&]() { return m_writersCount > 0; });
	}

	virtual void registerWriter([[maybe_unused]] const uint8_t writerIndex) noexcept
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_writersCount++;
		m_registrationCondition.notify_all();
		m_registrationCondition.wait(lock, [&]() { return m_readersCount > 0; });
	}

	virtual void unregisterWriter([[maybe_unused]] const uint8_t writerId) noexcept
	{
		m_writersCount--;
	}

	bool writersPresent() const noexcept { return m_writersCount > 0; }

	virtual bool finished() noexcept = 0;

	virtual bool
	write(const Reference<OutputContainer<ElementType>>& container, const uint8_t writerId) noexcept
		= 0;

	virtual OutputContainer<ElementType>* read(const uint8_t readerIndex) noexcept = 0;

	virtual ~OutputStorage() = default;

	/*void assignAndDeallocate(
		Reference<OutputContainer<ElementType>>& storageElement,
		const Reference<OutputContainer<ElementType>>& newContainer,
		const uint8_t writerId) noexcept
	{
		// ReferenceCounter<OutputContainer<ElementType>>* oldCounter = storageElement.getCounter();
		storageElement.assign(
			newContainer,
			makeDeallocationCallback(writerId)
			[&](ReferenceCounter<OutputContainer<ElementType>>* counter) {
				if (counter != oldCounter) {
					throw std::runtime_error(
						"Deallocation callback called with counter that does not match the old "
						"counter.");
				}
				this->m_allocationBuffer->deallocate(counter, writerId);
			});
		if (oldCounter->hasUsers()) {
			throw std::runtime_error("Old counter still has users after deallocation");
		}
		// this->m_allocationBuffer->deallocate(oldCounter, writerId);
	}*/

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
	std::condition_variable m_registrationCondition;
	std::mutex m_registrationMutex;
};

} // namespace ipxp::output