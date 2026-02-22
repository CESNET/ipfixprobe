#pragma once

//#include "../../processPlugin/flowRecord.hpp"
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
	constexpr static std::size_t ALLOCATION_BUFFER_CAPACITY = 65536;
	// constexpr static std::size_t ALLOCATION_BUFFER_CAPACITY = 2048;
	constexpr static std::size_t MAX_WRITERS_COUNT = 32;
	constexpr static std::size_t MAX_READERS_COUNT = 32;
	constexpr static std::size_t MAX_READER_GROUPS_COUNT = 8;

	explicit OutputStorage(
			std::shared_ptr<AllocationBufferBase<
				ReferenceCounter<OutputContaier<
					ElementType>>>> allocationBuffer
	) noexcept
		: m_allocationBuffer(allocationBuffer)
	{
		std::generate_n(std::back_inserter(m_storage), ALLOCATION_BUFFER_CAPACITY, [&]() {
			return Reference<OutputContainer<ElementType>>(m_allocationBuffer->allocate());
		});
	}

	virtual void registerReader(
		[[maybe_unused]] const uint8_t readerIndex) noexcept
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
		m_registrationCondition.wait(lock, [&]() {
			return m_readersCount > 0;
		});
	}

	virtual void unregisterWriter([[maybe_unused]] const uint8_t writerId) noexcept
	{
		m_writersCount--;
	}

	bool writersPresent() const noexcept { return m_writersCount > 0; }

	virtual bool finished() noexcept = 0;

	virtual bool write(ElementType* element, const uint8_t writerId) noexcept = 0;

	virtual ElementType* read(const uint8_t readerIndex) noexcept = 0;

	virtual ~OutputStorage() = default;

protected:
	std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContaier<ElementType>>>> m_allocationBuffer;
	std::vector<Reference<OutputContainer<ElementType>>> m_storage;
	std::atomic<uint8_t> m_writersCount {0};
	std::atomic<uint8_t> m_readersCount {0};

private:
	std::condition_variable m_registrationCondition;
	std::mutex m_registrationMutex;
};

} // namespace ipxp::output