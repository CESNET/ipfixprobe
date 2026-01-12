#pragma once

#include "allocationBuffer.hpp"
#include "allocationBuffer2.hpp"
#include "allocationBuffer3.hpp"
#include "allocationBufferBase.hpp"
#include "allocationBufferR.hpp"
#include "dummyAllocationBuffer.hpp"
#include "outputContainer.hpp"
#include "referenceCounterHandler.hpp"

#include <atomic>

namespace ipxp::output {

class ContainerWrapper;
class OutputStorage;

class ContainerWrapper {
public:
	bool empty() const noexcept { return data == nullptr; }

	ContainerWrapper(const ContainerWrapper& other) = delete;
	ContainerWrapper& operator=(const ContainerWrapper& other) = delete;

	ContainerWrapper(ContainerWrapper&& other) noexcept
		: data(other.data)
	{
		other.data = nullptr;
	}

	OutputContainer& getContainer() noexcept { return data->getData(); }

	void assign(
		const ContainerWrapper& other,
		AllocationBufferBase<ReferenceCounter<OutputContainer>>& origin) noexcept
	{
		if (!empty()) {
			origin.deallocate(data);
		}
		data = other.data;
	}

	void deallocate(AllocationBufferBase<ReferenceCounter<OutputContainer>>& origin) noexcept
	{
		if (!empty()) {
			origin.deallocate(data);
			data = nullptr;
		}
	}

	// ReferenceCounter<OutputContainer>* operator->() const noexcept { return m_data; }

	// ReferenceCounter<OutputContainer>* get() const noexcept { return m_data; }

private:
	friend class OutputStorage;

	explicit ContainerWrapper(ReferenceCounter<OutputContainer>* data) noexcept
		: data(data)
	{
	}

	explicit ContainerWrapper() noexcept
		: data(nullptr)
	{
	}

	ReferenceCounter<OutputContainer>* data;
};

class OutputStorage {
public:
	constexpr static std::size_t ALLOCATION_BUFFER_CAPACITY = 65536;
	constexpr static std::size_t MAX_WRITERS_COUNT = 32;

	explicit OutputStorage(const uint8_t writersCount) noexcept
		//, m_storage(ALLOCATION_BUFFER_CAPACITY, ContainerWrapper())
		: m_allocationBuffer(
			  std::make_unique<AllocationBuffer2<ReferenceCounter<OutputContainer>>>(
				  ALLOCATION_BUFFER_CAPACITY,
				  writersCount))
		, m_writersCount(writersCount)
	{
		// m_storage.resize(ALLOCATION_BUFFER_CAPACITY);
		std::generate_n(std::back_inserter(m_storage), ALLOCATION_BUFFER_CAPACITY, [&]() {
			return ContainerWrapper();
		});
	}

	virtual std::size_t registerReaderGroup(const uint8_t groupSize) noexcept
	{
		m_readerGroupSizes.push_back(groupSize);
		return m_readerGroupsCount++;
	}

	virtual void registerReader(const std::size_t readerGroupIndex) noexcept {}

	virtual void registerWriter() noexcept { m_allocationBuffer->registerWriter(); }

	virtual void unregisterWriter() noexcept
	{
		m_writersCount--;
		m_allocationBuffer->unregisterWriter();
	}

	bool writersPresent() const noexcept { return m_writersCount > 0; }

	virtual bool finished(const std::size_t readerGroupIndex) noexcept = 0;

	virtual void storeContainer(ContainerWrapper container) noexcept = 0;

	virtual std::optional<ReferenceCounterHandler<OutputContainer>>
	getContainer(const std::size_t readerGroupIndex) noexcept = 0;

	virtual ~OutputStorage() = default;

	ContainerWrapper allocateNewContainer() noexcept
	{
		return ContainerWrapper(m_allocationBuffer->allocate());
	}

protected:
	static constexpr ReferenceCounter<OutputContainer>&
	getReferenceCounter(ContainerWrapper& wrapper) noexcept
	{
		return *wrapper.data;
	}

	constexpr static uint16_t nextIndex(const uint16_t index) noexcept
	{
		return (index + 1) % ALLOCATION_BUFFER_CAPACITY;
	}

	// AllocationBuffer<ReferenceCounter<OutputContainer>> m_allocationBuffer;
	std::unique_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer>>> m_allocationBuffer;
	std::vector<ContainerWrapper> m_storage;
	std::atomic_uint8_t m_readerGroupsCount {0};
	std::vector<uint8_t> m_readerGroupSizes;
	std::atomic_uint8_t m_writersCount {0};
	std::mutex m_registrationMutex;
};

} // namespace ipxp::output