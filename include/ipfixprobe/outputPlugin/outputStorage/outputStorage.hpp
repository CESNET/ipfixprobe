#pragma once

#include "../../processPlugin/flowRecord.hpp"
#include "allocationBuffer.hpp"
#include "allocationBuffer2.hpp"
#include "allocationBuffer3.hpp"
#include "allocationBufferBase.hpp"
#include "allocationBufferR.hpp"
#include "dummyAllocationBuffer.hpp"
#include "outputContainer.hpp"
#include "referenceCounterHandler.hpp"

#include <atomic>
#include <condition_variable>

#include <boost/container/static_vector.hpp>

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
		origin.deallocate(data);
		data = nullptr;
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
	// constexpr static std::size_t ALLOCATION_BUFFER_CAPACITY = 40;
	constexpr static std::size_t MAX_WRITERS_COUNT = 32;
	constexpr static std::size_t MAX_READERS_COUNT = 32;
	constexpr static std::size_t MAX_READER_GROUPS_COUNT = 8;

	class WriteHandler {
	public:
		explicit WriteHandler(const uint8_t writerId, OutputStorage& storage) noexcept
			: m_writerId(writerId)
			, m_currentContainer(storage.allocateNewContainer())
			, m_storage(storage)
		{
		}

		~WriteHandler() noexcept { m_storage.unregisterWriter(m_writerId); }

		void pushFlowRecord(FlowRecordUniquePtr flowRecord) noexcept
		{
			if (m_currentContainer.getContainer().flows.size() == OutputContainer::SIZE) {
				if (m_storage.storeContainer(std::move(m_currentContainer), m_writerId)) {
					m_flowsPushed += OutputContainer::SIZE;
				}
				m_currentContainer.assign(
					m_storage.allocateNewContainer(),
					*m_storage.m_allocationBuffer);

				m_currentContainer.getContainer().creationTime = std::chrono::steady_clock::now();
				m_currentContainer.getContainer().sequenceNumber
					= ipxp::output::OutputContainer::globalSequenceNumber++;
				m_currentContainer.getContainer().readTimes = 0;
				m_currentContainer.getContainer().flows.clear();
			}

			m_currentContainer.getContainer().flows.push_back(std::move(flowRecord));
		}

		void flush() noexcept
		{
			if (m_currentContainer.empty() || m_currentContainer.getContainer().flows.empty()) {
				return;
			}

			const std::size_t flowsInContainer = m_currentContainer.getContainer().flows.size();
			if (m_storage.storeContainer(std::move(m_currentContainer), m_writerId)) {
				m_flowsPushed += flowsInContainer;
			}
			m_currentContainer.assign(
				m_storage.allocateNewContainer(),
				*m_storage.m_allocationBuffer);
		}

		/*bool storeContainer(ContainerWrapper container) noexcept
		{
			return m_storage.storeContainer(std::move(container), m_writerId);
		}*/

		std::size_t flowsPushed() const noexcept { return m_flowsPushed; }

	private:
		uint8_t m_writerId;
		uint8_t m_flowIndex {0};
		ContainerWrapper m_currentContainer;
		OutputStorage& m_storage;
		std::size_t m_flowsPushed {0};
	};

	class ReadHandler {
	public:
		explicit ReadHandler(
			const uint8_t readerGroupIndex,
			const uint8_t localReaderIndex,
			const uint8_t globalReaderIndex,
			OutputStorage& storage) noexcept
			: m_readerGroupIndex(readerGroupIndex)
			, m_localReaderIndex(localReaderIndex)
			, m_globalReaderIndex(globalReaderIndex)
			, m_storage(storage)
		{
			m_storage.registerReader(m_readerGroupIndex, m_localReaderIndex, m_globalReaderIndex);
		}

		const FlowRecordUniquePtr* getFlowRecord() noexcept
		{
			if (m_currentContainer.has_value()
				&& m_flowIndex < m_currentContainer->getData().flows.size()) [[likely]] {
				return &m_currentContainer->getData().flows[m_flowIndex++];
			}

			m_currentContainer = m_storage.getContainer(
				m_readerGroupIndex,
				m_localReaderIndex,
				m_globalReaderIndex);
			if (m_currentContainer == std::nullopt) {
				return nullptr;
			}
			m_flowIndex = 0;
			m_readContainers++;

			auto& y = m_currentContainer->getData();
			if (++m_currentContainer->getData().readTimes > 4) {
				throw std::runtime_error("Container read more times than there are reader groups.");
			}

			return &m_currentContainer->getData().flows[m_flowIndex++];
		}

		// void registerReader() noexcept { m_storage.registerReader(m_readerGroupIndex); }

		bool finished() noexcept { return m_storage.finished(m_readerGroupIndex); }

		// For debugging
		uint8_t getReaderIndex() const noexcept { return m_globalReaderIndex; }
		std::size_t readContainers() const noexcept { return m_readContainers; }

	private:
		const std::size_t m_readerGroupIndex;
		const uint8_t m_localReaderIndex;
		const uint8_t m_globalReaderIndex;
		uint8_t m_flowIndex {OutputContainer::SIZE};
		std::optional<ReferenceCounterHandler<OutputContainer>> m_currentContainer;
		OutputStorage& m_storage;
		std::size_t m_readContainers {0};
	};

	class ReaderGroupHandler {
	public:
		explicit ReaderGroupHandler(
			const uint8_t groupSize,
			OutputStorage& storage,
			const uint8_t readerGroupIndex,
			std::atomic<uint8_t>& readersRegisteredGlobally) noexcept
			: m_groupSize(groupSize)
			, m_storage(storage)
			, m_readerGroupIndex(readerGroupIndex)
			, m_readersRegisteredGlobally(readersRegisteredGlobally)
		{
		}

		ReadHandler getReaderHandler() noexcept
		{
			const uint8_t localReaderIndex = m_readersRegisteredInGroup++;
			const uint8_t globalReaderIndex = m_readersRegisteredGlobally++;
			return ReadHandler(m_readerGroupIndex, localReaderIndex, globalReaderIndex, m_storage);
		}

	private:
		const uint8_t m_groupSize;
		OutputStorage& m_storage;
		const std::size_t m_readerGroupIndex;
		std::atomic<uint8_t> m_readersRegisteredInGroup {0};
		std::atomic<uint8_t>& m_readersRegisteredGlobally;
	};

	explicit OutputStorage(const uint8_t writersCount) noexcept
		//, m_storage(ALLOCATION_BUFFER_CAPACITY, ContainerWrapper())
		: m_allocationBuffer(
			  std::make_unique<AllocationBuffer2<ReferenceCounter<OutputContainer>>>(
				  ALLOCATION_BUFFER_CAPACITY + MAX_WRITERS_COUNT * 10,
				  writersCount))
		, m_totalWritersCount(writersCount)
	{
		// m_storage.resize(ALLOCATION_BUFFER_CAPACITY);
		std::generate_n(std::back_inserter(m_storage), ALLOCATION_BUFFER_CAPACITY, [&]() {
			return ContainerWrapper();
		});
	}

	virtual ReaderGroupHandler& registerReaderGroup(const uint8_t groupSize) noexcept
	{
		m_readerGroupSizes.push_back(groupSize);
		m_readerGroupHandlers
			.emplace_back(groupSize, *this, m_readerGroupsCount, m_readersRegisteredGlobally);
		const uint8_t readerGroupIndex = m_readerGroupsCount++;
		return m_readerGroupHandlers.back();
	}

	virtual void registerReader(
		[[maybe_unused]] const uint8_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept
	{
		std::unique_lock<std::mutex> lock(m_registrationMutex);
		m_registrationCondition.notify_all();
		m_registrationCondition.wait(lock, [&]() { return m_writersCount > 0; });
	}

	virtual WriteHandler registerWriter() noexcept
	{
		m_allocationBuffer->registerWriter();

		std::unique_lock<std::mutex> lock(m_registrationMutex);
		const uint8_t currentWriterId = m_writersCount++;
		m_registrationCondition.notify_all();
		m_registrationCondition.wait(lock, [&]() {
			return m_readersRegisteredGlobally.load() > 0 && m_writersCount == m_totalWritersCount;
		});
		return WriteHandler(currentWriterId, *this);
	}

	virtual void unregisterWriter([[maybe_unused]] const uint8_t writerId) noexcept
	{
		m_writersCount--;
		m_allocationBuffer->unregisterWriter();
	}

	bool writersPresent() const noexcept { return m_writersCount > 0; }

	virtual bool finished(const std::size_t readerGroupIndex) noexcept = 0;

	virtual bool storeContainer(ContainerWrapper container, const uint8_t writerId) noexcept = 0;

	virtual std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		const uint8_t localReaderIndex,
		const uint8_t globalReaderIndex) noexcept
		= 0;

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
	const uint8_t m_totalWritersCount;
	std::atomic<uint8_t> m_readersRegisteredGlobally {0};
	std::condition_variable m_registrationCondition;
	boost::container::static_vector<ReaderGroupHandler, 4> m_readerGroupHandlers;

private:
	std::mutex m_registrationMutex;
};

} // namespace ipxp::output