#pragma once

#include "outputStorage.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

class LFNBOutputStorage : public OutputStorage {
public:
	constexpr static std::size_t BUCKET_SIZE = 512;

	explicit LFNBOutputStorage(const uint8_t writersCount) noexcept
		: OutputStorage(writersCount)
	{
	}

	std::size_t registerReaderGroup(const uint8_t groupSize) noexcept override
	{
		const std::size_t index = OutputStorage::registerReaderGroup(groupSize);
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		m_readerGroupPositions.emplace_back(m_nextWritePos.load());
		m_alreadyReadGroupPositions.emplace_back(0);
		return index;
	}

	void storeContainer(ContainerWrapper container) noexcept override
	{
		if (container.empty()) {
			throw std::runtime_error("Attempt to store empty container in LFNBOutputStorage");
		}
		const uint64_t sequentialWritePosition = m_nextWritePos++;
		const uint64_t writePosition = sequentialWritePosition % m_storage.size();
		while (!m_storage[writePosition].empty()
			   && getReferenceCounter(m_storage[writePosition]).hasUsers()) {
			std::this_thread::yield();
		}
		while (true) {
			const uint64_t distanceToReader = distanceToClosestReader(sequentialWritePosition);
			if (distanceToReader <= BUCKET_SIZE + m_writersCount + 1ULL) {
				// std::cout << "Writer slowed down. Distance to reader: "
				//		+ std::to_string(distanceToReader) + "\n";
				//   std::this_thread::yield();
				if (m_writtenPos - worstReaderPos() >= m_writersCount + 64ULL) {
					worstReaderPos()++;
				} else {
					std::this_thread::yield();
				}
			} else {
				break;
			}
		}
		m_storage[writePosition].assign(container, *m_allocationBuffer);
		std::atomic_thread_fence(std::memory_order_seq_cst);
		workerFinished(writePosition, sequentialWritePosition);
		/*const uint64_t oldConfirmedPos = m_confirmedPos++;
		if (oldConfirmedPos == sequentialWritePosition) {
			updateWrittenPos(oldConfirmedPos);
			std::cout << "Writer advanced written pos to " + std::to_string(m_writtenPos.load())
					+ "\n";
		}*/

		if (m_writtenPos >= *std::ranges::max_element(m_readerGroupSizes) + m_writersCount + 1ULL)
			[[unlikely]] {
			std::lock_guard<std::mutex> lock(m_registrationMutex);
			m_initialized = true;
			m_initializationCV.notify_all();
		}
	}

	std::optional<ReferenceCounterHandler<OutputContainer>>
	getContainer(const std::size_t readerGroupIndex) noexcept override
	{
		if (!m_initialized) [[unlikely]] {
			std::unique_lock<std::mutex> lock(m_registrationMutex);
			m_initializationCV.wait(lock, [&]() { return m_initialized; });
		}

		const uint64_t sequentialReadPosition = m_readerGroupPositions[readerGroupIndex]++;
		const uint64_t readPosition = sequentialReadPosition % m_storage.size();
		while (true) {
			const uint64_t distance = distanceToWriter(sequentialReadPosition);
			if (distance > m_readerGroupSizes[readerGroupIndex] + 5ULL || !writersPresent()) {
				break;
			}
			// std::cout << "Reader " + std::to_string(readerGroupIndex)
			//		+ " slowed down - distance: " + std::to_string(distance) + "\n";
			std::this_thread::yield();
		}

		if (m_storage[readPosition].empty()) {
			throw std::runtime_error("Should not happen");
		}
		ContainerWrapper& container = m_storage[readPosition];
		return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
			getReferenceCounter(container));
	}

	bool finished(const std::size_t readerGroupIndex) noexcept override
	{
		return !writersPresent();
	}

private:
	std::atomic<uint64_t>& worstReaderPos() noexcept
	{
		return m_readerGroupPositions[*std::ranges::min_element(
			std::views::iota(0ULL, m_readerGroupPositions.size()),
			{},
			[&](const std::size_t readerGroupIndex) {
				return (m_readerGroupPositions[readerGroupIndex]
						- m_readerGroupSizes[readerGroupIndex] + m_storage.size())
					% m_storage.size();
			})];
	}

	/*uint64_t worstReaderPos() noexcept
	{
		return std::ranges::min(
			std::views::iota(0ULL, m_readerGroupSizes.size())
			| std::views::transform([&](const std::size_t readerGroupIndex) {
				  return (m_readerGroupPositions[readerGroupIndex]
						  - m_readerGroupSizes[readerGroupIndex] + m_storage.size())
					  % m_storage.size();
			  }));
	}*/

	uint64_t distanceToClosestReader(const uint64_t sequentialWriteIndex) noexcept
	{
		return (worstReaderPos() - sequentialWriteIndex - 1 + m_storage.size()) % m_storage.size();
	}

	uint64_t distanceToWriter(const uint64_t sequentialReadIndex) noexcept
	{
		return m_writtenPos.load(std::memory_order_acquire) - sequentialReadIndex;
	}

	void updateWrittenPos(const uint64_t newValue) noexcept
	{
		uint64_t expected;
		do {
			expected = m_writtenPos.load(std::memory_order_relaxed);
			if (expected >= newValue) {
				return;
			}
		} while (!m_writtenPos.compare_exchange_weak(
			expected,
			newValue,
			std::memory_order_release,
			std::memory_order_acquire));
	}

	void workerFinished(const uint64_t boundedWritePos, const uint64_t sequentialWritePos) noexcept
	{
		const uint64_t bucketIndex = boundedWritePos / BUCKET_SIZE;
		const uint64_t finishedCount
			= m_writersFinished[bucketIndex].fetch_add(1, std::memory_order_acq_rel) + 1;
		if (finishedCount % BUCKET_SIZE == 0) {
			const uint64_t newWrittenPos = (sequentialWritePos / BUCKET_SIZE + 1) * BUCKET_SIZE;
			while (m_writtenPos.load(std::memory_order_acquire) != newWrittenPos - BUCKET_SIZE) {
				std::this_thread::yield();
			}
			m_writtenPos.store(newWrittenPos, std::memory_order_release);
		}
	}

	// std::vector<uint16_t> m_readIndex;
	boost::container::static_vector<std::atomic_uint64_t, MAX_WRITERS_COUNT> m_readerGroupPositions;
	boost::container::static_vector<std::atomic_uint64_t, MAX_WRITERS_COUNT>
		m_alreadyReadGroupPositions;
	std::array<std::atomic<uint64_t>, ALLOCATION_BUFFER_CAPACITY / BUCKET_SIZE> m_writersFinished;
	std::atomic_uint64_t m_nextWritePos {0};
	std::atomic_uint64_t m_confirmedPos {0};
	std::atomic_uint64_t m_writtenPos {0};
	std::mutex m_registrationMutex;
	bool m_initialized {false};
	std::condition_variable m_initializationCV;
};

} // namespace ipxp::output