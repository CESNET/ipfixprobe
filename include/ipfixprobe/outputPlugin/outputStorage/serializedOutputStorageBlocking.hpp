#pragma once

#include "outputStorage.hpp"
#include "serializedOutputStorage.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <vector>

namespace ipxp::output {

class SerializedOutputStorageBlocking : public SerializedOutputStorage {
public:
	explicit SerializedOutputStorageBlocking(const uint8_t writersCount) noexcept
		: SerializedOutputStorage(writersCount)
	{
	}

	bool storeContainer(
		ContainerWrapper container,
		[[maybe_unused]] const uint8_t writerId) noexcept override
	{
		std::unique_lock<std::mutex> lock(m_storageMutex);
		m_storage[m_writeIndex].assign(container, *m_allocationBuffer);

		m_tailNotifier.wait(lock, [&]() {
			return !someReaderReadsNextContainerNow() && allReadersHaveReadNextContainer();
		});

		m_writeIndex = nextIndex(m_writeIndex);
		return true;
	}

	std::optional<ReferenceCounterHandler<OutputContainer>> getContainer(
		const std::size_t readerGroupIndex,
		[[maybe_unused]] const uint8_t localReaderIndex,
		[[maybe_unused]] const uint8_t globalReaderIndex) noexcept override
	{
		std::lock_guard<std::mutex> lock(m_storageMutex);
		m_tailNotifier.notify_all();
		if (m_readIndex[readerGroupIndex] == m_writeIndex) {
			return std::nullopt;
		}
		auto& containerPtr = m_storage[m_readIndex[readerGroupIndex]];
		m_readIndex[readerGroupIndex] = nextIndex(m_readIndex[readerGroupIndex]);
		return std::make_optional<ReferenceCounterHandler<OutputContainer>>(
			getReferenceCounter(containerPtr));
	}

private:
	bool allReadersHaveReadNextContainer() noexcept
	{
		return std::ranges::all_of(m_readIndex, [&](const uint16_t readIdx) {
			return readIdx != nextIndex(m_writeIndex);
		});
	}

	bool someReaderReadsNextContainerNow() noexcept
	{
		return !m_storage[nextIndex(m_writeIndex)].empty()
			&& getReferenceCounter(m_storage[nextIndex(m_writeIndex)]).hasUsers();
	}

	std::condition_variable m_tailNotifier;
};

} // namespace ipxp::output