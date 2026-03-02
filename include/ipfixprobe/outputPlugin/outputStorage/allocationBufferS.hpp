#pragma once

#include "allocationBufferBase.hpp"
#include "backoffScheme.hpp"
#include "cacheAlligned.hpp"
#include "fastRandomGenerator.hpp"

#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <random>
#include <ranges>
#include <vector>

namespace ipxp::output {

template<typename ElementType>
class AllocationBufferS : public AllocationBufferBase<ElementType> {
public:
	explicit AllocationBufferS(const std::size_t capacity, const uint8_t writersCount) noexcept
		: m_objectPool(capacity + writersCount)
	{
		static_assert(
			std::atomic<HelpState>::is_always_lock_free,
			"HelpState must be lock-free atomic");
		// m_writersData.resize(writersCount);

		ElementType* begin = m_objectPool.data();
		const std::size_t objectsPerWriter = m_objectPool.size() / writersCount;
		for (const auto _ : std::views::iota(0U, writersCount)) {
			m_writersData.emplace_back(begin, objectsPerWriter);
			// writerData.storage = std::span<ElementType>(begin, objectsPerWriter);
			begin += objectsPerWriter;
		}
	}

	void unregisterWriter(const uint8_t writerId) noexcept override
	{
		std::atomic<HelpState>& state = m_helpStates[writerId].get();
		HelpState expected;
		HelpState desired;
		do {
			expected = state.load(std::memory_order_acquire);
			desired = expected;
			desired.stealingAllowed = true;
		} while (!state.compare_exchange_weak(
			expected,
			desired,
			std::memory_order_release,
			std::memory_order_acquire));
	}

	ElementType* allocate(const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		handleStealRequest(writerIndex);
		if (writerData.storage.empty()) {
			steal(writerIndex);
			d_stolen++;
		}
		ElementType* res = writerData.storage.back();
		writerData.storage.pop_back();
		return res;
	}

	void deallocate(ElementType* element, const uint8_t writerId) noexcept override
	{
		WriterData& writerData = m_writersData[writerId].get();
		writerData.storage.push_back(element);
	}

private:
	void handleStealRequest(const uint8_t writerIndex) noexcept
	{
		if (!m_helpStates[writerIndex]->load(std::memory_order_acquire).stealingRequested) {
			return;
		}
		m_helpStates[writerIndex]->store(HelpState {true, true}, std::memory_order_release);
		while (m_helpStates[writerIndex]->load(std::memory_order_acquire).stealingRequested) {
			BackoffScheme(1, 0).backoff();
		}
		m_helpStates[writerIndex]->store(HelpState {false, false}, std::memory_order_release);
	}

	void steal(const uint8_t writerIndex) noexcept
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		uint8_t stealVictimIndex = writerIndex;
		while (writerData.storage.empty()) {
			stealVictimIndex = (stealVictimIndex + 1) % m_writersData.size();
			if (stealVictimIndex == writerIndex) {
				continue;
			}
			if (!setStealRequest(stealVictimIndex)) {
				continue;
			}
			while (!isStealAllowed(stealVictimIndex)) {
				BackoffScheme(1, 0).backoff();
			}
			WriterData& stealVictimData = m_writersData[stealVictimIndex].get();
			for (std::size_t i = 0; i < stealVictimData.storage.size() / 2; i++) {
				ElementType* stolenElement = stealVictimData.storage.back();
				stealVictimData.storage.pop_back();
				writerData.storage.push_back(stolenElement);
			}
			clearStealRequest(stealVictimIndex);
		}
	}

	bool setStealRequest(const uint8_t victimIndex) noexcept
	{
		HelpState expected;
		HelpState desired;
		do {
			expected = m_helpStates[victimIndex]->load(std::memory_order_acquire);
			if (expected.stealingRequested) {
				return false;
			}
			desired = HelpState {true, expected.stealingAllowed};
		} while (!m_helpStates[victimIndex]->compare_exchange_weak(
			expected,
			desired,
			std::memory_order_release,
			std::memory_order_acquire));
		return true;
	}

	bool isStealAllowed(const uint8_t victimIndex) noexcept
	{
		return m_helpStates[victimIndex]->load(std::memory_order_acquire).stealingAllowed;
	}

	void clearStealRequest(const uint8_t victimIndex) noexcept
	{
		HelpState expected;
		HelpState desired;
		do {
			expected = m_helpStates[victimIndex]->load(std::memory_order_acquire);
			desired = expected;
			desired.stealingRequested = false;
		} while (!m_helpStates[victimIndex]->compare_exchange_weak(
			expected,
			desired,
			std::memory_order_release,
			std::memory_order_acquire));
	}
	/*= m_helpStates[victimIndex]->load(std::memory_order_acquire);
	currentValue.stealingRequested = false;
	m_helpStates[victimIndex]->store(currentValue, std::memory_order_release);*/

	struct WriterData {
		explicit WriterData(ElementType* begin, const std::size_t size) noexcept
		//	: currentUserIndex(writerIndex)
		{
			storage.reserve(size);
			for (const auto _ : std::views::iota(0U, size)) {
				storage.push_back(begin++);
			}
		}

		std::vector<ElementType*> storage;
		// std::atomic<uint8_t> currentUserIndex {0};
	};

	struct HelpState {
		// uint16_t helpRequests {0};
		bool stealingRequested {false};
		bool stealingAllowed {false};
	};

	std::vector<ElementType> m_objectPool;
	std::vector<CacheAlligned<WriterData>> m_writersData;
	std::array<CacheAlligned<std::atomic<HelpState>>, 32> m_helpStates;
	std::atomic<std::size_t> d_stolen {0};
	// FastRandomGenerator m_randomGenerator;
};

} // namespace ipxp::output