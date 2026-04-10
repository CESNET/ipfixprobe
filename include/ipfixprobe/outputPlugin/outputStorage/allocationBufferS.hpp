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
		: m_objectPool(capacity + writersCount * 4)
	{
		static_assert(
			std::atomic<HelpState>::is_always_lock_free,
			"HelpState must be lock-free atomic");

		ElementType* begin = m_objectPool.data();
		const std::size_t objectsPerWriter = m_objectPool.size() / writersCount;
		for (const auto _ : std::views::iota(0U, writersCount)) {
			m_writersData.emplace_back(begin, objectsPerWriter);
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
		HelpState expected;
		HelpState desired;
		do {
			expected = m_helpStates[writerIndex]->load(std::memory_order_acquire);
			if (!expected.stealingRequested) {
				return;
			}
			desired = expected;
			desired.stealingAllowed = true;
		} while (!m_helpStates[writerIndex]->compare_exchange_weak(
			expected,
			desired,
			std::memory_order_release,
			std::memory_order_acquire));

		while (m_helpStates[writerIndex]->load(std::memory_order_acquire).stealingRequested) {
			BackoffScheme(1, 0).backoff();
		}

		do {
			expected = m_helpStates[writerIndex]->load(std::memory_order_acquire);
			desired = expected;
			desired.stealingAllowed = false;
		} while (!m_helpStates[writerIndex]->compare_exchange_weak(
			expected,
			desired,
			std::memory_order_release,
			std::memory_order_acquire));

		while (m_helpStates[writerIndex]->load(std::memory_order_acquire).stealingRequested) {
			BackoffScheme(1, 0).backoff();
		}
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
			if (!waitForStealApproval(stealVictimIndex)) {
				clearStealRequest(stealVictimIndex);
				continue;
			}
			WriterData& stealVictimData = m_writersData[stealVictimIndex].get();
			const std::size_t numToSteal = stealVictimData.storage.size() / 2;
			const std::size_t startIndex = stealVictimData.storage.size() - numToSteal;
			const std::size_t oldSize = writerData.storage.size();
			writerData.storage.resize(oldSize + numToSteal);
			std::memcpy(
				&writerData.storage[oldSize],
				&stealVictimData.storage[startIndex],
				numToSteal * sizeof(ElementType*));
			stealVictimData.storage.resize(startIndex);
			/*for (std::size_t i = 0; i < stealVictimData.storage.size() / 2; i++) {
				ElementType* stolenElement = stealVictimData.storage.back();
				stealVictimData.storage.pop_back();
				writerData.storage.push_back(stolenElement);
			}*/
			clearStealRequest(stealVictimIndex);
		}
	}

	bool waitForStealApproval(const uint8_t victimIndex) noexcept
	{
		BackoffScheme backoff(200, 5);
		while (!isStealAllowed(victimIndex)) {
			if (!backoff.backoff()) {
				return false;
			}
		}
		return true;
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

	struct WriterData {
		explicit WriterData(ElementType* begin, const std::size_t size) noexcept
		{
			storage.reserve(size);
			for (const auto _ : std::views::iota(0U, size)) {
				storage.push_back(begin++);
			}
		}

		std::vector<ElementType*> storage;
	};

	struct HelpState {
		bool stealingRequested {false};
		bool stealingAllowed {false};
	};

	std::vector<ElementType> m_objectPool;
	std::vector<CacheAlligned<WriterData>> m_writersData;
	std::array<CacheAlligned<std::atomic<HelpState>>, 32> m_helpStates;
	std::atomic<std::size_t> d_stolen {0};
};

} // namespace ipxp::output