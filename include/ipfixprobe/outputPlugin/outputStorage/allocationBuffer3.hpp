#pragma once

#include "allocationBufferBase.hpp"
#include "cacheAlligned.hpp"

#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <random>
#include <ranges>
#include <vector>

namespace ipxp::output {

template<typename ElementType>
class AllocationBuffer3 : public AllocationBufferBase<ElementType> {
public:
	explicit AllocationBuffer3(const std::size_t capacity, const uint8_t writersCount) noexcept
		: m_objectPool(capacity + writersCount * writersCount)
	{
		const std::size_t objectsPerQueue = m_objectPool.size() / m_queues.size();
		m_writersData.resize(writersCount);
		for (const std::size_t writerIndex : std::views::iota(0U, writersCount)) {
			m_writersData[writerIndex]->queueIndex = writerIndex;
		}
		for (const std::size_t queueIndex : std::views::iota(0U, m_queues.size())) {
			for (const std::size_t elementIndex : std::views::iota(0U, objectsPerQueue)) {
				m_queues[queueIndex]->tryPush(
					m_objectPool.data() + queueIndex * objectsPerQueue + elementIndex);
			}
		}
	}

	ElementType* allocate(const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		while (true) {
			writerData.queueIndex = (writerData.queueIndex + 1) % m_queues.size();
			ElementType* res = m_queues[writerData.queueIndex]->tryPop();
			if (res) {
				return res;
			}
		}
	}

	void deallocate(ElementType* element, const uint8_t writerIndex) noexcept override
	{
		WriterData& writerData = m_writersData[writerIndex].get();
		while (true) {
			writerData.queueIndex = (writerData.queueIndex + 1) % m_queues.size();
			if (m_queues[writerData.queueIndex]->tryPush(element)) {
				return;
			}
		}
	}

protected:
	class Queue {
	public:
		ElementType* tryPop() noexcept
		{
			if (!tryLock()) {
				return nullptr;
			}
			if (pointers.empty()) {
				unlock();
				return nullptr;
			}
			ElementType* res = pointers.back();
			pointers.pop_back();
			unlock();
			return res;
		}

		bool tryPush(ElementType* element) noexcept
		{
			if (!tryLock()) {
				return false;
			}
			pointers.push_back(element);
			unlock();
			return true;
		}

		void prefetch() noexcept
		{
			__builtin_prefetch(
				pointers.data() + pointers.size() - 1,
				PrefetchMode::Read,
				Locality::High);
			__builtin_prefetch(&pointers, PrefetchMode::Write, Locality::High);
			__builtin_prefetch(&lock, PrefetchMode::Write, Locality::High);
		}

	private:
		std::vector<ElementType*> pointers;
		std::atomic_flag lock {false};

		bool tryLock() noexcept { return !lock.test_and_set(std::memory_order_acquire); }
		void unlock() noexcept { lock.clear(std::memory_order_release); }
	};

	struct WriterData {
		uint64_t queueIndex;
	};

	std::vector<ElementType> m_objectPool;
	std::vector<CacheAlligned<WriterData>> m_writersData;

	std::array<CacheAlligned<Queue>, 32> m_queues;
};

} // namespace ipxp::output