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
		for (auto&& [queue, objects] : std::views::zip(
				 m_queues,
				 m_objectPool | std::views::chunk(m_objectPool.size() / writersCount))) {
			std::ranges::for_each(objects, [&queue](ElementType& element) {
				queue.get().tryPush(&element);
			});
		}
	}

	ElementType* allocate([[maybe_unused]] const uint8_t writerId) noexcept override
	{
		static thread_local std::mt19937 gen(std::random_device {}());
		static thread_local std::uniform_int_distribution<> dist(0, 31);
		static thread_local uint64_t threadQueueIndex = dist(gen);
		while (true) {
			threadQueueIndex = (threadQueueIndex + 1) % m_queues.size();
			// const uint64_t queueIndex = m_nextQueue++ % m_queues.size();
			const std::optional<ElementType*> res = m_queues[threadQueueIndex].get().tryPop();

			if (res.has_value()) {
				return *res;
			}
		}
	}

	void deallocate(ElementType* element, [[maybe_unused]] const uint8_t writerId) noexcept override
	{
		static thread_local std::mt19937 gen(std::random_device {}());
		static thread_local std::uniform_int_distribution<> dist(0, 31);
		static thread_local uint64_t threadQueueIndex = dist(gen);
		while (true) {
			threadQueueIndex = (threadQueueIndex + 1) % m_queues.size();
			// const uint64_t queueIndex = m_nextQueue++ % m_queues.size();
			if (m_queues[threadQueueIndex].get().tryPush(element)) {
				return;
			}
		}
	}

private:
	class Queue {
	public:
		std::optional<ElementType*> tryPop() noexcept
		{
			if (!tryLock()) {
				return std::nullopt;
			}
			if (pointers.empty()) {
				unlock();
				return std::nullopt;
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

	private:
		std::vector<ElementType*> pointers;
		std::atomic_flag lock {false};

		bool tryLock() noexcept { return !lock.test_and_set(std::memory_order_acquire); }
		void unlock() noexcept { lock.clear(std::memory_order_release); }
	};

	std::vector<ElementType> m_objectPool;
	std::array<CacheAlligned<Queue>, 32> m_queues;
	std::atomic_uint64_t m_nextQueue {0};
};

} // namespace ipxp::output