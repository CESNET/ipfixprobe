#pragma once

// #include "outputContainer.hpp"

#include "allocationBufferBase.hpp"
#include "cacheAlligned.hpp"

#include <atomic>
#include <cstddef>
#include <iostream>

namespace ipxp::output {

template<typename T>
class ReferenceCounter {
public:
	/*explicit ReferenceCounter(T data) noexcept
		: m_data(std::move(data))
	{
	}*/

	explicit ReferenceCounter() noexcept
		: m_data()
	{
	}

	ReferenceCounter& operator=(const ReferenceCounter&) = delete;
	ReferenceCounter(const ReferenceCounter&) = delete;

	T& getData() noexcept { return m_data.get(); }

	void incrementUserCount() noexcept { m_refCount->fetch_add(1, std::memory_order_relaxed); }

	uint8_t decrementUserCount()
	{
		const uint8_t refCount = m_refCount->fetch_sub(1, std::memory_order_acq_rel);
		return refCount;
	}

private:
	CacheAlligned<T> m_data;
	CacheAlligned<std::atomic<uint32_t>> m_refCount {0};
};

template<typename T>
class Reference {
public:
	explicit Reference(ReferenceCounter<T>& counter) noexcept
		: m_counter(&counter)
	{
		m_counter->incrementUserCount();
	}

	Reference(const Reference&) = delete;
	Reference& operator=(const Reference&) = delete;

	Reference(Reference&& other) noexcept
		: Reference(*other.m_counter)
	{
	}

	Reference& operator=(Reference&&) = delete;

	auto&& getData(this auto&& self) noexcept { return self.m_counter->getData(); }

	template<typename OnDestructorCallback>
	void assign(const Reference& other, const OnDestructorCallback& onDestructorCallback) noexcept
	{
		/*if (this == &other) {
			throw std::runtime_error("Self-assignment is not allowed");
		}
		if (m_counter == other.m_counter) {
			throw std::runtime_error("Both references point to the same counter");
		}*/
		other.m_counter->incrementUserCount();
		auto* oldCounter = m_counter;
		m_counter = other.m_counter;
		const uint8_t userCount = oldCounter->decrementUserCount();
		if (userCount == 1) {
			onDestructorCallback(oldCounter);
		}
	}

	constexpr auto&& getCounter(this auto&& self) noexcept { return self.m_counter; }

	~Reference() noexcept { m_counter->decrementUserCount(); }

private:
	ReferenceCounter<T>* m_counter;
};

} // namespace ipxp::output