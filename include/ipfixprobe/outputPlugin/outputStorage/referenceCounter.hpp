#pragma once

// #include "outputContainer.hpp"

#include "allocationBufferBase.hpp"

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
		/*if (m_refCount == 0) {
			throw std::runtime_error(
				"ReferenceCounterHandler destructor called but user count is already zero.");
		}*/
		const uint8_t refCount = m_refCount->fetch_sub(1, std::memory_order_acq_rel);
		if (refCount == 1) {
			// m_data.~T();
		}
		return refCount;
	}

	// bool hasUsers() const noexcept { return m_refCount.load(std::memory_order_acquire) > 0; }

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

	/*Reference(const Reference& other) noexcept
		: Reference(*other.m_counter)
	{
	}*/

	/*Reference& operator=(const Reference& other) noexcept
	{
		if (this != &other) {
			m_counter->decrementUserCount();
			m_counter = other.m_counter;
			m_counter->incrementUserCount();
		}
		return *this;
	}*/

	template<typename OnDestructorCallback>
	void assign(const Reference& other, const OnDestructorCallback& onDestructorCallback) noexcept
	{
		if (this == &other) {
			throw std::runtime_error("Self-assignment is not allowed");
			// return false;
		}
		if (m_counter == other.m_counter) {
			throw std::runtime_error("Both references point to the same counter");
		}
		other.m_counter->incrementUserCount();
		auto* oldCounter = m_counter;
		m_counter = other.m_counter;
		const uint8_t userCount = oldCounter->decrementUserCount();
		if (userCount == 1) {
			onDestructorCallback(oldCounter);
		}
	}

	auto&& getCounter(this auto&& self) noexcept { return self.m_counter; }

	~Reference() noexcept { m_counter->decrementUserCount(); }

	// uint8_t getUserCount() const noexcept { return m_counter->m_refCount.load(); }

private:
	ReferenceCounter<T>* m_counter;
};

} // namespace ipxp::output