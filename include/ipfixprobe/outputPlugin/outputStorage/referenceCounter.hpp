#pragma once

//#include "outputContainer.hpp"

#include <atomic>
#include <cstddef>
#include <iostream>

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

	T& getData() noexcept { return m_data; }

	void incrementUserCount() noexcept { m_refCount++; }

	void decrementUserCount()
	{
		if (m_refCount == 0) {
			throw std::runtime_error(
				"ReferenceCounterHandler destructor called but user count is already zero.");
		}
		const uint8_t refCount = m_refCount--;
		if (refCount == 0) {
			m_data.~T();
		}
	}

	bool hasUsers() const noexcept { return m_refCount.load() > 0; }

private:
	T m_data;
	std::atomic_uint8_t m_refCount {0};
};

template<typename T>
class Reference {
public:
	explicit Reference(ReferenceCounter<T>& counter) noexcept
		: m_counter(&counter)
	{
		m_counter->incrementUserCount();
	}

	auto&& getData(this auto&& self) noexcept { return self.m_counter->getData(); }

	Reference(const Reference& other) noexcept
		: Reference(*other.m_counter)
	{
	}

	/*Reference& operator=(const Reference& other) noexcept
	{
		if (this != &other) {
			m_counter->decrementUserCount();
			m_counter = other.m_counter;
			m_counter->incrementUserCount();
		}
		return *this;
	}*/

	void assign(const Reference& other, 
		AllocationBufferBase<ReferenceCounter<T>>& allocationBuffer) noexcept
	{
		if (this != &other) {
			return;	
		}	
		const uint8_t userCount = m_counter->decrementUserCount();
		if (userCount == 0) {
			allocationBuffer.deallocate(m_counter);
		}
		m_counter = other.m_counter;
		m_counter->incrementUserCount();
	
	}

	~Reference() noexcept { m_counter->decrementUserCount(); }

private:
	ReferenceCounter<T>* m_counter;
};