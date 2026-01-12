#pragma once

#include "outputContainer.hpp"

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
		m_refCount--;
	}

	bool hasUsers() const noexcept { return m_refCount.load() > 0; }

private:
	T m_data;
	std::atomic_uint8_t m_refCount {0};
};

template<typename T>
class ReferenceCounterHandler {
public:
	explicit ReferenceCounterHandler(ReferenceCounter<T>& counter) noexcept
		: m_counter(counter)
	{
		m_counter.incrementUserCount();
	}

	auto&& getData(this auto&& self) noexcept { return self.m_counter.getData(); }

	ReferenceCounterHandler(const ReferenceCounterHandler&) = delete;
	ReferenceCounterHandler& operator=(const ReferenceCounterHandler&) = delete;

	~ReferenceCounterHandler() noexcept { m_counter.decrementUserCount(); }

private:
	ReferenceCounter<T>& m_counter;
};