#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

namespace ipxp::output {

class Spinlock {
	std::atomic_flag flag = ATOMIC_FLAG_INIT;

public:
	void lock() noexcept
	{
		while (flag.test(std::memory_order_relaxed)
			   || flag.test_and_set(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
	}

	bool try_lock() noexcept { return !flag.test_and_set(std::memory_order_acquire); }

	void unlock() noexcept { flag.clear(std::memory_order_release); }
};

class SpinlockGuard {
public:
	explicit SpinlockGuard(Spinlock& lock)
		: m_lock(lock)
	{
		m_lock.lock();
	}
	~SpinlockGuard() { m_lock.unlock(); }

	SpinlockGuard(const SpinlockGuard&) = delete;
	SpinlockGuard& operator=(const SpinlockGuard&) = delete;

private:
	Spinlock& m_lock;
};

} // namespace ipxp::output