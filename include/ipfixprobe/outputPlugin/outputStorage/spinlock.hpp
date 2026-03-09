#pragma once

#include "backoffScheme.hpp"

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
		BackoffScheme backoffScheme(20, std::numeric_limits<std::size_t>::max());
		while (true) {
			while (flag.test(std::memory_order_acquire)) {
				backoffScheme.backoff();
			}
			if (!flag.test_and_set(std::memory_order_acquire)) {
				return;
			}
			backoffScheme.backoff();
		}
	}

	bool tryLock() noexcept { return !flag.test_and_set(std::memory_order_acquire); }

	void unlock() noexcept { flag.clear(std::memory_order_release); }

	bool isLocked() const noexcept { return flag.test(std::memory_order_acquire); }
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