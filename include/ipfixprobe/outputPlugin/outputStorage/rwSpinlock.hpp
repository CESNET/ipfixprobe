#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <thread>

namespace ipxp::output {

class WriteLockGuard;
class ReadLockGuard;

class RWSpinlock {
	constexpr static uint8_t WRITER_LOCKED = std::numeric_limits<uint8_t>::max();
	std::atomic_uint8_t m_status {0};

	friend class WriteLockGuard;
	friend class ReadLockGuard;
};

class WriteLockGuard {
public:
	explicit WriteLockGuard(RWSpinlock& spinlock)
		: m_spinlock(spinlock)
	{
		lock();
	}

	~WriteLockGuard() { unlock(); }

private:
	void lock() noexcept
	{
		uint8_t expected;
		while (true) {
			expected = m_spinlock.m_status.load();
			if (expected != 0) {
				std::this_thread::yield();
				continue;
			}
			if (m_spinlock.m_status.compare_exchange_strong(
					expected,
					RWSpinlock::WRITER_LOCKED,
					std::memory_order_acquire,
					std::memory_order_relaxed)) {
				return;
			}
		}
	}

	void unlock() noexcept { m_spinlock.m_status.store(0, std::memory_order_release); }

	RWSpinlock& m_spinlock;
};

class ReadLockGuard {
public:
	explicit ReadLockGuard(RWSpinlock& spinlock)
		: m_spinlock(spinlock)
	{
		lock();
	}

	~ReadLockGuard() { unlock(); }

private:
	void lock() noexcept
	{
		uint8_t expected;
		while (true) {
			expected = m_spinlock.m_status.load();
			if (expected == RWSpinlock::WRITER_LOCKED) {
				std::this_thread::yield();
				continue;
			}
			if (m_spinlock.m_status.compare_exchange_weak(
					expected,
					expected + 1,
					std::memory_order_acquire,
					std::memory_order_relaxed)) {
				return;
			}
		}
	}

	void unlock() noexcept { m_spinlock.m_status.fetch_sub(1, std::memory_order_release); }

	RWSpinlock& m_spinlock;
};

} // namespace ipxp::output