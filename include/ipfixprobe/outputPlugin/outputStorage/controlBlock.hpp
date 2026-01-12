#pragma once

#include "spinActionBarrier.hpp"
#include "threadUtils.hpp"

#include <atomic>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>

namespace ipxp::output {

class ControlBlock {
	enum class BufferHalf : uint8_t { LOWER = 0, UPPER = 1 };
	struct Status {
		uint16_t readPos;
		uint16_t readEnd;
		uint16_t writePos;
		BufferHalf currentHalf;
	};

public:
	explicit ControlBlock(const std::size_t capacity, const uint8_t writersCount) noexcept
		: m_capacity(capacity)
		, m_writersCount(writersCount)
	{
		static_assert(
			decltype(m_status)::is_always_lock_free,
			"Error: ControlBlock must be lock-free for performance!");

		m_status = Status {
			.readPos = 0,
			.readEnd = static_cast<uint16_t>(m_capacity / 2),
			.writePos = static_cast<uint16_t>(m_capacity / 2),
			.currentHalf = BufferHalf::LOWER};
	}

	void registerWriter() noexcept {}

	void unregisterWriter() noexcept
	{
		std::lock_guard<std::mutex> lock(m_registrationMutex);
		m_writersCount--;
		m_barrier.decreaseBarrierSize();
	}

	std::optional<uint16_t> getReadPos() noexcept
	{
		Status oldStatus = m_status.load(std::memory_order_relaxed);
		Status newStatus;
		do {
			newStatus = oldStatus;
			newStatus.readPos++;
		} while (!m_status.compare_exchange_weak(
			oldStatus,
			newStatus,
			std::memory_order_release,
			std::memory_order_acquire));

		if (oldStatus.readPos >= oldStatus.readEnd) {
			m_barrier.arriveAndWait();
			return std::nullopt;
		}
		/*if (oldStatus.readPos >= oldStatus.readEnd) {
			if (getThreadId() == *m_mainThreadId) {
				while (m_writersWaiting.load() < m_writersCount - 1) {
					std::this_thread::yield();
				}
				swapHalves();
				m_reset = true;
				m_writersWaiting++;
				while (m_writersAwaken.load() < m_writersCount - 1) {
					std::this_thread::yield();
				}
				m_writersWaiting = 0;
				m_writersAwaken = 0;
				m_reset = false;
				return std::nullopt;
			}
			while (m_reset) {}
			m_writersWaiting++;
			while (m_writersWaiting.load() < m_writersCount) {
				if (!m_mainThreadId.has_value()) {
					chooseMainThread();
					return std::nullopt;
				}
				std::this_thread::yield();
			}
			m_writersAwaken++;
			return std::nullopt;
		}*/
		return oldStatus.readPos;
	}

	std::optional<uint16_t> getWritePos() noexcept
	{
		Status oldStatus = m_status.load(std::memory_order_relaxed);
		Status newStatus;
		do {
			newStatus = oldStatus;
			newStatus.writePos++;
		} while (!m_status.compare_exchange_weak(
			oldStatus,
			newStatus,
			std::memory_order_release,
			std::memory_order_acquire));

		const uint16_t writeEnd
			= (oldStatus.currentHalf == BufferHalf::UPPER) ? m_capacity / 2 : m_capacity;
		if (oldStatus.writePos >= writeEnd) {
			return std::nullopt;
		}
		return oldStatus.writePos;
	}

private:
	void swapHalves() noexcept
	{
		Status oldStatus;
		Status newStatus;
		m_swapped++;
		do {
			oldStatus = m_status.load();
			newStatus
				= {.readPos = static_cast<uint16_t>(
					   oldStatus.currentHalf == BufferHalf::UPPER ? 0 : m_capacity / 2),
				   .readEnd = oldStatus.writePos,
				   .writePos = static_cast<uint16_t>(
					   oldStatus.currentHalf == BufferHalf::LOWER ? 0 : m_capacity / 2),
				   .currentHalf = oldStatus.currentHalf == BufferHalf::LOWER ? BufferHalf::UPPER
																			 : BufferHalf::LOWER};
		} while (!m_status.compare_exchange_weak(oldStatus, newStatus));
	}

	std::atomic<Status> m_status;
	const std::size_t m_capacity;
	std::atomic_uint32_t m_swapped;
	std::atomic_uint8_t m_writersCount;
	std::atomic_uint8_t m_writersWaiting {0};
	std::atomic_uint8_t m_writersAwaken {0};
	std::atomic_bool m_reset;
	std::mutex m_registrationMutex;
	struct SwapFunctor {
		ControlBlock* parent;
		void operator()() noexcept { parent->swapHalves(); }
	};
	SpinActionBarrier<SwapFunctor> m_barrier {m_writersCount, SwapFunctor {this}};
};

} // namespace ipxp::output