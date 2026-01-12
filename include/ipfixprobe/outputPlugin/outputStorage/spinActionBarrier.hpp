#include "threadUtils.hpp"

#include <atomic>
#include <functional>
#include <thread>

namespace ipxp::output {

template<typename Action>
class SpinActionBarrier {
public:
	explicit SpinActionBarrier(const uint8_t barrierSize, Action completionAction)
		: m_barrierSize(barrierSize)
		, m_completionAction(std::move(completionAction))
	{
	}

	void decreaseBarrierSize() noexcept { m_barrierSize--; }
	void increaseBarrierSize() noexcept { m_barrierSize++; }

	void arriveAndWait()
	{
		const uint8_t currentGeneration = m_currentGeneration.load(std::memory_order_acquire);
		m_mainThreadId = getThreadId();
		m_threadsWaiting++;
		if (m_threadsWaiting.load(std::memory_order_acquire) > 100) {
			throw std::runtime_error("Should not happen");
		}
		if (m_threadsWaiting.load(std::memory_order_acquire)
			> m_barrierSize.load(std::memory_order_acquire)) [[unlikely]] {
			throw std::runtime_error("Too many threads arrived at barrier");
		}

		while (m_threadsWaiting.load(std::memory_order_acquire)
			   < m_barrierSize.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		if (m_mainThreadId == getThreadId()) {
			m_completionAction();
			while (m_threadsEnteredCriticalSection.load(std::memory_order_acquire)
				   != m_barrierSize.load(std::memory_order_acquire) - 1) {
				std::this_thread::yield();
			}
			m_threadsWaiting.store(0, std::memory_order_release);
			m_threadsEnteredCriticalSection.store(0, std::memory_order_release);
			m_currentGeneration.fetch_add(1, std::memory_order_release);
			return;
		}
		m_threadsEnteredCriticalSection++;
		while (currentGeneration == m_currentGeneration.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
	}

private:
	std::atomic<uint8_t> m_threadsWaiting {0};
	std::atomic<uint8_t> m_threadsEnteredCriticalSection {0};

	std::atomic<uint8_t> m_barrierSize;
	uint16_t m_mainThreadId;
	std::atomic<uint8_t> m_currentGeneration {0};
	std::atomic<uint8_t> m_completed {0};
	Action m_completionAction;
};

} // namespace ipxp::output