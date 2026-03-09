#pragma once

#include "allocationBufferBase.hpp"

#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <ranges>
#include <vector>

namespace ipxp::output {

/*template<typename ElementType>
class AllocationBuffer : public AllocationBufferBase<ElementType> {
public:
	explicit AllocationBuffer(const std::size_t capacity, const uint8_t writersCount) noexcept
		: m_objectPool(4 * capacity)
		, m_writersCount(writersCount)
	{
		static_assert(
			decltype(m_controlBlock)::is_always_lock_free,
			"Error: ControlBlock must be lock-free for performance!");

		std::ranges::transform(
			m_objectPool,
			std::back_inserter(m_pointers),
			[](ElementType& element) { return &element; });
		// m_objectPointers[0].insert(m_objectPointers[0].end(), writersCount, nullptr);
		//  m_objectPointers[0].push_back(nullptr);
		m_pointers.resize(m_objectPool.size() * 2);
		// m_returnedPos = m_pointers.size() / 2;
		// m_lastFreePos = m_returnedPos.load();
		m_controlBlock = ControlBlock {
			.freePos = 0,
			.freeEnd = static_cast<uint16_t>(m_pointers.size() / 2),
			.returnedPos = static_cast<uint16_t>(m_pointers.size() / 2),
			.currentHalf = BufferHalf::LOWER};
		// m_freeAllocations = m_objectPointers[0].data();
		// m_returnedAllocations = m_objectPointers[1].data();

		// m_readPos = static_cast<uint16_t>(capacity - 1);
	}

	ElementType* allocate() noexcept override
	{
		const ControlBlock oldBlock = getFreePos();
		const uint16_t readPos = oldBlock.freePos;
		if (readPos == oldBlock.freeEnd) {
			swapControlBlock();
			return allocate();
		}
		if (readPos >= oldBlock.freeEnd) {
			// std::this_thread::yield();
			return allocate();
		}

		ElementType* res = m_pointers[readPos];
		m_pointers[readPos] = nullptr;
		// m_free.pop_back();
		if (!res) {
			throw std::runtime_error("TEST");
		}
		return res;
	}

	void deallocate(ElementType* element) noexcept override
	{
		const uint16_t writePos = getReturnedPos();
		m_pointers[writePos] = element;
		// m_free.push_back(element);
	}

private:

	std::vector<ElementType> m_objectPool;
	// std::array<std::vector<ElementType*>, 2> m_objectPointers;
	std::vector<ElementType*> m_pointers;

	ElementType** m_freeAllocations {nullptr};
	ElementType** m_returnedAllocations {nullptr};
	//  std::vector<ElementType*> m_free;
	// std::atomic_uint16_t m_freePos {0};
	// std::atomic_uint16_t m_lastFreePos {0};
	// std::atomic_uint16_t m_returnedPos {0};
	std::atomic_flag m_bufferSwitchLock {false};
	const uint8_t m_writersCount;
	uint16_t m_lastReturnedPos {0};
	std::atomic_uint16_t m_swapped {0};
	std::barrier<> m_switchBarrier {m_writersCount};

	// std::atomic_uint8_t m_currentlyWriting {0};

	// std::vector<ElementType*> m_taken;
};*/

} // namespace ipxp::output