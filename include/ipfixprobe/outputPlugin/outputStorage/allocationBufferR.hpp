#pragma once

#include "allocationBufferBase.hpp"
#include "controlBlock.hpp"

#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <functional>
#include <ranges>
#include <vector>

namespace ipxp::output {

template<typename ElementType>
class AllocationBufferR : public AllocationBufferBase<ElementType> {
public:
	explicit AllocationBufferR(const std::size_t capacity, const uint8_t writersCount) noexcept
		: m_objectPool(capacity + 4 * writersCount)
		, m_writersCount(writersCount)
	{
		std::ranges::transform(
			m_objectPool,
			std::back_inserter(m_pointers),
			[](ElementType& element) { return &element; });
		m_pointers.resize(m_objectPool.size() * 2);
		m_controlBlock.emplace(m_pointers.size(), m_writersCount);
	}

	void registerWriter() noexcept override { m_controlBlock->registerWriter(); }
	void unregisterWriter() noexcept override { m_controlBlock->unregisterWriter(); }

	ElementType* allocate() noexcept override
	{
		const std::optional<uint16_t> readPos = std::invoke([&]() {
			std::optional<uint16_t> res = std::nullopt;
			while (!res.has_value()) {
				res = m_controlBlock->getReadPos();
			}
			return res;
		});

		ElementType* res = m_pointers[*readPos];
		m_pointers[*readPos] = nullptr;
		if (!res) {
			throw std::runtime_error("Should not happen");
		}
		return res;
	}

	void deallocate(ElementType* element) noexcept override
	{
		const std::optional<uint16_t> writePos = m_controlBlock->getWritePos();
		if (!writePos.has_value()) {
			throw std::runtime_error("Should not happen");
		}
		m_pointers[*writePos] = element;
	}

private:
	std::vector<ElementType> m_objectPool;
	std::vector<ElementType*> m_pointers;
	std::optional<ControlBlock> m_controlBlock;
	const uint8_t m_writersCount;
};

} // namespace ipxp::output