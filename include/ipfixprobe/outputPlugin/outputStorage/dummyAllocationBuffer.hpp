#pragma once

#include <cstddef>
#include <cstdint>

namespace ipxp::output {

#include "allocationBufferBase.hpp"

template<typename ElementType>
class DummyAllocationBuffer : public AllocationBufferBase<ElementType> {
public:
	explicit DummyAllocationBuffer(const std::size_t capacity, const uint8_t writersCount) noexcept
	{
	}

	ElementType* allocate() noexcept override { return new ElementType(); }

	void deallocate(ElementType* element) noexcept override { delete element; }
};

} // namespace ipxp::output