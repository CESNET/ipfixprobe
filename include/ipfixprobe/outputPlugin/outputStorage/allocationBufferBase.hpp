#pragma once

namespace ipxp::output {

template<typename ElementType>
class AllocationBufferBase {
public:
	virtual ElementType* allocate() noexcept = 0;

	virtual void deallocate(ElementType* element) noexcept = 0;

	virtual void unregisterWriter() noexcept {}

	virtual void registerWriter() noexcept {}

	virtual ~AllocationBufferBase() = default;
};

} // namespace ipxp::output
