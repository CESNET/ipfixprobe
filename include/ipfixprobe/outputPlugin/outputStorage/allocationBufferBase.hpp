#pragma once

namespace ipxp::output {

template<typename ElementType>
class AllocationBufferBase {
public:
	static_assert(
		std::is_default_constructible_v<ElementType>,
		"ElementType must be default constructible");

	virtual ElementType* allocate(const uint8_t writerId) noexcept = 0;

	virtual void deallocate(ElementType* element, const uint8_t writerId) noexcept = 0;

	virtual void unregisterWriter() noexcept {}

	virtual void registerWriter() noexcept {}

	virtual ~AllocationBufferBase() = default;

	void replace(ElementType*& oldValue, ElementType* newValue, const uint8_t writerId) noexcept
	{
		if (oldValue != nullptr) {
			deallocate(oldValue, writerId);
		}
		oldValue = newValue;
	}
};

} // namespace ipxp::output
