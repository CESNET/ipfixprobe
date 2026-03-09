#pragma once

namespace ipxp::output {

template<typename ElementType>
class AllocationBufferBase {
public:
	static_assert(
		std::is_default_constructible_v<ElementType>,
		"ElementType must be default constructible");

	virtual ElementType* allocate(const uint8_t writerIndex) noexcept = 0;

	virtual void deallocate(ElementType* element, const uint8_t writerIndex) noexcept = 0;

	virtual void unregisterWriter([[maybe_unused]] const uint8_t writerIndex) noexcept {}

	virtual void registerWriter([[maybe_unused]] const uint8_t writerIndex) noexcept {}

	virtual ~AllocationBufferBase() = default;

	/*void replace(ElementType*& oldValue, ElementType* newValue, const uint8_t writerId) noexcept
	{
		if (oldValue != nullptr) {
			deallocate(oldValue, writerId);
		}
		oldValue = newValue;
	}*/
};

} // namespace ipxp::output
