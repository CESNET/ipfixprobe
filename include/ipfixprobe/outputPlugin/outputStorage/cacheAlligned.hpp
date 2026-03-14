#pragma once

#include <cstddef>
#include <new>

namespace ipxp::output {

template<typename Type>
class CacheAlligned {
public:
	template<typename... Args>
	explicit CacheAlligned(Args&&... args) noexcept
		: data(std::forward<Args>(args)...)
	{
	}

	CacheAlligned<Type>& operator=(const Type& other) noexcept
	{
		data = other;
		return *this;
	}

	constexpr auto& get(this auto& self) noexcept { return self.data; }

	constexpr auto operator->(this auto& self) noexcept { return &self.data; }

private:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winterference-size"
	static constexpr std::size_t EXPECTED_CACHE_LINE_SIZE
		= std::hardware_destructive_interference_size;
#pragma GCC diagnostic pop
	static constexpr std::size_t PADDING_SIZE
		= (sizeof(Type) < EXPECTED_CACHE_LINE_SIZE) ? (EXPECTED_CACHE_LINE_SIZE - sizeof(Type)) : 0;

	alignas(EXPECTED_CACHE_LINE_SIZE) Type data;
	const std::array<std::byte, PADDING_SIZE> m_padding {};
};

} // namespace ipxp::output