#pragma once

namespace ipxp::output {

template<typename Type>
class CacheAlligned {
public:
	template<typename... Args>
	explicit CacheAlligned(Args&&... args) noexcept
		: data(std::forward<Args>(args)...)
	{
	}

	auto& get(this auto& self) noexcept { return self.data; }

	auto operator->(this auto& self) noexcept { return &self.data; }

private:
	static constexpr std::size_t EXPECTED_CACHE_LINE_SIZE = 64;

	alignas(EXPECTED_CACHE_LINE_SIZE) Type data;
	// const std::array<std::byte, EXPECTED_CACHE_LINE_SIZE - sizeof(Type)> m_padding {};
};

} // namespace ipxp::output