#pragma once

#include <cstdint>

namespace ipxp::process {

class Direction {
private:
	enum class Value : std::size_t { Forward, Reverse };

	constexpr Direction(const Value value) noexcept
		: m_value(value)
	{
	}

public:
	const static Direction Forward;
	const static Direction Reverse;

	constexpr Direction(const bool value) noexcept
		: m_value(static_cast<Value>(value))
	{
	}

	constexpr operator bool() const noexcept { return static_cast<bool>(m_value); }

	constexpr Direction operator!() const noexcept
	{
		return Direction(!static_cast<bool>(m_value));
	}

private:
	Value m_value;
};

inline const Direction Direction::Forward = Direction(Value::Forward);
inline const Direction Direction::Reverse = Direction(Value::Reverse);

template<typename T>
struct DirectionalField {
	T values[2] {};

	constexpr T& operator[](const Direction d) { return values[static_cast<bool>(d)]; }

	constexpr const T& operator[](const Direction d) const { return values[static_cast<bool>(d)]; }
};

} // namespace ipxp::process