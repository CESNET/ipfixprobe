#pragma once

#include <cstdint>

class Direction {
private:
	enum class Value : std::size_t {};
public:
	constexpr static Value Forward = static_cast<Value>(0);
	constexpr static Value Reverse = static_cast<Value>(1);

	constexpr Direction(const Value value) noexcept 
	: m_value(value) {}

	constexpr Direction(const bool value) noexcept 
	: m_value(static_cast<Value>(value)) {}

	constexpr operator Value() const noexcept 
	{
		return m_value;
	}

	constexpr Direction operator!() const noexcept
	{
		return m_value == Direction::Forward ? Direction::Reverse : Direction::Forward;
	}
private:
	Value m_value;
};


template<typename T>
struct DirectionalField {
	T values[2]{};

	constexpr T& operator[](Direction d) 
	{ 
		return d == Direction::Forward ? values[0] : values[1];
	}

	constexpr const T& operator[](Direction d) const 
	{
		return d == Direction::Forward ? values[0] : values[1];
	}
};