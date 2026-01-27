#pragma once

template<typename ValueType>
class DoubleBufferedValue {
public:
	void setNewValue(ValueType newValue) noexcept
	{
		const uint8_t nextIndex = (m_currentIndex + 1) % 2;
		m_values[nextIndex] = std::move(newValue);
		m_currentIndex = nextIndex;
	}

	auto& getCurrentValue(this auto&& self) noexcept { return self.m_values[self.m_currentIndex]; }

private:
	std::array<ValueType, 2> m_values;
	uint8_t m_currentIndex {0};
};