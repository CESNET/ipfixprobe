#pragma once

template<typename ValueType>
class DoubleBufferedValue {
public:
	void setNewValue(ValueType newValue) noexcept
	{
		const uint8_t nextIndex = (m_currentIndex + 1) % 2;
		m_values[nextIndex] = std::move(newValue);
		m_currentIndex.store(nextIndex, std::memory_order_release);
	}

	auto& getCurrentValue(this auto&& self) noexcept
	{
		return self.m_values[self.m_currentIndex.load(std::memory_order_acquire)];
	}

private:
	std::array<ValueType, 2> m_values;
	std::atomic<uint8_t> m_currentIndex {0};
};