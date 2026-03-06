#pragma once

#include "allocationBuffer3.hpp"
#include "fastRandomGenerator.hpp"

#include <deque>

namespace ipxp::output {

template<typename ElementType>
class AllocationBuffer3RD : public AllocationBuffer3<ElementType> {
public:
	explicit AllocationBuffer3RD(const std::size_t capacity, const uint8_t writersCount) noexcept
		: AllocationBuffer3<ElementType>(capacity, writersCount)
		, m_randomGenerator(1, writersCount)
	{
		for (const auto _ : std::views::iota(0U, writersCount)) {
			m_randomHandlers.emplace_back(this->m_randomGenerator.getHandler());
		}
	}

	ElementType* allocate(const uint8_t writerIndex) noexcept override
	{
		typename AllocationBuffer3<ElementType>::WriterData& writerData
			= this->m_writersData[writerIndex].get();
		FastRandomGenerator<>::FastRandomGeneratorHandler& randomHandler
			= this->m_randomHandlers[writerIndex].get();
		while (true) {
			writerData.queueIndex
				= (writerData.queueIndex + randomHandler.getValue()) % this->m_queues.size();
			ElementType* res = this->m_queues[writerData.queueIndex]->tryPop();
			if (res) {
				return res;
			}
		}
	}

	void deallocate(ElementType* element, const uint8_t writerIndex) noexcept override
	{
		typename AllocationBuffer3<ElementType>::WriterData& writerData
			= this->m_writersData[writerIndex].get();
		FastRandomGenerator<>::FastRandomGeneratorHandler& randomHandler
			= this->m_randomHandlers[writerIndex].get();
		while (true) {
			writerData.queueIndex
				= (writerData.queueIndex + randomHandler.getValue()) % this->m_queues.size();
			if (this->m_queues[writerData.queueIndex]->tryPush(element)) {
				return;
			}
		}
	}

private:
	FastRandomGenerator<> m_randomGenerator;
	std::deque<CacheAlligned<FastRandomGenerator<>::FastRandomGeneratorHandler>> m_randomHandlers;
};

} // namespace ipxp::output