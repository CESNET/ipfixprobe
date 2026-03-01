#pragma once

#include "../../ring.h"
#include "outputStorage.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/container/static_vector.hpp>

namespace ipxp::output {

template<typename ElementType>
class RingOutputStorage : public OutputStorage<ElementType> {
public:
	explicit RingOutputStorage(
		const uint8_t expectedWritersCount,
		const uint8_t expectedReadersCount,
		std::shared_ptr<AllocationBufferBase<ReferenceCounter<OutputContainer<ElementType>>>>
			allocationBuffer) noexcept
		: OutputStorage<ElementType>(expectedWritersCount, expectedReadersCount, allocationBuffer)
		, m_ring(
			  ipx_ring_init(
				  static_cast<uint32_t>(OutputStorage<ElementType>::STORAGE_CAPACITY),
				  expectedWritersCount > 1),
			  &ipx_ring_destroy)
	{
	}

	bool write(
		const Reference<OutputContainer<ElementType>>& container,
		[[maybe_unused]] const uint8_t writerIndex) noexcept override
	{
		ipx_ring_push(m_ring.get(), container.getCounter());
		return true;
	}

	OutputContainer<ElementType>* read([[maybe_unused]] const uint8_t readerIndex) noexcept override
	{
		/*if (m_lastReadContainer != nullptr) {
			this->m_allocationBuffer->deallocate(m_lastReadContainer, 0);
			m_lastReadContainer = nullptr;
		}*/
		/*if (ipx_ring_cnt(m_ring.get()) == 0) {
			return nullptr;
		}*/

		auto pop = ipx_ring_pop(m_ring.get());
		if (pop == nullptr) {
			return nullptr;
		}
		m_container.storage.clear();
		m_container.storage.push_back(nullptr);
		return &m_container;
	}

	bool finished() noexcept override
	{
		return !this->writersPresent() && ipx_ring_cnt(m_ring.get()) == 0;
	}

private:
	std::unique_ptr<ipx_ring_t, decltype(&ipx_ring_destroy)> m_ring;
	OutputContainer<ElementType> m_container;
};

} // namespace ipxp::output