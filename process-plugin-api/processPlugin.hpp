#pragma once

#include "fieldHandler.hpp"
#include "flowRecord.hpp"
#include "packet.hpp"

#include <cstdint>
#include <string>

enum class FlowAction : int {
	/**
	 * @brief Request complete flow data (packets + metadata).
	 */
	RequestFullData,

	/**
	 * @brief Request only trimmed flow data (no payload).
	 */
	RequestTrimmedData,

	/**
	 * @brief Indicate that no further processing is needed for this flow.
	 */
	RequestNoData,

	/**
	 * @brief Export the flow immediately and erase its record.
	 */
	Flush,

	/**
	 * @brief Export the flow immediately, erase its record, and re-insert new flow.
	 */
	FlushAndReinsert
};

class ProcessPlugin {
public:
	ProcessPlugin() = default;

	virtual FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
	{
		(void) flowRecord;
		(void) packet;

		return FlowAction::RequestNoData;
	}

	virtual FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet)
	{
		(void) flowRecord;
		(void) packet;

		return FlowAction::RequestNoData;
	}

	virtual void onFlowExport() {}

	virtual const void* getExportData() const noexcept = 0;

	virtual ProcessPlugin* clone(std::byte* constructAtAddress) const = 0;

	virtual std::string getName() const = 0;

	virtual ~ProcessPlugin() = default;
};

template<typename E>
constexpr std::size_t enum_size()
{
	return static_cast<std::size_t>(E::FIELDS_SIZE);
}

template<typename Enum, typename T, std::size_t Size>
class EnumArray {
public:
	static_assert(std::is_enum_v<Enum>, "EnumArray requires an enum type");

	// Přetížený operator[], který umožní indexovat pomocí enum class
	T& operator[](Enum index) { return m_data[static_cast<std::size_t>(index)]; }

	const T& operator[](Enum index) const { return m_data[static_cast<std::size_t>(index)]; }

private:
	std::array<T, Size> m_data;
};

template<typename Enum>
class FieldHandlers {
protected:
	EnumArray<Enum, FieldHandler, enum_size<Enum>()> m_fieldHandlers;
};
