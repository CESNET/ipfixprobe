#pragma once

#include "fieldHandler.hpp"
#include "flowRecord.hpp"
#include "packet.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>

/**
 * @brief Represents the possible actions a processing plugin can request after handling a packet.
 */
enum class FlowAction : int {
	/**
	 * Request complete flow data (packets + metadata).
	 */
	RequestFullData,

	/**
	 * Request only trimmed flow data (no payload).
	 */
	RequestTrimmedData,

	/**
	 * Indicate that no further processing is needed for this flow.
	 */
	RequestNoData,

	/**
	 * Export the flow immediately and erase its record.
	 */
	Flush,

	/**
	 * Export the flow immediately, erase its record, and re-insert a new flow.
	 */
	FlushAndReinsert
};

/**
 * @brief Abstract base class for all flow-processing plugins.
 *
 * Provides a common interface for plugins that react to flow lifecycle events.
 */
class ProcessPlugin {
public:
	ProcessPlugin() = default;
	virtual ~ProcessPlugin() = default;

	/**
	 * @brief Called when a new flow is created.
	 *
	 * @param flowRecord Reference to the new flow record.
	 * @param packet Packet that triggered the flow creation.
	 * @return Requested action after processing.
	 */
	virtual FlowAction onFlowCreate(FlowRecord& flowRecord, const Packet& packet)
	{
		(void) flowRecord;
		(void) packet;
		return FlowAction::RequestNoData;
	}

	/**
	 * @brief Called when an existing flow is updated with a new packet.
	 *
	 * @param flowRecord Reference to the existing flow record.
	 * @param packet The incoming packet.
	 * @return Requested action after processing.
	 */
	virtual FlowAction onFlowUpdate(FlowRecord& flowRecord, const Packet& packet)
	{
		(void) flowRecord;
		(void) packet;
		return FlowAction::RequestNoData;
	}

	/**
	 * @brief Called right before a flow is exported.
	 *
	 * Can be used for cleanup or finalization.
	 */
	virtual void onFlowExport() {}

	/**
	 * @brief Returns a pointer to the data to be exported.
	 *
	 * Typically points to a POD structure.
	 *
	 * @return Const void pointer to export data.
	 */
	virtual const void* getExportData() const noexcept = 0;

	/**
	 * @brief Clone the plugin into pre-allocated memory.
	 *
	 * Uses placement new semantics.
	 *
	 * @param constructAtAddress Address where the clone should be constructed.
	 * @return Pointer to the newly constructed clone.
	 */
	virtual ProcessPlugin* clone(std::byte* constructAtAddress) const = 0;

	/**
	 * @brief Returns the unique name of the plugin.
	 *
	 * Used e.g. for schema identification or logging.
	 *
	 * @return Name of the plugin.
	 */
	virtual std::string getName() const = 0;
};

/**
 * @brief CRTP base class that provides default clone() implementation.
 *
 * Use this class as a base if your derived plugin has copy constructor.
 */
template<typename Derived>
class ProcessPluginWithClone : public ProcessPlugin {
public:
	ProcessPluginWithClone() = default;
	~ProcessPluginWithClone() override = default;

	/**
	 * @brief Clone the derived plugin using placement new.
	 */
	ProcessPlugin* clone(std::byte* constructAtAddress) const override
	{
		return std::construct_at(
			reinterpret_cast<Derived*>(constructAtAddress),
			static_cast<const Derived&>(*this));
	}
};

/**
 * @brief Helper to determine the number of enum values.
 *
 * Requires that the enum defines a final enumerator named `FIELDS_SIZE`.
 *
 * @tparam E The enum type.
 * @return Number of elements.
 */
template<typename E>
constexpr uint8_t enum_size()
{
	return static_cast<uint8_t>(E::FIELDS_SIZE);
}

/**
 * @brief Fixed-size array indexed by enum class.
 *
 * Simplifies code by allowing strongly typed enum indexing.
 *
 * @tparam Enum Enum class type (must be contiguous, starting at 0).
 * @tparam T Stored type.
 * @tparam Size Size of the enum (should match number of fields).
 */
template<typename Enum, typename T, uint8_t Size>
class EnumArray {
public:
	static_assert(std::is_enum_v<Enum>, "EnumArray requires an enum type");

	/**
	 * @brief Access element by enum index.
	 *
	 * @param index Enum value.
	 * @return Reference to the stored value.
	 */
	T& operator[](Enum index) { return m_data[static_cast<uint8_t>(index)]; }

	/**
	 * @brief Const access to element by enum index.
	 *
	 * @param index Enum value.
	 * @return Const reference to the stored value.
	 */
	const T& operator[](Enum index) const { return m_data[static_cast<uint8_t>(index)]; }

private:
	std::array<T, Size> m_data;
};

/**
 * @brief Storage for field handlers indexed by enum.
 *
 * Designed to hold field accessors for a plugin schema.
 *
 * @tparam Enum Enum type used to represent individual fields.
 */

template<typename Enum>
using FieldHandlers = EnumArray<Enum, FieldHandler, enum_size<Enum>()>;
