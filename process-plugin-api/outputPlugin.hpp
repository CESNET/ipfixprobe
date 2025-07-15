#pragma once

#include "flowRecord.hpp"
#include "fieldManager.hpp"

class OutputPlugin {
public:
	virtual void processRecord(FlowRecord& flowRecord, FieldManager& manager) = 0;

	virtual ~OutputPlugin() = default;
};
