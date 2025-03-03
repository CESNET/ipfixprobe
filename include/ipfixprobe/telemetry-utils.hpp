/**
 * \file
 * \brief Contains the TelemetryUtils class for managing telemetry data.
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2024 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 */

#pragma once

#include <memory>
#include <string_view>

#include <telemetry.hpp>

namespace ipxp {

class TelemetryUtils {
public:
	/**
	 * @brief Register a File in the telemetry holder
	 *
	 * If the file is already registered, it will not be registered again.
	 *
	 * @param directory Directory to register the file in
	 * @param filename Name of the file
	 * @param ops File operations
	 */
	void register_file(
		std::shared_ptr<telemetry::Directory> directory,
		const std::string_view& filename,
		telemetry::FileOps ops)
	{
		if (directory->getEntry(filename)) {
			return;
		}

		auto file = directory->addFile(filename, ops);
		m_holder.add(file);
	}

protected:
	telemetry::Holder m_holder;
};

} // namespace ipxp