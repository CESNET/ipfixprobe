/**
 * \file
 * \brief Class for managing port telemetry.
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

#include <cstdint>
#include <memory>

#include <telemetry.hpp>

namespace ipxp {

/**
 * @brief Class for managing DPDK port telemetry
 *
 * This class integrates and monitors telemetry information for a specific DPDK port.
 */
class DpdkPortTelemetry {
public:
	/**
	 * @brief Constructor for DpdkPortTelemetry
	 *
	 * Creates an instance of the class for a specific DPDK port and adds telemetry files to the
	 * directory.
	 *
	 * @param portId ID of the DPDK port
	 * @param dir Directory for telemetry files
	 */
	DpdkPortTelemetry(uint16_t portId, const std::shared_ptr<telemetry::Directory>& dir);

private:
	const uint16_t M_PORT_ID;
	telemetry::Holder m_holder;
};

} // namespace ipxp