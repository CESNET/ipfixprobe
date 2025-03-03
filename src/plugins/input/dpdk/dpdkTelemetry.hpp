/**
 * \file
 * \brief Class for managing DPDK telemetry
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

#include <telemetry.hpp>

namespace ipxp {

/**
 * @brief Class for managing DPDK telemetry
 *
 * This class handles the integration of DPDK telemetry data (rings, mempools) into the telemetry
 * directory.
 */
class DpdkTelemetry {
public:
    /**
     * @brief Constructor for DpdkTelemetry
     *
     * Initializes the DPDK telemetry manager and adds files representing DPDK rings and mempools to
     * the provided telemetry directory.
     *
     * @param dpdkDir Pointer to the telemetry directory where files will be added.
     */
    DpdkTelemetry(const std::shared_ptr<telemetry::Directory>& dpdkDir);

private:
    telemetry::Holder m_holder;
};

} // namespace ct
