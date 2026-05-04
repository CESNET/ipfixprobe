/**
 * @file
 * @brief Implementation of OutputPlugin telemetry integration
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2026
 *
 * This file contains the implementation of telemetry-related functions for
 * the OutputPlugin class. It provides functionality to register parser statistics
 * in the telemetry system and manage telemetry directories.
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ipfixprobe/outputPlugin.hpp>

namespace ipxp {

static telemetry::Content get_output_stats(const OutputPlugin* plugin)
{
	telemetry::Dict dict;
	dict["processed"] = plugin->m_flows_seen;
	dict["dropped"] = plugin->m_flows_dropped;
	return dict;
}

void OutputPlugin::set_telemetry_dirs(std::shared_ptr<telemetry::Directory> output_dir)
{
	telemetry::FileOps statsOps = {[this]() { return get_output_stats(this); }, nullptr};

	register_file(output_dir, "stats", statsOps);
}

} // namespace ipxp
