/**
 * \file flowendreason.hpp
 * \brief Reasons of exporting cache
 */
/*
 * Copyright (C) 2023 CESNET
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

#ifndef IPFIXPROBE_CACHE_FLOWENDREASON_HPP
#define IPFIXPROBE_CACHE_FLOWENDREASON_HPP

namespace ipxp {
enum FlowEndReason : uint8_t {
    FLOW_END_RESERVED,
    FLOW_END_IDLE_TIMEOUT,///< 	The Flow was terminated because it was considered to be idle.
    FLOW_END_ACTIVE_TIMEOUT, ///<The Flow was terminated for reporting purposes while it was still active, for example, after the maximum lifetime of unreported Flows was reached.
    FLOW_END_EOF_DETECTED, ///< The Flow was terminated because the Metering Process detected signals indicating the end of the Flow, for example, the TCP FIN flag.
    FLOW_END_FORCED_END, ///< The Flow was terminated because of some external event, for example, a shutdown of the Metering Process initiated by a network management application.
    FLOW_END_LACK_OF_RECOURSES ///<The Flow was terminated because of lack of resources available to the Metering Process and/or the Exporting Process.
};

} // namespace ipxp

#endif // IPFIXPROBE_CACHE_FLOWENDREASON_HPP
