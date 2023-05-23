/**
 * \file input.hpp
 * \brief Generic interface of input plugin
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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
 *
 *
 *
 */

#ifndef IPXP_INPUT_HPP
#define IPXP_INPUT_HPP

#include <string>

#include "plugin.hpp"
#include "packet.hpp"

namespace ipxp {

/**
 * \brief Base class for packet receivers.
 */
class InputPlugin : public Plugin
{
public:
   enum class Result {
      TIMEOUT = 0,
      PARSED,
      NOT_PARSED,
      END_OF_FILE,
      ERROR
   };

   uint64_t m_seen;
   uint64_t m_parsed;
   uint64_t m_dropped;

   InputPlugin() : m_seen(0), m_parsed(0), m_dropped(0) {}
   virtual ~InputPlugin() {}

   virtual Result get(PacketBlock &packets) = 0;
};

}
#endif /* IPXP_INPUT_TEMPLATE_HPP */
