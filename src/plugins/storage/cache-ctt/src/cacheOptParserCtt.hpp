/**
* \file
 * \author Damir Zainullin <zaidamilda@gmail.com>
 * \brief Contains the CacheOptParser class for parsing cache options.
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

#pragma once

#include "../../cache/src/cacheOptParser.hpp"

#include <feta.hpp>
#include <optional>

namespace ipxp {

class CacheOptParserCtt : public CacheOptParser {
public:
   std::optional<feta::OffloadMode> m_offload_mode;
   size_t m_offload_threshold{1000};
   size_t m_ctt_remove_queue_size{1024};

   ~CacheOptParserCtt() override = default;
   CacheOptParserCtt();
};


} // ipxp
